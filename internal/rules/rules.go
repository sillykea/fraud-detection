// Package rules scores a payment from features of the payer's recent
// activity. It is pure: no database, no clock, so every rule can be tested
// with a literal.
//
// Each rule that fires gives a score in (0, 1]. Scores are combined as
// independent evidence, 1 - Π(1 - s): two weak signals add up to more than
// either, but nothing reaches 1 on its own.
package rules

import (
	"fmt"
	"math"
	"sort"

	"github.com/sillykea/fraud-detection/internal/money"
)

// Features describe a payment and its payer's activity up to and including
// it. Amount fields are in minor units of the payment's currency.
type Features struct {
	AmountMinor int64
	Currency    string

	// Velocity: payments the payer made in the last minute.
	Outgoing1m int
	// Fan-out: distinct payees in the last 10 minutes.
	DistinctPayees10m int

	// Baseline: the payer's payments in this currency over the previous
	// 30 days, not counting this one.
	History30d     int
	Median30dMinor int64
	PriorToPayee   int   // all earlier payments from payer to this payee
	LargestToPayee int64 // largest earlier payment to this payee, same currency

	// Pass-through: money in and out of the payer over the last 30 minutes.
	Inflow30mMinor    int64
	DistinctPayers30m int
	Outflow30mMinor   int64

	// Structuring: payments in the last 24 hours just under the reporting
	// threshold, this one included.
	NearThreshold24h int
}

// Config holds the thresholds. Zero values mean "use the default".
type Config struct {
	VelocityPerMinute  int              // default 8
	FanOutPayees       int              // default 5
	SpikeMultiple      float64          // default 10
	SpikeMinHistory    int              // default 5
	MuleMinPayers      int              // default 3
	MuleOutShare       float64          // default 0.8
	StructuringCount   int              // default 3
	LargeAmount        map[string]int64 // minor units by currency; default 2,000 in major units
	ReportingThreshold map[string]int64 // minor units by currency; default 10,000 in major units
	ReviewAt           float64          // default 0.5
	BlockAt            float64          // default 0.8
}

func (c Config) withDefaults() Config {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	deff := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.VelocityPerMinute, 8)
	def(&c.FanOutPayees, 5)
	def(&c.SpikeMinHistory, 5)
	def(&c.MuleMinPayers, 3)
	def(&c.StructuringCount, 3)
	deff(&c.SpikeMultiple, 10)
	deff(&c.MuleOutShare, 0.8)
	deff(&c.ReviewAt, 0.5)
	deff(&c.BlockAt, 0.8)
	return c
}

// threshold returns m[currency], or major units scaled to the currency's
// minor unit when the currency has no explicit setting.
func threshold(m map[string]int64, currency string, major int64) int64 {
	if v, ok := m[currency]; ok {
		return v
	}
	exp, err := money.Exponent(currency)
	if err != nil {
		exp = 2
	}
	return major * int64(math.Pow10(exp))
}

// Large is the "large payment" amount for a currency.
func (c Config) Large(currency string) int64 { return threshold(c.LargeAmount, currency, 2_000) }

// Reporting is the reporting threshold that structuring tries to stay under.
func (c Config) Reporting(currency string) int64 {
	return threshold(c.ReportingThreshold, currency, 10_000)
}

// NearThreshold reports whether amount is within 10% below the reporting
// threshold: the band people structuring payments aim for.
func (c Config) NearThreshold(amount int64, currency string) bool {
	t := c.Reporting(currency)
	return amount < t && amount*10 >= t*9
}

// Signal is one rule that fired.
type Signal struct {
	Rule   string  `json:"rule"`
	Score  float64 `json:"score"`
	Reason string  `json:"reason"`
}

// Decision is what a pre-payment check recommends.
type Decision string

const (
	Allow  Decision = "allow"
	Review Decision = "review"
	Block  Decision = "block"
)

// Result is the combined verdict.
type Result struct {
	Score    float64  `json:"score"`
	Decision Decision `json:"decision"`
	Signals  []Signal `json:"signals"`
}

// Severity of an alert for a result that needs review.
func (r Result) Severity() string {
	if r.Decision == Block {
		return "high"
	}
	return "medium"
}

// Evaluate runs every rule.
func Evaluate(cfg Config, f Features) Result {
	c := cfg.withDefaults()
	amt := func(m int64) string { return money.Format(m, f.Currency) + " " + f.Currency }
	var s []Signal
	add := func(rule string, score float64, format string, args ...any) {
		s = append(s, Signal{Rule: rule, Score: score, Reason: fmt.Sprintf(format, args...)})
	}

	// A burst of payments: scripted draining after an account takeover.
	if f.Outgoing1m > c.VelocityPerMinute {
		score := 0.6
		if f.Outgoing1m >= 2*c.VelocityPerMinute {
			score = 0.9
		}
		add("velocity", score, "%d payments in the last minute (limit %d)", f.Outgoing1m, c.VelocityPerMinute)
	}

	// Many different payees in a few minutes: spreading money out.
	if f.DistinctPayees10m >= c.FanOutPayees {
		add("fan_out", 0.6, "%d different payees in 10 minutes", f.DistinctPayees10m)
	}

	// Far above what this payer normally sends, to someone they haven't sent
	// that much before. Rent going to the same landlord every month is not a
	// spike after the first time.
	if f.History30d >= c.SpikeMinHistory && f.Median30dMinor > 0 &&
		float64(f.AmountMinor) >= c.SpikeMultiple*float64(f.Median30dMinor) &&
		f.LargestToPayee*2 < f.AmountMinor {
		ratio := float64(f.AmountMinor) / float64(f.Median30dMinor)
		score := 0.5
		if ratio >= 3*c.SpikeMultiple {
			score = 0.75
		}
		add("amount_spike", score, "%s is %.0fx the payer's 30-day median of %s", amt(f.AmountMinor), ratio, amt(f.Median30dMinor))
	}

	// A large first payment to someone new.
	if f.PriorToPayee == 0 && f.AmountMinor >= c.Large(f.Currency) {
		add("new_payee_large", 0.4, "first payment to this payee and it is %s", amt(f.AmountMinor))
	}

	// Money arrives from several people and leaves again almost at once:
	// the pattern of a money mule.
	if f.DistinctPayers30m >= c.MuleMinPayers && f.Inflow30mMinor > 0 &&
		float64(f.Outflow30mMinor) >= c.MuleOutShare*float64(f.Inflow30mMinor) {
		add("pass_through", 0.7, "received %s from %d payers and sent %s on within 30 minutes",
			amt(f.Inflow30mMinor), f.DistinctPayers30m, amt(f.Outflow30mMinor))
	}

	// Several payments just under the reporting threshold in a day.
	if f.NearThreshold24h >= c.StructuringCount {
		add("structuring", 0.7, "%d payments just under %s in 24 hours", f.NearThreshold24h, amt(c.Reporting(f.Currency)))
	}

	sort.Slice(s, func(i, j int) bool { return s[i].Score > s[j].Score })
	keep := 1.0
	for _, sig := range s {
		keep *= 1 - sig.Score
	}
	r := Result{Score: math.Round((1-keep)*1000) / 1000, Decision: Allow, Signals: s}
	if r.Signals == nil {
		r.Signals = []Signal{}
	}
	switch {
	case r.Score >= c.BlockAt:
		r.Decision = Block
	case r.Score >= c.ReviewAt:
		r.Decision = Review
	}
	return r
}
