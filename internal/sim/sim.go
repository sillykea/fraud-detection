// Package sim generates labelled payment traffic, ordinary customers with
// fraud mixed in, and measures how well the detector separates them.
//
// The ordinary traffic is deliberately not easy: customers have different
// spending levels, pay rent, pay friends, try new shops and now and then buy
// something big. A detector that flags all of that is useless, so the false
// positive rate matters as much as recall.
package sim

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"
)

// Txn is one payment. Case is empty for ordinary traffic.
type Txn struct {
	ID       string
	From, To string
	Minor    int64
	At       time.Time
	Case     string // e.g. "takeover-3"
	Scenario string // e.g. "takeover"; "ordinary" for normal traffic
	Eval     bool   // inside the measured window (after warm-up)
}

// Scenario describes a kind of fraud.
type Scenario struct {
	Name string
	// Detectable is false for patterns the rules are not designed to catch.
	// They are reported, so the blind spot is visible, but not gated on.
	Detectable bool
	Doc        string
}

// Scenarios in report order.
var Scenarios = []Scenario{
	{"takeover", true, "account takeover: a large payment to a new payee, then a burst draining the rest"},
	{"mule", true, "money mule: several victims pay one account, which sends it on within minutes"},
	{"fan_out", true, "a compromised account spreads small payments over many new payees"},
	{"structuring", true, "several payments in a day just under the 10,000 reporting threshold"},
	{"low_and_slow", false, "one payment of 3-5x the usual to a new payee: looks like ordinary life"},
}

// Config sizes a run.
type Config struct {
	Seed           uint64
	Users          int // ordinary customers
	WarmupDays     int // history before measuring starts
	EvalDays       int // measured window
	CasesPerKind   int // fraud cases per scenario
	Prefix         string
	Start          time.Time
	BigPurchaseOne float64 // share of users making one legitimately huge purchase in the window
}

type user struct {
	id      string
	median  float64 // usual payment, minor units
	rate    float64 // payments per day
	payees  []string
	rent    int64
	rentDay int
}

// Generate returns every payment, sorted by time.
func Generate(c Config) []Txn {
	r := rand.New(rand.NewPCG(c.Seed, c.Seed^0x9e3779b97f4a7c15))
	g := &gen{c: c, r: r}
	users := make([]*user, c.Users)
	merchants := make([]string, 120)
	for i := range merchants {
		merchants[i] = g.id("shop", i)
	}
	for i := range users {
		u := &user{
			id:     g.id("user", i),
			median: math.Exp(r.NormFloat64()*0.6 + math.Log(4_000)), // ~NZ$40, from ~$12 to ~$130
			rate:   0.6 + r.Float64()*2.4,
		}
		for range 3 + r.IntN(5) {
			u.payees = append(u.payees, merchants[r.IntN(len(merchants))])
		}
		if r.Float64() < 0.35 {
			u.rent = 120_000 + r.Int64N(150_000)
			u.rentDay = r.IntN(28)
		}
		users[i] = u
	}
	// A few friends each, paid now and then.
	for _, u := range users {
		for range 1 + r.IntN(2) {
			if f := users[r.IntN(len(users))]; f != u {
				u.payees = append(u.payees, f.id)
			}
		}
	}

	days := c.WarmupDays + c.EvalDays
	for _, u := range users {
		for d := range days {
			if u.rent > 0 && d%30 == u.rentDay {
				g.add(u.id, g.id("landlord", 0)+"_"+u.id, u.rent, g.dayTime(d, 8, 10), "", "ordinary")
			}
			n := poisson(r, u.rate)
			for range n {
				to := u.payees[r.IntN(len(u.payees))]
				if r.Float64() < 0.15 { // trying somewhere new
					to = merchants[r.IntN(len(merchants))]
				}
				amt := u.median * math.Exp(r.NormFloat64()*0.5)
				if r.Float64() < 0.03 { // a bigger shop now and then
					amt *= 2 + r.Float64()*3
				}
				g.add(u.id, to, int64(amt)+100, g.dayTime(d, 7, 23), "", "ordinary")
			}
		}
	}
	// A legitimately big one-off purchase from a new seller (a car, a
	// bond): the false positive every takeover rule will make.
	for _, u := range users {
		if r.Float64() < c.BigPurchaseOne {
			d := c.WarmupDays + r.IntN(c.EvalDays)
			g.add(u.id, g.id("dealer", r.IntN(1000)), 800_000+r.Int64N(2_000_000), g.dayTime(d, 9, 17), "", "ordinary")
		}
	}

	for k := range c.CasesPerKind {
		victim := func() *user { return users[r.IntN(len(users))] }
		at := func() time.Time { return g.dayTime(c.WarmupDays+r.IntN(c.EvalDays), 0, 24) }

		// Takeover.
		{
			u, t, cs := victim(), at(), fmt.Sprintf("takeover-%d", k)
			big := int64(math.Max(u.median*(15+r.Float64()*30), 250_000))
			g.add(u.id, g.id("atk", k*10), big, t, cs, "takeover")
			drop := g.id("atk", k*10+1)
			for range 10 {
				t = t.Add(time.Duration(2+r.IntN(4)) * time.Second)
				g.add(u.id, drop, 10_000+r.Int64N(40_000), t, cs, "takeover")
			}
		}
		// Mule.
		{
			mule, t, cs := g.id("mule", k), at(), fmt.Sprintf("mule-%d", k)
			var in int64
			for range 4 + r.IntN(3) {
				amt := 30_000 + r.Int64N(120_000)
				in += amt
				g.add(victim().id, mule, amt, t, cs, "mule")
				t = t.Add(time.Duration(1+r.IntN(5)) * time.Minute)
			}
			t = t.Add(time.Duration(5+r.IntN(10)) * time.Minute)
			g.add(mule, g.id("cashout", k), in*int64(85+r.IntN(11))/100, t, cs, "mule")
		}
		// Fan-out: spaced out enough to stay under the velocity limit.
		{
			u, t, cs := victim(), at(), fmt.Sprintf("fan_out-%d", k)
			for i := range 6 + r.IntN(3) {
				g.add(u.id, g.id("drop", k*10+i), 2_000+r.Int64N(18_000), t, cs, "fan_out")
				t = t.Add(time.Duration(55+r.IntN(30)) * time.Second)
			}
		}
		// Structuring.
		{
			smurf, t, cs := g.id("smurf", k), at(), fmt.Sprintf("structuring-%d", k)
			for i := range 3 + r.IntN(2) {
				g.add(smurf, g.id("payee", k*10+i), 900_000+r.Int64N(99_000), t, cs, "structuring")
				t = t.Add(time.Duration(2+r.IntN(5)) * time.Hour)
			}
		}
		// Low and slow.
		{
			u := victim()
			g.add(u.id, g.id("quiet", k), int64(u.median*(3+r.Float64()*2)), at(), fmt.Sprintf("low_and_slow-%d", k), "low_and_slow")
		}
	}

	sort.SliceStable(g.txns, func(i, j int) bool { return g.txns[i].At.Before(g.txns[j].At) })
	evalFrom := c.Start.Add(time.Duration(c.WarmupDays) * 24 * time.Hour)
	for i := range g.txns {
		g.txns[i].ID = fmt.Sprintf("%s_%06d", c.Prefix, i)
		g.txns[i].Eval = !g.txns[i].At.Before(evalFrom)
	}
	return g.txns
}

type gen struct {
	c    Config
	r    *rand.Rand
	txns []Txn
}

func (g *gen) id(kind string, n int) string { return fmt.Sprintf("%s_%s_%d", g.c.Prefix, kind, n) }

func (g *gen) dayTime(day, fromHour, toHour int) time.Time {
	secs := fromHour*3600 + g.r.IntN((toHour-fromHour)*3600)
	return g.c.Start.Add(time.Duration(day)*24*time.Hour + time.Duration(secs)*time.Second)
}

func (g *gen) add(from, to string, minor int64, at time.Time, cs, scenario string) {
	if from == to || minor <= 0 {
		return
	}
	g.txns = append(g.txns, Txn{From: from, To: to, Minor: minor, At: at, Case: cs, Scenario: scenario})
}

func poisson(r *rand.Rand, lambda float64) int {
	l, k, p := math.Exp(-lambda), 0, 1.0
	for {
		p *= r.Float64()
		if p <= l {
			return k
		}
		k++
	}
}

// ScenarioResult is recall for one kind of fraud.
type ScenarioResult struct {
	Scenario
	Cases, Detected int
	// PaymentsBeforeAlert is the median number of fraudulent payments that
	// went through before the first alert, over detected cases.
	PaymentsBeforeAlert float64
}

func (s ScenarioResult) Recall() float64 {
	if s.Cases == 0 {
		return 0
	}
	return float64(s.Detected) / float64(s.Cases)
}

// Report summarises a run over the measured window.
type Report struct {
	Scenarios        []ScenarioResult
	Ordinary         int // ordinary payments in the window
	FalsePositives   int // of those, how many raised an alert
	Alerts           int // alerts in the window
	FraudAlerts      int // alerts on fraudulent payments
	FalsePositiveIDs []string
}

func (r Report) FPR() float64 {
	if r.Ordinary == 0 {
		return 0
	}
	return float64(r.FalsePositives) / float64(r.Ordinary)
}

func (r Report) Precision() float64 {
	if r.Alerts == 0 {
		return 0
	}
	return float64(r.FraudAlerts) / float64(r.Alerts)
}

// Evaluate scores a run: alerted holds the IDs of payments that raised an alert.
func Evaluate(txns []Txn, alerted map[string]bool) Report {
	var rep Report
	type caseState struct {
		scenario string
		before   int
		hit      bool
	}
	cases := map[string]*caseState{}
	var order []string
	for _, t := range txns {
		if !t.Eval && t.Case == "" {
			continue
		}
		if t.Case == "" {
			rep.Ordinary++
			if alerted[t.ID] {
				rep.FalsePositives++
				rep.Alerts++
				rep.FalsePositiveIDs = append(rep.FalsePositiveIDs, t.ID)
			}
			continue
		}
		cs := cases[t.Case]
		if cs == nil {
			cs = &caseState{scenario: t.Scenario}
			cases[t.Case] = cs
			order = append(order, t.Case)
		}
		if alerted[t.ID] {
			rep.Alerts++
			rep.FraudAlerts++
			cs.hit = true
		} else if !cs.hit {
			cs.before++
		}
	}
	for _, sc := range Scenarios {
		res := ScenarioResult{Scenario: sc}
		var before []int
		for _, name := range order {
			cs := cases[name]
			if cs.scenario != sc.Name {
				continue
			}
			res.Cases++
			if cs.hit {
				res.Detected++
				before = append(before, cs.before)
			}
		}
		if len(before) > 0 {
			sort.Ints(before)
			res.PaymentsBeforeAlert = float64(before[len(before)/2])
		}
		rep.Scenarios = append(rep.Scenarios, res)
	}
	return rep
}

// Markdown renders the report as a table.
func (r Report) Markdown() string {
	s := "| Scenario | Cases | Detected | Recall | Fraud payments before first alert (median) | Gated |\n|---|---|---|---|---|---|\n"
	for _, sc := range r.Scenarios {
		gated := "yes"
		if !sc.Detectable {
			gated = "no (known blind spot)"
		}
		s += fmt.Sprintf("| %s | %d | %d | %.0f%% | %.0f | %s |\n", sc.Name, sc.Cases, sc.Detected, sc.Recall()*100, sc.PaymentsBeforeAlert, gated)
	}
	s += fmt.Sprintf("\nOrdinary payments: %d, of which alerted: %d (false positive rate %.3f%%). Alert precision: %.1f%% (%d of %d alerts were fraud).\n",
		r.Ordinary, r.FalsePositives, r.FPR()*100, r.Precision()*100, r.FraudAlerts, r.Alerts)
	return s
}
