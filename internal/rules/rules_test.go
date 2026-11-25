package rules

import (
	"slices"
	"testing"
)

// normal is an ordinary payment from an account with a steady history.
func normal() Features {
	return Features{
		AmountMinor: 4_500, Currency: "NZD", Outgoing1m: 1, DistinctPayees10m: 1,
		History30d: 40, Median30dMinor: 3_000, PriorToPayee: 6, LargestToPayee: 5_000,
		Outflow30mMinor: 4_500,
	}
}

func rulesOf(r Result) []string {
	var out []string
	for _, s := range r.Signals {
		out = append(out, s.Rule)
	}
	slices.Sort(out)
	return out
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(*Features)
		rules    []string
		decision Decision
	}{
		{"normal payment", func(*Features) {}, nil, Allow},
		{"velocity at the limit", func(f *Features) { f.Outgoing1m = 8 }, nil, Allow},
		{"velocity over the limit", func(f *Features) { f.Outgoing1m = 9 }, []string{"velocity"}, Review},
		{"velocity at twice the limit", func(f *Features) { f.Outgoing1m = 16 }, []string{"velocity"}, Block},
		{"fan-out", func(f *Features) { f.DistinctPayees10m = 5 }, []string{"fan_out"}, Review},
		{"spike to a new payee", func(f *Features) {
			f.AmountMinor, f.PriorToPayee, f.LargestToPayee = 300_000, 0, 0
		}, []string{"amount_spike", "new_payee_large"}, Block},
		{"spike but this payee has had as much before (rent)", func(f *Features) {
			f.AmountMinor, f.LargestToPayee = 150_000, 150_000
		}, nil, Allow},
		{"spike with too little history to judge", func(f *Features) {
			f.AmountMinor, f.History30d, f.LargestToPayee = 100_000, 4, 0
		}, nil, Allow},
		{"large first payment alone is not enough to alert", func(f *Features) {
			f.AmountMinor, f.PriorToPayee, f.LargestToPayee, f.Median30dMinor = 250_000, 0, 0, 100_000
		}, []string{"new_payee_large"}, Allow},
		{"pass-through", func(f *Features) {
			f.DistinctPayers30m, f.Inflow30mMinor, f.Outflow30mMinor = 4, 100_000, 90_000
		}, []string{"pass_through"}, Review},
		{"money in from many, mostly kept", func(f *Features) {
			f.DistinctPayers30m, f.Inflow30mMinor, f.Outflow30mMinor = 4, 100_000, 50_000
		}, nil, Allow},
		{"structuring", func(f *Features) { f.NearThreshold24h = 3 }, []string{"structuring"}, Review},
		{"two weak signals combine", func(f *Features) {
			f.Outgoing1m, f.DistinctPayees10m = 9, 6
		}, []string{"fan_out", "velocity"}, Block},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := normal()
			c.edit(&f)
			r := Evaluate(Config{}, f)
			if got := rulesOf(r); !slices.Equal(got, c.rules) {
				t.Errorf("rules %v, want %v", got, c.rules)
			}
			if r.Decision != c.decision {
				t.Errorf("decision %s (score %.3f), want %s", r.Decision, r.Score, c.decision)
			}
			for _, s := range r.Signals {
				if s.Reason == "" {
					t.Errorf("%s has no reason", s.Rule)
				}
			}
		})
	}
}

func TestScoreCombination(t *testing.T) {
	f := normal()
	f.Outgoing1m, f.DistinctPayees10m = 9, 6 // 0.6 and 0.6
	if got := Evaluate(Config{}, f).Score; got != 0.84 {
		t.Errorf("score %v, want 1-(0.4*0.4)=0.84", got)
	}
	if Evaluate(Config{}, normal()).Signals == nil {
		t.Error("signals must be an empty list, not null, in JSON")
	}
}

func TestThresholdsByCurrency(t *testing.T) {
	var c Config
	if c.Large("NZD") != 200_000 || c.Large("JPY") != 2_000 || c.Large("KWD") != 2_000_000 {
		t.Errorf("default large amounts: NZD %d JPY %d KWD %d", c.Large("NZD"), c.Large("JPY"), c.Large("KWD"))
	}
	c.LargeAmount = map[string]int64{"JPY": 300_000}
	if c.Large("JPY") != 300_000 {
		t.Errorf("override ignored: %d", c.Large("JPY"))
	}
	// 90% to just under 100% of 10,000.00 NZD.
	for amount, want := range map[int64]bool{899_999: false, 900_000: true, 999_999: true, 1_000_000: false} {
		if got := c.NearThreshold(amount, "NZD"); got != want {
			t.Errorf("NearThreshold(%d) = %v", amount, got)
		}
	}
}

func TestConfigOverrides(t *testing.T) {
	f := normal()
	f.Outgoing1m = 5
	if r := Evaluate(Config{VelocityPerMinute: 4}, f); r.Decision != Review {
		t.Errorf("custom velocity limit ignored: %+v", r)
	}
	f = normal()
	f.DistinctPayers30m, f.Inflow30mMinor, f.Outflow30mMinor = 3, 1000, 1000
	if r := Evaluate(Config{ReviewAt: 0.75}, f); r.Decision != Allow {
		t.Errorf("custom review threshold ignored: %+v", r)
	}
}
