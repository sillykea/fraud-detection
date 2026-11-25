package sim

import (
	"slices"
	"testing"
	"time"
)

func small() Config {
	return Config{Seed: 7, Users: 50, WarmupDays: 10, EvalDays: 10, CasesPerKind: 3,
		Prefix: "t", Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), BigPurchaseOne: 0.05}
}

func TestGenerateIsDeterministicAndLabelled(t *testing.T) {
	a, b := Generate(small()), Generate(small())
	if !slices.Equal(a, b) {
		t.Fatal("same seed gave different traffic")
	}
	if !slices.IsSortedFunc(a, func(x, y Txn) int { return x.At.Compare(y.At) }) {
		t.Error("not sorted by time")
	}
	perScenario := map[string]map[string]bool{}
	ids := map[string]bool{}
	for _, tx := range a {
		if ids[tx.ID] {
			t.Fatalf("duplicate id %s", tx.ID)
		}
		ids[tx.ID] = true
		if tx.From == tx.To || tx.Minor <= 0 {
			t.Fatalf("bad payment %+v", tx)
		}
		if tx.Case != "" {
			if !tx.Eval {
				t.Errorf("fraud outside the measured window: %+v", tx)
			}
			if perScenario[tx.Scenario] == nil {
				perScenario[tx.Scenario] = map[string]bool{}
			}
			perScenario[tx.Scenario][tx.Case] = true
		}
	}
	for _, sc := range Scenarios {
		if len(perScenario[sc.Name]) != 3 {
			t.Errorf("%s: %d cases, want 3", sc.Name, len(perScenario[sc.Name]))
		}
	}
}

func TestEvaluate(t *testing.T) {
	txns := []Txn{
		{ID: "w", Eval: false, Scenario: "ordinary"},                     // warm-up: not counted
		{ID: "o1", Eval: true, Scenario: "ordinary"},                     // false positive
		{ID: "o2", Eval: true, Scenario: "ordinary"},                     // fine
		{ID: "a1", Eval: true, Case: "takeover-0", Scenario: "takeover"}, // missed
		{ID: "a2", Eval: true, Case: "takeover-0", Scenario: "takeover"}, // caught
		{ID: "b1", Eval: true, Case: "takeover-1", Scenario: "takeover"}, // never caught
		{ID: "m1", Eval: true, Case: "mule-0", Scenario: "mule"},         // caught at once
	}
	rep := Evaluate(txns, map[string]bool{"w": true, "o1": true, "a2": true, "m1": true})
	if rep.Ordinary != 2 || rep.FalsePositives != 1 || rep.Alerts != 3 || rep.FraudAlerts != 2 {
		t.Errorf("totals %+v", rep)
	}
	byName := map[string]ScenarioResult{}
	for _, s := range rep.Scenarios {
		byName[s.Name] = s
	}
	if s := byName["takeover"]; s.Cases != 2 || s.Detected != 1 || s.PaymentsBeforeAlert != 1 {
		t.Errorf("takeover %+v", s)
	}
	if s := byName["mule"]; s.Recall() != 1 || s.PaymentsBeforeAlert != 0 {
		t.Errorf("mule %+v", s)
	}
	if rep.FPR() != 0.5 || rep.Markdown() == "" {
		t.Errorf("fpr %v", rep.FPR())
	}
}
