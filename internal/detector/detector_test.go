package detector_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sillykea/fraud-detection/internal/detector"
	"github.com/sillykea/fraud-detection/internal/event"
	"github.com/sillykea/fraud-detection/internal/rules"
	"github.com/sillykea/fraud-detection/internal/testdb"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
)

// body builds a ledger event for a transfer.
func body(evt, txn, from, to string, minor int64, at time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": evt, "type": "transaction.posted",
		"transaction": map[string]any{
			"id": txn, "kind": "transfer", "created_at": at,
			"entries": []map[string]any{
				{"account_id": from, "amount_minor": -minor, "currency": "NZD"},
				{"account_id": to, "amount_minor": minor, "currency": "NZD"},
			},
		},
	})
	return b
}

type harness struct {
	t   *testing.T
	det *detector.Detector
	n   int
}

func newHarness(t *testing.T) *harness {
	return &harness{t: t, det: &detector.Detector{Pool: testdb.New(t)}}
}

// pay ingests one transfer and returns what happened.
func (h *harness) pay(from, to string, minor int64, at time.Time) detector.IngestResult {
	h.t.Helper()
	h.n++
	id := fmt.Sprint(h.n)
	res, err := h.det.Ingest(ctx, "evt_"+id, body("evt_"+id, "txn_"+id, from, to, minor, at))
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

// history gives an account a month of ordinary spending.
func (h *harness) history(account string) {
	for i := range 20 {
		h.pay(account, fmt.Sprintf("shop_%d", i%4), 2_000+int64(i*100), t0.Add(time.Duration(i)*36*time.Hour))
	}
}

func hasRule(r detector.IngestResult, rule string) bool {
	for _, s := range r.Result.Signals {
		if s.Rule == rule {
			return true
		}
	}
	return false
}

func TestDuplicatesAreProcessedOnce(t *testing.T) {
	h := newHarness(t)
	b := body("evt_dup", "txn_dup", "acc_a", "acc_b", 500, t0)
	var wg sync.WaitGroup
	outcomes := make(chan detector.Outcome, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := h.det.Ingest(ctx, "evt_dup", b)
			if err != nil {
				t.Error(err)
			}
			outcomes <- res.Outcome
		}()
	}
	wg.Wait()
	close(outcomes)
	count := map[detector.Outcome]int{}
	for o := range outcomes {
		count[o]++
	}
	if count[detector.Scored] != 1 || count[detector.Duplicate] != 19 {
		t.Errorf("outcomes %v, want 1 scored and 19 duplicates", count)
	}
	var payments int
	h.det.Pool.QueryRow(ctx, `SELECT count(*) FROM payments`).Scan(&payments)
	if payments != 1 {
		t.Errorf("%d payments stored, want 1", payments)
	}
}

func TestAccountTakeover(t *testing.T) {
	h := newHarness(t)
	h.history("victim")
	at := t0.Add(31 * 24 * time.Hour)

	first := h.pay("victim", "attacker_1", 450_000, at)
	if !hasRule(first, "amount_spike") || !hasRule(first, "new_payee_large") || first.Result.Decision != rules.Block {
		t.Fatalf("large first payment: %+v", first.Result)
	}
	if first.AlertID == 0 {
		t.Fatal("no alert raised")
	}
	var last detector.IngestResult
	for i := range 10 {
		last = h.pay("victim", "attacker_2", 20_000, at.Add(time.Duration(i+1)*3*time.Second))
	}
	if !hasRule(last, "velocity") {
		t.Errorf("burst not caught: %+v", last.Result)
	}

	a, err := h.det.Get(ctx, first.AlertID)
	if err != nil {
		t.Fatal(err)
	}
	if a.AccountID != "victim" || a.ToAccount != "attacker_1" || a.Severity != "high" || len(a.Signals) != 2 {
		t.Errorf("alert %+v", a)
	}
}

func TestOrdinaryActivityRaisesNothing(t *testing.T) {
	h := newHarness(t)
	h.history("alice")
	// Rent: big compared to the usual, but the same landlord every month.
	h.pay("alice", "landlord", 180_000, t0.Add(2*24*time.Hour))
	h.history("alice") // second month, already has history
	res := h.pay("alice", "landlord", 180_000, t0.Add(32*24*time.Hour))
	if res.Result.Decision != rules.Allow {
		t.Errorf("second rent payment: %+v", res.Result)
	}
	alerts, err := h.det.List(ctx, detector.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Errorf("%d alerts on ordinary activity: %+v", len(alerts), alerts[0].Signals)
	}
}

func TestMule(t *testing.T) {
	h := newHarness(t)
	for i := range 4 {
		h.pay(fmt.Sprintf("victim_%d", i), "mule", 80_000, t0.Add(time.Duration(i)*time.Minute))
	}
	res := h.pay("mule", "cashout", 290_000, t0.Add(12*time.Minute))
	if !hasRule(res, "pass_through") || res.AlertID == 0 {
		t.Errorf("mule not caught: %+v", res.Result)
	}
}

func TestStructuring(t *testing.T) {
	h := newHarness(t)
	var res detector.IngestResult
	for i, amt := range []int64{950_000, 980_000, 920_000} {
		res = h.pay("smurf", fmt.Sprintf("p%d", i), amt, t0.Add(time.Duration(i)*5*time.Hour))
	}
	if !hasRule(res, "structuring") {
		t.Errorf("structuring not caught: %+v", res.Result)
	}
}

// Scoring is serialised per payer, so a burst that arrives all at once on
// many connections still looks like a burst. All 30 share one timestamp, so
// whatever order they land in, the k-th one scored sees k-1 others: exactly
// payments 9 to 30 go over the limit of 8. Without the lock, concurrent
// transactions can't see each other's uncommitted rows and fewer are caught.
func TestConcurrentBurstIsSeenWhole(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	results := make(chan detector.IngestResult, 30)
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("burst_%d", i)
			res, err := h.det.Ingest(ctx, id, body(id, "t"+id, "acc_x", "acc_y", 1_000, t0))
			if err != nil {
				t.Error(err)
			}
			results <- res
		}()
	}
	wg.Wait()
	close(results)
	flagged := 0
	for r := range results {
		if hasRule(r, "velocity") {
			flagged++
		}
	}
	if flagged != 22 {
		t.Errorf("%d of 30 burst payments flagged, want 22", flagged)
	}
}

// A late event is judged against the activity around when it was posted,
// not when it arrived.
func TestLateEventUsesPostingTime(t *testing.T) {
	h := newHarness(t)
	for i := range 9 {
		h.pay("acc_l", "acc_m", 1_000, t0.Add(time.Duration(i)*time.Second))
	}
	// Arrives after an hour of quiet, but was posted inside the burst.
	h.pay("acc_l", "acc_m", 1_000, t0.Add(time.Hour))
	late := h.pay("acc_l", "acc_m", 1_000, t0.Add(10*time.Second))
	if !hasRule(late, "velocity") {
		t.Errorf("late burst payment not flagged: %+v", late.Result)
	}
}

func TestTrustedAndRejected(t *testing.T) {
	h := newHarness(t)
	if err := h.det.Trust(ctx, "bank", "funding account"); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if res := h.pay("bank", fmt.Sprintf("cust_%d", i), 10_000, t0.Add(time.Duration(i)*time.Second)); res.Outcome != detector.Ignored {
			t.Fatalf("trusted payer scored: %+v", res)
		}
	}
	res, err := h.det.Ingest(ctx, "evt_bad", []byte(`{"event_id":"evt_bad","type":"transaction.posted"}`))
	if err != nil || res.Outcome != detector.Rejected {
		t.Fatalf("malformed event: %+v %v", res, err)
	}
	again, _ := h.det.Ingest(ctx, "evt_bad", []byte(`{}`))
	if again.Outcome != detector.Duplicate {
		t.Errorf("rejected event processed again: %+v", again)
	}
	mismatch, _ := h.det.Ingest(ctx, "evt_other", body("evt_x", "txn_x", "a", "b", 1, t0))
	if mismatch.Outcome != detector.Rejected {
		t.Errorf("Idempotency-Key not matching event_id was accepted: %+v", mismatch)
	}
	if err := h.det.Untrust(ctx, "bank"); err != nil {
		t.Fatal(err)
	}
	if err := h.det.Untrust(ctx, "bank"); !errors.Is(err, detector.ErrNotFound) {
		t.Errorf("untrusting twice: %v", err)
	}
}

func TestScoreWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.history("bob")
	r, err := h.det.Score(ctx, event.Payment{From: "bob", To: "stranger", AmountMinor: 500_000,
		Currency: "NZD", At: t0.Add(31 * 24 * time.Hour), TransactionID: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != rules.Block {
		t.Errorf("pre-check: %+v", r)
	}
	var n int
	h.det.Pool.QueryRow(ctx, `SELECT count(*) FROM payments WHERE to_account = 'stranger'`).Scan(&n)
	if n != 0 {
		t.Error("Score stored the payment")
	}
}

func TestResolve(t *testing.T) {
	h := newHarness(t)
	for i := range 4 {
		h.pay(fmt.Sprintf("v%d", i), "mule", 50_000, t0)
	}
	res := h.pay("mule", "out", 200_000, t0.Add(time.Minute))
	a, err := h.det.Resolve(ctx, res.AlertID, "fraud", "confirmed with the bank", "analyst@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "resolved" || *a.Resolution != "fraud" || a.ResolvedAt == nil {
		t.Errorf("resolved alert %+v", a)
	}
	if _, err := h.det.Resolve(ctx, res.AlertID, "legitimate", "", "someone"); !errors.Is(err, detector.ErrConflict) {
		t.Errorf("second resolve: %v", err)
	}
	if _, err := h.det.Resolve(ctx, 999999, "fraud", "", "x"); !errors.Is(err, detector.ErrNotFound) {
		t.Errorf("missing alert: %v", err)
	}
	open, _ := h.det.List(ctx, detector.AlertFilter{Status: "open"})
	resolved, _ := h.det.List(ctx, detector.AlertFilter{Status: "resolved", AccountID: "mule"})
	if len(open) != 0 || len(resolved) != 1 {
		t.Errorf("open %d resolved %d", len(open), len(resolved))
	}
}
