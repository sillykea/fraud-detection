package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sillykea/fraud-detection/internal/api"
	"github.com/sillykea/fraud-detection/internal/detector"
	"github.com/sillykea/fraud-detection/internal/metrics"
	"github.com/sillykea/fraud-detection/internal/testdb"
)

const (
	token  = "test-token-0123456789abcdef0123456789"
	secret = "webhook-secret-0123456789abcdef012345"
)

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// The same vector the ledger's tests pin, so the two sides can't drift apart.
func TestVerifySignatureMatchesLedger(t *testing.T) {
	body := []byte(`{"event_id":"evt_1"}`)
	header := "t=1700000000,v1=6cee9870342146e9ec63da18ecb1ee83e669ab35b33530cae78683ebcf468945"
	if err := api.VerifySignature([]byte("s3cret"), body, header, time.Unix(1700000060, 0), 5*time.Minute); err != nil {
		t.Fatalf("ledger's signature rejected: %v", err)
	}
	cases := map[string]struct {
		header string
		at     time.Time
	}{
		"stale":         {header, time.Unix(1700000000+301, 0)},
		"from future":   {header, time.Unix(1700000000-301, 0)},
		"tampered":      {strings.Replace(header, "6cee", "6cef", 1), time.Unix(1700000000, 0)},
		"missing":       {"", time.Unix(1700000000, 0)},
		"no timestamp":  {"v1=6cee", time.Unix(1700000000, 0)},
		"not hex":       {"t=1700000000,v1=zz", time.Unix(1700000000, 0)},
		"other secrets": {"t=1700000000,v1=00", time.Unix(1700000000, 0)},
	}
	for name, c := range cases {
		if err := api.VerifySignature([]byte("s3cret"), body, c.header, c.at, 5*time.Minute); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type env struct {
	t   *testing.T
	srv *httptest.Server
	reg *metrics.Registry
}

func newEnv(t *testing.T) *env {
	pool := testdb.New(t)
	reg := metrics.New()
	s := &api.Server{
		Detector: &detector.Detector{Pool: pool}, Pool: pool, Metrics: reg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Token:  token, WebhookSecret: []byte(secret), Now: func() time.Time { return now },
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, reg: reg}
}

func sign(body []byte, at time.Time) string {
	// Built independently of the code under test.
	ts := fmt.Sprint(at.Unix())
	return "t=" + ts + ",v1=" + hmacHex([]byte(secret), []byte(ts+"."+string(body)))
}

func (e *env) event(id, from, to string, minor int64, at time.Time, signature string) int {
	e.t.Helper()
	b, _ := json.Marshal(map[string]any{
		"event_id": id, "type": "transaction.posted",
		"transaction": map[string]any{"id": "txn_" + id, "kind": "transfer", "created_at": at,
			"entries": []map[string]any{
				{"account_id": from, "amount_minor": -minor, "currency": "NZD"},
				{"account_id": to, "amount_minor": minor, "currency": "NZD"}}},
	})
	if signature == "" {
		signature = sign(b, now)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/events", bytes.NewReader(b))
	req.Header.Set("Idempotency-Key", id)
	req.Header.Set("X-Ledger-Signature", signature)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (e *env) call(method, path, tok string, body any, out any) int {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func TestWebhookStatusCodes(t *testing.T) {
	e := newEnv(t)
	if c := e.event("e1", "a", "b", 100, now, ""); c != http.StatusNoContent {
		t.Errorf("valid event: %d", c)
	}
	if c := e.event("e1", "a", "b", 100, now, ""); c != http.StatusNoContent {
		t.Errorf("duplicate: %d", c)
	}
	if c := e.event("e2", "a", "b", 100, now, "t=1,v1=00"); c != http.StatusUnauthorized {
		t.Errorf("bad signature: %d", c)
	}
	// Authentic but malformed: acknowledged so it doesn't block the outbox.
	bad := []byte(`{"event_id":"e3","type":"transaction.posted","transaction":{}}`)
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/events", bytes.NewReader(bad))
	req.Header.Set("X-Ledger-Signature", sign(bad, now))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("malformed event: %d", resp.StatusCode)
	}
	var m strings.Builder
	e.reg.Write(&m)
	for _, want := range []string{
		`fraud_events_total{result="scored"} 1`, `fraud_events_total{result="duplicate"} 1`,
		`fraud_events_total{result="rejected"} 1`, `fraud_events_total{result="unauthenticated"} 1`,
	} {
		if !strings.Contains(m.String(), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestAlertsFlow(t *testing.T) {
	e := newEnv(t)
	for i := range 4 {
		e.event(fmt.Sprint("in", i), fmt.Sprint("victim", i), "mule", 60_000, now.Add(-10*time.Minute), "")
	}
	e.event("out", "mule", "cashout", 230_000, now.Add(-5*time.Minute), "")

	if c := e.call("GET", "/v1/alerts", "", nil, nil); c != http.StatusUnauthorized {
		t.Errorf("no token: %d", c)
	}
	if c := e.call("GET", "/v1/alerts", "wrong", nil, nil); c != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", c)
	}
	var list struct{ Alerts []detector.Alert }
	if c := e.call("GET", "/v1/alerts?status=open", token, nil, &list); c != 200 || len(list.Alerts) != 1 {
		t.Fatalf("list: %d %+v", c, list)
	}
	a := list.Alerts[0]
	if a.AccountID != "mule" || a.Signals[0].Rule != "pass_through" || a.AmountMinor != 230_000 {
		t.Errorf("alert %+v", a)
	}
	path := fmt.Sprintf("/v1/alerts/%d/resolve", a.ID)
	if c := e.call("POST", path, token, map[string]string{"resolution": "maybe", "by": "x"}, nil); c != 400 {
		t.Errorf("bad resolution: %d", c)
	}
	if c := e.call("POST", path, token, map[string]string{"resolution": "fraud", "by": "analyst"}, nil); c != 200 {
		t.Errorf("resolve: %d", c)
	}
	if c := e.call("POST", path, token, map[string]string{"resolution": "fraud", "by": "analyst"}, nil); c != 409 {
		t.Errorf("resolve twice: %d", c)
	}
	if c := e.call("GET", "/v1/alerts/123456", token, nil, nil); c != 404 {
		t.Errorf("missing alert: %d", c)
	}
	if c := e.call("GET", "/v1/alerts?status=weird", token, nil, nil); c != 400 {
		t.Errorf("bad filter: %d", c)
	}
}

func TestScoreAndTrust(t *testing.T) {
	e := newEnv(t)
	var r struct {
		Decision string
		Score    float64
		Signals  []struct{ Rule string }
	}
	req := map[string]string{"from": "acc_a", "to": "acc_b", "amount": "2500.00", "currency": "NZD"}
	if c := e.call("POST", "/v1/score", token, req, &r); c != 200 || r.Decision != "allow" || len(r.Signals) != 1 {
		t.Errorf("score: %d %+v", c, r)
	}
	if c := e.call("POST", "/v1/score", token, map[string]string{"from": "a", "to": "a", "amount": "1", "currency": "NZD"}, nil); c != 400 {
		t.Errorf("same account: %d", c)
	}
	if c := e.call("POST", "/v1/score", token, map[string]string{"from": "a", "to": "b", "amount": "-1", "currency": "NZD"}, nil); c != 400 {
		t.Errorf("negative amount: %d", c)
	}
	if c := e.call("PUT", "/v1/trusted-accounts/bank", token, map[string]string{"note": "funding"}, nil); c != 204 {
		t.Errorf("trust: %d", c)
	}
	if c := e.call("DELETE", "/v1/trusted-accounts/bank", token, nil, nil); c != 204 {
		t.Errorf("untrust: %d", c)
	}
	if c := e.call("DELETE", "/v1/trusted-accounts/bank", token, nil, nil); c != 404 {
		t.Errorf("untrust twice: %d", c)
	}
}
