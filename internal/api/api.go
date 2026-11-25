// Package api is the HTTP interface: the webhook the ledger delivers events
// to, a pre-payment scoring endpoint, and the alert review queue.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sillykea/fraud-detection/internal/detector"
	"github.com/sillykea/fraud-detection/internal/event"
	"github.com/sillykea/fraud-detection/internal/metrics"
	"github.com/sillykea/fraud-detection/internal/money"
)

const maxBody = 1 << 20

// Server wires the detector to HTTP.
type Server struct {
	Detector *detector.Detector
	Pool     *pgxpool.Pool
	Metrics  *metrics.Registry
	Logger   *slog.Logger
	Token    string // bearer token for /v1 (except the webhook)
	// WebhookSecret verifies X-Ledger-Signature on /v1/events. Empty means
	// unsigned events are accepted (local development only).
	WebhookSecret []byte
	// SignatureTolerance is how old a signed event may be (default 5m).
	SignatureTolerance time.Duration
	Now                func() time.Time
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.Metrics.Write(w)
	})
	mux.HandleFunc("POST /v1/events", s.ingest)
	mux.HandleFunc("POST /v1/score", s.auth(s.score))
	mux.HandleFunc("GET /v1/alerts", s.auth(s.listAlerts))
	mux.HandleFunc("GET /v1/alerts/{id}", s.auth(s.getAlert))
	mux.HandleFunc("POST /v1/alerts/{id}/resolve", s.auth(s.resolve))
	mux.HandleFunc("PUT /v1/trusted-accounts/{id}", s.auth(s.trust))
	mux.HandleFunc("DELETE /v1/trusted-accounts/{id}", s.auth(s.untrust))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such route")
	})
	return s.observe(mux)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// VerifySignature checks an X-Ledger-Signature header:
// t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">.
func VerifySignature(secret, body []byte, header string, now time.Time, tolerance time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("missing or malformed X-Ledger-Signature")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
		return errors.New("signature timestamp outside the allowed window")
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("malformed signature")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("signature does not match")
	}
	return nil
}

// ingest is the ledger's webhook. Its status codes are chosen for the
// ledger's relay, which retries anything but a 2xx:
//
//	204  scored, ignored or a duplicate
//	202  malformed but authentic: kept in rejected_events, not retried,
//	     so one bad event can't block every event behind it
//	401  bad signature: retried, because it's a config problem to fix
//	5xx  our failure: retried
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "event body over 1 MiB")
		return
	}
	if len(s.WebhookSecret) > 0 {
		tol := s.SignatureTolerance
		if tol == 0 {
			tol = 5 * time.Minute
		}
		if err := VerifySignature(s.WebhookSecret, body, r.Header.Get("X-Ledger-Signature"), s.now(), tol); err != nil {
			s.Metrics.Add("fraud_events_total", metrics.Labels("result", "unauthenticated"), 1)
			writeErr(w, http.StatusUnauthorized, "bad_signature", err.Error())
			return
		}
	}
	res, err := s.Detector.Ingest(r.Context(), r.Header.Get("Idempotency-Key"), body)
	if err != nil && res.Outcome != detector.Rejected {
		s.Logger.Error("ingest failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.Metrics.Add("fraud_events_total", metrics.Labels("result", string(res.Outcome)), 1)
	switch res.Outcome {
	case detector.Rejected:
		s.Logger.Warn("event rejected", "reason", res.Reason)
		writeJSON(w, http.StatusAccepted, map[string]string{"outcome": string(res.Outcome), "reason": res.Reason})
		return
	case detector.Scored:
		s.Metrics.Observe("fraud_event_lag_seconds", "", s.now().Sub(res.Payment.At).Seconds())
		for _, sig := range res.Result.Signals {
			s.Metrics.Add("fraud_rule_hits_total", metrics.Labels("rule", sig.Rule), 1)
		}
		if res.AlertID != 0 {
			s.Metrics.Add("fraud_alerts_total", metrics.Labels("severity", res.Result.Severity()), 1)
			s.Logger.Info("alert", "alert_id", res.AlertID, "account", res.Payment.From,
				"transaction", res.Payment.TransactionID, "score", res.Result.Score)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) score(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.From == "" || req.To == "" || req.From == req.To {
		writeErr(w, http.StatusBadRequest, "invalid_request", "from and to must be two different accounts")
		return
	}
	amount, err := money.Parse(req.Amount, req.Currency)
	if err != nil || amount <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "amount must be a positive decimal in a known currency")
		return
	}
	res, err := s.Detector.Score(r.Context(), event.Payment{
		TransactionID: "pending", Kind: "transfer", From: req.From, To: req.To,
		AmountMinor: amount, Currency: req.Currency, At: s.now().UTC(),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Metrics.Add("fraud_score_decisions_total", metrics.Labels("decision", string(res.Decision)), 1)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := detector.AlertFilter{Status: q.Get("status"), AccountID: q.Get("account")}
	if f.Status != "" && f.Status != "open" && f.Status != "resolved" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "status must be open or resolved")
		return
	}
	var err error
	if v := q.Get("before"); v != "" {
		if f.BeforeID, err = strconv.ParseInt(v, 10, 64); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "before must be an alert id")
			return
		}
	}
	if v := q.Get("limit"); v != "" {
		if f.Limit, err = strconv.Atoi(v); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "limit must be a number")
			return
		}
	}
	alerts, err := s.Detector.List(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	if alerts == nil {
		alerts = []detector.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such alert")
		return 0, false
	}
	return id, true
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a, err := s.Detector.Get(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Resolution string `json:"resolution"`
		Note       string `json:"note"`
		By         string `json:"by"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Resolution != "fraud" && req.Resolution != "legitimate" {
		writeErr(w, http.StatusBadRequest, "invalid_request", `resolution must be "fraud" or "legitimate"`)
		return
	}
	if req.By == "" || len(req.Note) > 2000 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "by is required and note is at most 2000 characters")
		return
	}
	a, err := s.Detector.Resolve(r.Context(), id, req.Resolution, req.Note, req.By)
	if errors.Is(err, detector.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]string{"code": "already_resolved", "message": "alert was already resolved"}, "alert": a})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) trust(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 && !decode(w, r, &req) {
		return
	}
	if err := s.Detector.Trust(r.Context(), r.PathValue("id"), req.Note); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) untrust(w http.ResponseWriter, r *http.Request) {
	if err := s.Detector.Untrust(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if p := recover(); p != nil {
				s.Logger.Error("panic", "panic", p, "path", r.URL.Path)
				writeErr(sw, http.StatusInternalServerError, "internal", "internal error")
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			s.Metrics.Add("fraud_http_requests_total", metrics.Labels("route", route, "code", strconv.Itoa(sw.code)), 1)
			s.Metrics.Observe("fraud_http_request_duration_seconds", metrics.Labels("route", route), time.Since(start).Seconds())
		}()
		next.ServeHTTP(sw, r)
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing or wrong bearer token")
			return
		}
		h(w, r)
	}
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Pool.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "database unreachable")
		return
	}
	w.Write([]byte("ok"))
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeErr(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": kind, "message": msg}})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, detector.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "not found")
	default:
		s.Logger.Error("request failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}
