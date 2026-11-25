package metrics

import (
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	r := New()
	r.Add("fraud_events_total", Labels("result", "scored"), 2)
	r.Set("fraud_alerts_open", "", 3)
	r.Observe("fraud_http_request_duration_seconds", Labels("route", "GET /x"), 0.02)
	var b strings.Builder
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		`fraud_events_total{result="scored"} 2`,
		"fraud_alerts_open 3",
		`fraud_http_request_duration_seconds_bucket{route="GET /x",le="0.025"} 1`,
		`fraud_http_request_duration_seconds_bucket{route="GET /x",le="0.01"} 0`,
		`fraud_http_request_duration_seconds_count{route="GET /x"} 1`,
		"# TYPE fraud_alerts_open gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if Labels("k", `a"b`) != `k="a\"b"` {
		t.Errorf("label escaping: %s", Labels("k", `a"b`))
	}
}
