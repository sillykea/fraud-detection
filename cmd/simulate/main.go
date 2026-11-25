// Command simulate measures the detector against labelled traffic.
//
// Replay mode (default) generates two months of synthetic payments with
// fraud mixed in, sends them to the service as signed ledger events, then
// reads back the alerts and reports recall per fraud pattern and the false
// positive rate on ordinary payments. It exits 1 if the detector misses its
// targets, so CI can gate on it.
//
//	simulate -url http://localhost:8090 -token $FRAUD_API_TOKEN -secret $LEDGER_WEBHOOK_SECRET
//
// Ledger mode drives the real payments-ledger instead: it creates and funds
// accounts, posts ordinary and fraudulent transfers through its API, and
// checks the alerts that arrive through the ledger's signed outbox.
//
//	simulate -mode ledger -ledger-url http://localhost:8080 -ledger-token $LEDGER_API_TOKEN \
//	         -url http://localhost:8090 -token $FRAUD_API_TOKEN
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sillykea/fraud-detection/internal/money"
	"github.com/sillykea/fraud-detection/internal/sim"
)

func main() {
	mode := flag.String("mode", "replay", "replay | ledger")
	url := flag.String("url", "http://localhost:8090", "fraud service URL")
	token := flag.String("token", os.Getenv("FRAUD_API_TOKEN"), "fraud API token")
	secret := flag.String("secret", os.Getenv("LEDGER_WEBHOOK_SECRET"), "webhook secret (replay mode)")
	users := flag.Int("users", 300, "ordinary customers (replay mode)")
	warmup := flag.Int("warmup-days", 30, "days of history before measuring (replay mode)")
	days := flag.Int("days", 30, "measured days (replay mode)")
	cases := flag.Int("cases", 20, "fraud cases per scenario (replay mode)")
	seed := flag.Uint64("seed", 1, "random seed (replay mode)")
	workers := flag.Int("workers", 8, "concurrent senders (replay mode)")
	minRecall := flag.Float64("min-recall", 0.9, "fail if recall on a gated scenario is below this")
	maxFPR := flag.Float64("max-fpr", 0.005, "fail if the false positive rate is above this")
	report := flag.String("report", "", "also write the markdown report to this file")
	ledgerURL := flag.String("ledger-url", "http://localhost:8080", "ledger URL (ledger mode)")
	ledgerToken := flag.String("ledger-token", os.Getenv("LEDGER_API_TOKEN"), "ledger API token (ledger mode)")
	flag.Parse()

	fraud := &client{base: strings.TrimRight(*url, "/"), token: *token}
	var err error
	switch *mode {
	case "replay":
		err = replay(fraud, []byte(*secret), sim.Config{
			Seed: *seed, Users: *users, WarmupDays: *warmup, EvalDays: *days, CasesPerKind: *cases,
			Prefix: "r" + randHex(3), Start: time.Now().UTC().Truncate(time.Hour).Add(-time.Duration(*warmup+*days) * 24 * time.Hour),
			BigPurchaseOne: 0.003,
		}, *workers, *minRecall, *maxFPR, *report)
	case "ledger":
		err = viaLedger(fraud, &client{base: strings.TrimRight(*ledgerURL, "/"), token: *ledgerToken})
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

type client struct {
	base, token string
	http        http.Client
}

func (c *client) do(method, path string, headers map[string]string, body []byte, out any) (int, error) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: %w: %s", method, path, err, b)
		}
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return resp.StatusCode, nil
}

func (c *client) json(method, path string, in, out any) error {
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	_, err := c.do(method, path, nil, b, out)
	return err
}

func ledgerEvent(t sim.Txn) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": "evt_" + t.ID, "type": "transaction.posted",
		"transaction": map[string]any{"id": "txn_" + t.ID, "kind": "transfer", "created_at": t.At,
			"entries": []map[string]any{
				{"account_id": t.From, "amount_minor": -t.Minor, "currency": "NZD"},
				{"account_id": t.To, "amount_minor": t.Minor, "currency": "NZD"}}},
	})
	return b
}

func sign(secret, body []byte) string {
	ts := fmt.Sprint(time.Now().Unix())
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

// send delivers events with several workers but close to time order: an
// event starts only once every event more than slack older has finished.
// That keeps cross-account patterns (money in, then out) in order while
// still sending in parallel, much like a ledger with a few outbox relays.
func send(fraud *client, secret []byte, txns []sim.Txn, workers int) error {
	const slack = 2 * time.Second
	var (
		mu     sync.Mutex
		cond   = sync.NewCond(&mu)
		done   = make([]bool, len(txns))
		low    = 0 // every event before low is done
		next   = 0
		failed error
	)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if next >= len(txns) || failed != nil {
					mu.Unlock()
					return
				}
				i := next
				next++
				for low < i && txns[low].At.Before(txns[i].At.Add(-slack)) && failed == nil {
					cond.Wait()
				}
				mu.Unlock()

				body := ledgerEvent(txns[i])
				_, err := fraud.do("POST", "/v1/events", map[string]string{
					"Idempotency-Key": "evt_" + txns[i].ID, "X-Ledger-Signature": sign(secret, body)}, body, nil)

				mu.Lock()
				if err != nil && failed == nil {
					failed = err
				}
				done[i] = true
				for low < len(txns) && done[low] {
					low++
				}
				cond.Broadcast()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return failed
}

type alert struct {
	ID            int64  `json:"id"`
	TransactionID string `json:"transaction_id"`
	AccountID     string `json:"account_id"`
	Signals       []struct {
		Rule string `json:"rule"`
	} `json:"signals"`
}

// alerts reads every alert whose account starts with prefix.
func alerts(fraud *client, prefix string) ([]alert, error) {
	var all []alert
	before := int64(0)
	for {
		var page struct{ Alerts []alert }
		path := "/v1/alerts?limit=500"
		if before > 0 {
			path += fmt.Sprintf("&before=%d", before)
		}
		if err := fraud.json("GET", path, nil, &page); err != nil {
			return nil, err
		}
		for _, a := range page.Alerts {
			if strings.HasPrefix(a.AccountID, prefix) {
				all = append(all, a)
			}
			before = a.ID
		}
		if len(page.Alerts) < 500 {
			return all, nil
		}
	}
}

func replay(fraud *client, secret []byte, cfg sim.Config, workers int, minRecall, maxFPR float64, reportFile string) error {
	txns := sim.Generate(cfg)
	fmt.Printf("generated %d payments for %d customers over %d+%d days (run %s)\n",
		len(txns), cfg.Users, cfg.WarmupDays, cfg.EvalDays, cfg.Prefix)
	start := time.Now()
	if err := send(fraud, secret, txns, workers); err != nil {
		return err
	}
	elapsed := time.Since(start)
	fmt.Printf("sent in %s: %.0f events/s\n", elapsed.Round(time.Millisecond), float64(len(txns))/elapsed.Seconds())

	list, err := alerts(fraud, cfg.Prefix)
	if err != nil {
		return err
	}
	alerted := map[string]bool{}
	for _, a := range list {
		alerted[strings.TrimPrefix(a.TransactionID, "txn_")] = true
	}
	rep := sim.Evaluate(txns, alerted)
	md := rep.Markdown()
	fmt.Println()
	fmt.Print(md)
	if reportFile != "" {
		header := fmt.Sprintf("Seed %d, %d customers, %d warm-up + %d measured days, %d cases per scenario, %d payments, %.0f events/s.\n\n",
			cfg.Seed, cfg.Users, cfg.WarmupDays, cfg.EvalDays, cfg.CasesPerKind, len(txns), float64(len(txns))/elapsed.Seconds())
		if err := os.WriteFile(reportFile, []byte(header+md), 0o644); err != nil {
			return err
		}
	}
	byID := map[string]sim.Txn{}
	for _, t := range txns {
		byID[t.ID] = t
	}
	rules := map[string][]string{}
	for _, a := range list {
		for _, s := range a.Signals {
			rules[strings.TrimPrefix(a.TransactionID, "txn_")] = append(rules[strings.TrimPrefix(a.TransactionID, "txn_")], s.Rule)
		}
	}
	byRules := map[string]int{}
	for _, id := range rep.FalsePositiveIDs {
		byRules[strings.Join(rules[id], "+")]++
	}
	if len(byRules) > 0 {
		fmt.Printf("false positives by rule: %v\n", byRules)
	}
	for i, id := range rep.FalsePositiveIDs {
		if i == 10 {
			fmt.Printf("  ... and %d more\n", len(rep.FalsePositiveIDs)-10)
			break
		}
		t := byID[id]
		fmt.Printf("  false positive: %s pays %s %s NZD %v\n", t.From, t.To, money.Format(t.Minor, "NZD"), rules[id])
	}

	var problems []string
	for _, s := range rep.Scenarios {
		if s.Detectable && s.Recall() < minRecall {
			problems = append(problems, fmt.Sprintf("%s recall %.0f%% < %.0f%%", s.Name, s.Recall()*100, minRecall*100))
		}
	}
	if rep.FPR() > maxFPR {
		problems = append(problems, fmt.Sprintf("false positive rate %.3f%% > %.3f%%", rep.FPR()*100, maxFPR*100))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	fmt.Println("\nPASS")
	return nil
}

// viaLedger runs a small scripted day through the real ledger.
func viaLedger(fraud, ledger *client) error {
	run := randHex(3)
	newAccount := func(name string, allowNegative bool) (string, error) {
		var a struct{ ID string }
		err := ledger.json("POST", "/v1/accounts", map[string]any{"name": run + " " + name, "currency": "NZD", "allow_negative": allowNegative}, &a)
		return a.ID, err
	}
	n := 0
	pay := func(from, to, amount string) error {
		n++
		b, _ := json.Marshal(map[string]string{"from": from, "to": to, "amount": amount, "currency": "NZD"})
		_, err := ledger.do("POST", "/v1/transfers", map[string]string{"Idempotency-Key": fmt.Sprintf("%s-%d", run, n)}, b, nil)
		return err
	}
	must := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(1)
		}
	}
	acct := func(name string) string {
		id, err := newAccount(name, false)
		must(err)
		return id
	}

	bank, err := newAccount("funding", true)
	if err != nil {
		return err
	}
	must(fraud.json("PUT", "/v1/trusted-accounts/"+bank, map[string]string{"note": "simulation funding account"}, nil))
	shops := []string{acct("cafe"), acct("supermarket"), acct("petrol")}

	ordinary := make([]string, 12)
	for i := range ordinary {
		ordinary[i] = acct(fmt.Sprintf("customer %d", i))
		must(pay(bank, ordinary[i], "5000.00"))
	}
	for round := range 3 {
		for i, u := range ordinary {
			must(pay(u, shops[(i+round)%len(shops)], fmt.Sprintf("%d.%02d", 12+i*3, round*7)))
		}
	}

	// Takeover: a normal history, then a big payment to a stranger and a burst.
	victim := acct("takeover victim")
	must(pay(bank, victim, "8000.00"))
	for i := range 6 {
		must(pay(victim, shops[i%3], fmt.Sprintf("%d.50", 20+i*5)))
	}
	attacker := acct("attacker")
	must(pay(victim, attacker, "3500.00"))
	for range 10 {
		must(pay(victim, attacker, "50.00"))
	}

	// Mule: four customers pay one account, which forwards it at once.
	mule := acct("mule")
	for _, u := range ordinary[:4] {
		must(pay(u, mule, "600.00"))
	}
	must(pay(mule, acct("cash out"), "2200.00"))

	// Structuring: three payments just under 10,000.
	smurf := acct("structurer")
	must(pay(bank, smurf, "40000.00"))
	for i := range 3 {
		must(pay(smurf, acct(fmt.Sprintf("payee %d", i)), fmt.Sprintf("%d.00", 9_400+i*150)))
	}

	// Fan-out: small payments to six new people.
	spreader := acct("fan-out")
	must(pay(bank, spreader, "1000.00"))
	for i := range 6 {
		must(pay(spreader, acct(fmt.Sprintf("drop %d", i)), "25.00"))
	}
	fmt.Printf("posted %d transfers through the ledger (run %s)\n", n, run)

	expect := map[string]string{victim: "takeover", mule: "mule", smurf: "structuring", spreader: "fan_out"}
	innocent := map[string]bool{bank: true}
	for _, u := range ordinary[4:] {
		innocent[u] = true
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		var page struct{ Alerts []alert }
		if err := fraud.json("GET", "/v1/alerts?limit=500", nil, &page); err != nil {
			return err
		}
		found := map[string]bool{}
		for _, a := range page.Alerts {
			if innocent[a.AccountID] {
				return fmt.Errorf("alert on an ordinary customer: %+v", a)
			}
			if _, ok := expect[a.AccountID]; ok {
				found[a.AccountID] = true
			}
		}
		if len(found) == len(expect) {
			for acc, name := range expect {
				fmt.Printf("  caught %-12s on %s\n", name, acc)
			}
			fmt.Println("PASS: every pattern raised an alert, no ordinary customer did")
			return nil
		}
		if time.Now().After(deadline) {
			var missing []string
			for acc, name := range expect {
				if !found[acc] {
					missing = append(missing, name)
				}
			}
			return fmt.Errorf("no alert within 60s for: %s", strings.Join(missing, ", "))
		}
		time.Sleep(time.Second)
	}
}
