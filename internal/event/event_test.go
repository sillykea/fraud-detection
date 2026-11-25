package event

import (
	"errors"
	"testing"
	"time"
)

func TestParseTransfer(t *testing.T) {
	_, p, err := Parse([]byte(`{"event_id":"evt_1","type":"transaction.posted","transaction":{
		"id":"txn_1","kind":"transfer","created_at":"2026-11-25T10:00:00+01:00","entries":[
		{"account_id":"acc_a","amount_minor":-1250,"currency":"NZD"},
		{"account_id":"acc_b","amount_minor":1250,"currency":"NZD"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Payment{TransactionID: "txn_1", Kind: "transfer", From: "acc_a", To: "acc_b",
		AmountMinor: 1250, Currency: "NZD", ToAmountMinor: 1250, ToCurrency: "NZD",
		At: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	if p != want {
		t.Errorf("got %+v\nwant %+v", p, want)
	}
}

func TestParseConversionSkipsFXPools(t *testing.T) {
	_, p, err := Parse([]byte(`{"event_id":"evt_2","type":"transaction.posted","transaction":{
		"id":"txn_2","kind":"conversion","created_at":"2026-11-25T09:00:00Z","entries":[
		{"account_id":"acc_a","amount_minor":-10000,"currency":"NZD"},
		{"account_id":"sys_fx_nzd","amount_minor":10000,"currency":"NZD"},
		{"account_id":"sys_fx_eur","amount_minor":-5512,"currency":"EUR"},
		{"account_id":"acc_b","amount_minor":5512,"currency":"EUR"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.From != "acc_a" || p.To != "acc_b" || p.AmountMinor != 10000 || p.Currency != "NZD" ||
		p.ToAmountMinor != 5512 || p.ToCurrency != "EUR" {
		t.Errorf("got %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]struct {
		body string
		want error
	}{
		"not json":    {`{`, ErrInvalid},
		"no event id": {`{"type":"transaction.posted","transaction":{"id":"t","created_at":"2026-01-01T00:00:00Z"}}`, ErrInvalid},
		"other type": {`{"event_id":"e","type":"account.created","transaction":{"id":"t",
			"created_at":"2026-01-01T00:00:00Z"}}`, ErrNotPayment},
		"system only": {`{"event_id":"e","type":"transaction.posted","transaction":{"id":"t",
			"created_at":"2026-01-01T00:00:00Z","entries":[
			{"account_id":"sys_fx_nzd","amount_minor":-5,"currency":"NZD"},
			{"account_id":"sys_fx_x","amount_minor":5,"currency":"NZD"}]}}`, ErrNotPayment},
		"two payers": {`{"event_id":"e","type":"transaction.posted","transaction":{"id":"t",
			"created_at":"2026-01-01T00:00:00Z","entries":[
			{"account_id":"a","amount_minor":-5,"currency":"NZD"},
			{"account_id":"b","amount_minor":-5,"currency":"NZD"},
			{"account_id":"c","amount_minor":10,"currency":"NZD"}]}}`, ErrInvalid},
		"entry without account": {`{"event_id":"e","type":"transaction.posted","transaction":{"id":"t",
			"created_at":"2026-01-01T00:00:00Z","entries":[{"amount_minor":-5,"currency":"NZD"}]}}`, ErrInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse([]byte(c.body)); !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}
