// Package event turns a payments-ledger "transaction.posted" event into the
// payment it represents: who paid whom, how much, and when.
package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Ledger is the event body the ledger's outbox sends.
type Ledger struct {
	EventID     string `json:"event_id"`
	Type        string `json:"type"`
	Transaction struct {
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		CreatedAt time.Time `json:"created_at"`
		Entries   []struct {
			AccountID   string `json:"account_id"`
			AmountMinor int64  `json:"amount_minor"`
			Currency    string `json:"currency"`
		} `json:"entries"`
	} `json:"transaction"`
}

// Payment is one customer-to-customer movement of money.
type Payment struct {
	TransactionID string    `json:"transaction_id"`
	Kind          string    `json:"kind"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	AmountMinor   int64     `json:"amount_minor"`
	Currency      string    `json:"currency"`
	ToAmountMinor int64     `json:"to_amount_minor"`
	ToCurrency    string    `json:"to_currency"`
	At            time.Time `json:"at"`
}

var (
	// ErrInvalid means the event is malformed. It will never become valid,
	// so it should be set aside rather than retried.
	ErrInvalid = errors.New("invalid event")
	// ErrNotPayment means a well-formed event that moves no money between
	// customers (for example, only system accounts are involved).
	ErrNotPayment = errors.New("not a customer payment")
)

// System accounts (FX pools) are internal plumbing: a conversion moves money
// customer -> pool -> pool -> customer, and only the two ends matter here.
func system(account string) bool { return strings.HasPrefix(account, "sys_") }

// Parse decodes body and extracts the payment.
func Parse(body []byte) (Ledger, Payment, error) {
	var ev Ledger
	if err := json.Unmarshal(body, &ev); err != nil {
		return ev, Payment{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if ev.EventID == "" || ev.Transaction.ID == "" || ev.Transaction.CreatedAt.IsZero() {
		return ev, Payment{}, fmt.Errorf("%w: missing event_id, transaction id or created_at", ErrInvalid)
	}
	if ev.Type != "transaction.posted" {
		return ev, Payment{}, fmt.Errorf("%w: type %q", ErrNotPayment, ev.Type)
	}
	p, err := toPayment(ev)
	return ev, p, err
}

func toPayment(ev Ledger) (Payment, error) {
	t := ev.Transaction
	p := Payment{TransactionID: t.ID, Kind: t.Kind, At: t.CreatedAt.UTC()}
	var payers, payees int
	for _, e := range t.Entries {
		if e.AccountID == "" || e.Currency == "" {
			return p, fmt.Errorf("%w: entry without account or currency", ErrInvalid)
		}
		if system(e.AccountID) {
			continue
		}
		switch {
		case e.AmountMinor < 0:
			payers++
			p.From, p.AmountMinor, p.Currency = e.AccountID, -e.AmountMinor, e.Currency
		case e.AmountMinor > 0:
			payees++
			p.To, p.ToAmountMinor, p.ToCurrency = e.AccountID, e.AmountMinor, e.Currency
		}
	}
	if payers == 0 && payees == 0 {
		return p, ErrNotPayment
	}
	if payers != 1 || payees != 1 || p.From == p.To {
		return p, fmt.Errorf("%w: want one customer paying one other, got %d payers and %d payees", ErrInvalid, payers, payees)
	}
	return p, nil
}
