// Package detector ingests ledger events, keeps the payment history the rules
// need, and raises alerts.
//
// Each event is handled in one Postgres transaction: record the event ID,
// store the payment, compute features, score, and write any alert. A
// redelivered event finds its ID already recorded and changes nothing, so the
// ledger's at-least-once delivery becomes exactly-once processing.
package detector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sillykea/fraud-detection/internal/event"
	"github.com/sillykea/fraud-detection/internal/rules"
)

// Detector is safe for concurrent use.
type Detector struct {
	Pool  *pgxpool.Pool
	Rules rules.Config
}

// Outcome says what happened to one event.
type Outcome string

const (
	Scored    Outcome = "scored"    // a payment was scored
	Duplicate Outcome = "duplicate" // the event was processed before
	Ignored   Outcome = "ignored"   // valid, but nothing to score (trusted payer, system-only)
	Rejected  Outcome = "rejected"  // malformed; set aside in rejected_events
)

// IngestResult is what Ingest did.
type IngestResult struct {
	Outcome Outcome
	Payment event.Payment
	Result  rules.Result
	AlertID int64 // 0 if no alert was raised
	Reason  string
}

// Ingest processes one ledger event body. eventID is the delivery's
// Idempotency-Key; it must match the body's event_id when both are present.
func (d *Detector) Ingest(ctx context.Context, eventID string, body []byte) (IngestResult, error) {
	ev, p, perr := event.Parse(body)
	if eventID == "" {
		eventID = ev.EventID
	}
	if eventID == "" {
		return IngestResult{Outcome: Rejected, Reason: "no event id"}, fmt.Errorf("%w: no event id", event.ErrInvalid)
	}
	if perr == nil && ev.EventID != eventID {
		perr = fmt.Errorf("%w: Idempotency-Key %q does not match event_id %q", event.ErrInvalid, eventID, ev.EventID)
	}

	var res IngestResult
	err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		res = IngestResult{}
		tag, err := tx.Exec(ctx, `INSERT INTO processed_events (event_id) VALUES ($1) ON CONFLICT DO NOTHING`, eventID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			res.Outcome = Duplicate
			return nil
		}
		switch {
		case errors.Is(perr, event.ErrNotPayment):
			res.Outcome, res.Reason = Ignored, perr.Error()
			return nil
		case perr != nil:
			res.Outcome, res.Reason = Rejected, perr.Error()
			_, err := tx.Exec(ctx, `INSERT INTO rejected_events (event_id, reason, payload) VALUES ($1, $2, $3)`,
				eventID, perr.Error(), body)
			return err
		}
		res.Payment = p
		return d.score(ctx, tx, p, &res)
	})
	return res, err
}

func (d *Detector) score(ctx context.Context, tx pgx.Tx, p event.Payment, res *IngestResult) error {
	// Serialise scoring per payer. Two payments from one account arriving
	// together must each see the other, or a burst split across replicas
	// would never look like a burst.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, p.From); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO payments (transaction_id, kind, from_account, to_account, amount_minor, currency,
		                      to_amount_minor, to_currency, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING`,
		p.TransactionID, p.Kind, p.From, p.To, p.AmountMinor, p.Currency, p.ToAmountMinor, p.ToCurrency, p.At)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Same transaction under a different event ID. Never expected from
		// the ledger; treat it as already done rather than double-count.
		res.Outcome, res.Reason = Duplicate, "transaction already scored"
		return nil
	}
	var trusted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM trusted_accounts WHERE account_id = $1)`, p.From).
		Scan(&trusted); err != nil {
		return err
	}
	if trusted {
		res.Outcome, res.Reason = Ignored, "payer is a trusted account"
		return nil
	}

	f, err := features(ctx, tx, p, d.Rules)
	if err != nil {
		return err
	}
	res.Result = rules.Evaluate(d.Rules, f)
	res.Outcome = Scored
	if _, err := tx.Exec(ctx, `UPDATE payments SET score = $2, scored_at = now() WHERE transaction_id = $1`,
		p.TransactionID, res.Result.Score); err != nil {
		return err
	}
	if res.Result.Decision == rules.Allow {
		return nil
	}
	signals, err := json.Marshal(res.Result.Signals)
	if err != nil {
		return err
	}
	return tx.QueryRow(ctx, `
		INSERT INTO alerts (transaction_id, account_id, score, severity, signals)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		p.TransactionID, p.From, res.Result.Score, res.Result.Severity(), signals).Scan(&res.AlertID)
}

// Score checks a payment that hasn't happened yet, without storing anything,
// so a payment flow can ask before it posts.
func (d *Detector) Score(ctx context.Context, p event.Payment) (rules.Result, error) {
	if p.ToAmountMinor == 0 {
		p.ToAmountMinor, p.ToCurrency = p.AmountMinor, p.Currency
	}
	var r rules.Result
	err := pgx.BeginTxFunc(ctx, d.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		f, err := features(ctx, tx, p, d.Rules)
		if err != nil {
			return err
		}
		r = rules.Evaluate(d.Rules, f)
		return nil
	})
	return r, err
}

// features reads the payer's history as of p.At, leaving out p itself, then
// adds p. Doing the "+ this payment" step here, not in SQL, means the same
// code serves stored payments and hypothetical ones from Score.
//
// Windows are by when the ledger posted each payment, not when it arrived
// here, so a delayed event is judged against the activity around it.
func features(ctx context.Context, tx pgx.Tx, p event.Payment, cfg rules.Config) (rules.Features, error) {
	f := rules.Features{AmountMinor: p.AmountMinor, Currency: p.Currency}
	reporting := cfg.Reporting(p.Currency)
	err := tx.QueryRow(ctx, `
		WITH mine AS (
			SELECT * FROM payments
			WHERE from_account = $1 AND transaction_id <> $2
			  AND occurred_at <= $3 AND occurred_at > $3 - interval '30 days'
		)
		SELECT
			(SELECT count(*) FROM mine WHERE occurred_at > $3 - interval '1 minute'),
			(SELECT count(DISTINCT to_account) FROM mine
			   WHERE occurred_at > $3 - interval '10 minutes' AND to_account <> $4),
			(SELECT count(*) FROM mine WHERE currency = $5),
			(SELECT coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY amount_minor), 0) FROM mine WHERE currency = $5),
			(SELECT count(*) FROM payments
			   WHERE from_account = $1 AND to_account = $4 AND transaction_id <> $2 AND occurred_at <= $3),
			(SELECT coalesce(max(amount_minor), 0) FROM payments
			   WHERE from_account = $1 AND to_account = $4 AND currency = $5 AND transaction_id <> $2 AND occurred_at <= $3),
			(SELECT coalesce(sum(to_amount_minor), 0) FROM payments
			   WHERE to_account = $1 AND to_currency = $5 AND occurred_at <= $3 AND occurred_at > $3 - interval '30 minutes'),
			(SELECT count(DISTINCT from_account) FROM payments
			   WHERE to_account = $1 AND occurred_at <= $3 AND occurred_at > $3 - interval '30 minutes'),
			(SELECT coalesce(sum(amount_minor), 0) FROM mine
			   WHERE currency = $5 AND occurred_at > $3 - interval '30 minutes'),
			(SELECT count(*) FROM mine
			   WHERE currency = $5 AND occurred_at > $3 - interval '24 hours'
			     AND amount_minor < $6 AND amount_minor * 10 >= $6 * 9)`,
		p.From, p.TransactionID, p.At, p.To, p.Currency, reporting).Scan(
		&f.Outgoing1m, &f.DistinctPayees10m, &f.History30d, &f.Median30dMinor,
		&f.PriorToPayee, &f.LargestToPayee, &f.Inflow30mMinor, &f.DistinctPayers30m,
		&f.Outflow30mMinor, &f.NearThreshold24h)
	if err != nil {
		return f, fmt.Errorf("features: %w", err)
	}
	f.Outgoing1m++
	f.DistinctPayees10m++ // this payee, which the query left out
	f.Outflow30mMinor += p.AmountMinor
	if cfg.NearThreshold(p.AmountMinor, p.Currency) {
		f.NearThreshold24h++
	}
	return f, nil
}
