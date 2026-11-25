package detector

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sillykea/fraud-detection/internal/rules"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Alert is a payment that needs a person to look at it.
type Alert struct {
	ID            int64          `json:"id"`
	TransactionID string         `json:"transaction_id"`
	AccountID     string         `json:"account_id"`
	ToAccount     string         `json:"to_account"`
	AmountMinor   int64          `json:"amount_minor"`
	Currency      string         `json:"currency"`
	Score         float64        `json:"score"`
	Severity      string         `json:"severity"`
	Signals       []rules.Signal `json:"signals"`
	Status        string         `json:"status"`
	Resolution    *string        `json:"resolution"`
	Note          string         `json:"note"`
	ResolvedBy    *string        `json:"resolved_by"`
	OccurredAt    time.Time      `json:"occurred_at"`
	CreatedAt     time.Time      `json:"created_at"`
	ResolvedAt    *time.Time     `json:"resolved_at"`
}

const alertCols = `a.id, a.transaction_id, a.account_id, p.to_account, p.amount_minor, p.currency,
	a.score, a.severity, a.signals, a.status, a.resolution, a.note, a.resolved_by,
	p.occurred_at, a.created_at, a.resolved_at`

func scanAlert(row pgx.CollectableRow) (Alert, error) {
	var a Alert
	var signals []byte
	err := row.Scan(&a.ID, &a.TransactionID, &a.AccountID, &a.ToAccount, &a.AmountMinor, &a.Currency,
		&a.Score, &a.Severity, &signals, &a.Status, &a.Resolution, &a.Note, &a.ResolvedBy,
		&a.OccurredAt, &a.CreatedAt, &a.ResolvedAt)
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal(signals, &a.Signals)
}

// AlertFilter narrows List. Empty fields match everything.
type AlertFilter struct {
	Status    string // open | resolved
	AccountID string
	BeforeID  int64 // keyset pagination: alerts with a smaller ID
	Limit     int
}

// List returns alerts newest first.
func (d *Detector) List(ctx context.Context, f AlertFilter) ([]Alert, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := d.Pool.Query(ctx, `
		SELECT `+alertCols+` FROM alerts a JOIN payments p USING (transaction_id)
		WHERE ($1 = '' OR a.status = $1) AND ($2 = '' OR a.account_id = $2) AND ($3 = 0 OR a.id < $3)
		ORDER BY a.id DESC LIMIT $4`, f.Status, f.AccountID, f.BeforeID, f.Limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAlert)
}

// Get returns one alert.
func (d *Detector) Get(ctx context.Context, id int64) (Alert, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+alertCols+` FROM alerts a JOIN payments p USING (transaction_id) WHERE a.id = $1`, id)
	if err != nil {
		return Alert{}, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAlert)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// Resolve closes an open alert as fraud or legitimate. Resolving twice is a
// conflict, so two reviewers can't silently overwrite each other.
func (d *Detector) Resolve(ctx context.Context, id int64, resolution, note, by string) (Alert, error) {
	if resolution != "fraud" && resolution != "legitimate" {
		return Alert{}, errors.New(`resolution must be "fraud" or "legitimate"`)
	}
	tag, err := d.Pool.Exec(ctx, `
		UPDATE alerts SET status = 'resolved', resolution = $2, note = $3, resolved_by = $4, resolved_at = now()
		WHERE id = $1 AND status = 'open'`, id, resolution, note, by)
	if err != nil {
		return Alert{}, err
	}
	if tag.RowsAffected() == 0 {
		a, err := d.Get(ctx, id)
		if err != nil {
			return a, err
		}
		return a, ErrConflict
	}
	return d.Get(ctx, id)
}

// OpenAlerts counts alerts waiting for review.
func (d *Detector) OpenAlerts(ctx context.Context) (int64, error) {
	var n int64
	err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE status = 'open'`).Scan(&n)
	return n, err
}

// Trust stops scoring an account's outgoing payments.
func (d *Detector) Trust(ctx context.Context, account, note string) error {
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO trusted_accounts (account_id, note) VALUES ($1, $2)
		ON CONFLICT (account_id) DO UPDATE SET note = EXCLUDED.note`, account, note)
	return err
}

// Untrust resumes scoring an account.
func (d *Detector) Untrust(ctx context.Context, account string) error {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM trusted_accounts WHERE account_id = $1`, account)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
