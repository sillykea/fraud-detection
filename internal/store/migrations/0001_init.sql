-- Every event the ledger delivered, so a redelivery is recognised and skipped.
CREATE TABLE processed_events (
    event_id    text PRIMARY KEY,
    received_at timestamptz NOT NULL DEFAULT now()
);

-- Events that were authentic but could not be used (malformed, unknown type).
-- They are acknowledged so one bad event can't stall the ledger's outbox,
-- and kept here for someone to look at.
CREATE TABLE rejected_events (
    event_id    text PRIMARY KEY,
    reason      text NOT NULL,
    payload     bytea NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);

-- One row per customer-to-customer movement of money, derived from a ledger
-- transaction. For conversions, amount is what left the payer and
-- to_amount is what reached the payee.
CREATE TABLE payments (
    transaction_id text PRIMARY KEY,
    kind           text NOT NULL,
    from_account   text NOT NULL,
    to_account     text NOT NULL,
    amount_minor   bigint NOT NULL CHECK (amount_minor > 0),
    currency       text NOT NULL,
    to_amount_minor bigint NOT NULL CHECK (to_amount_minor > 0),
    to_currency    text NOT NULL,
    occurred_at    timestamptz NOT NULL,
    score          double precision,
    scored_at      timestamptz
);
CREATE INDEX payments_from_time ON payments (from_account, occurred_at);
CREATE INDEX payments_to_time ON payments (to_account, occurred_at);
CREATE INDEX payments_pair ON payments (from_account, to_account);

-- Accounts whose outgoing payments are not scored: funding and settlement
-- accounts that legitimately send to thousands of customers.
CREATE TABLE trusted_accounts (
    account_id text PRIMARY KEY,
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id             bigserial PRIMARY KEY,
    transaction_id text NOT NULL UNIQUE REFERENCES payments (transaction_id),
    account_id     text NOT NULL,
    score          double precision NOT NULL CHECK (score >= 0 AND score <= 1),
    severity       text NOT NULL CHECK (severity IN ('medium', 'high')),
    signals        jsonb NOT NULL,
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolution     text CHECK (resolution IN ('fraud', 'legitimate')),
    note           text NOT NULL DEFAULT '',
    resolved_by    text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    CHECK ((status = 'open') = (resolution IS NULL))
);
CREATE INDEX alerts_open ON alerts (id) WHERE status = 'open';
CREATE INDEX alerts_account ON alerts (account_id, id);
