// Command fraud runs the fraud detection service.
//
//	fraud                  serve the API and webhook
//	fraud migrate          apply database migrations and exit
//	fraud -version         print the version
//	fraud -healthcheck URL exit 0 if URL answers 200 (the image has no curl)
//
// Environment:
//
//	DATABASE_URL           postgres://user:pass@host:5432/db
//	FRAUD_API_TOKEN        bearer token for /v1 (32+ characters)
//	LEDGER_WEBHOOK_SECRET  verifies X-Ledger-Signature on /v1/events (32+ characters)
//	ALLOW_UNSIGNED_EVENTS  "true" to accept unsigned events (local development only)
//	FRAUD_LISTEN           listen address (default :8090)
//	AUTO_MIGRATE           apply migrations on start (default true)
//	RULE_VELOCITY_PER_MINUTE, RULE_FAN_OUT_PAYEES, RULE_SPIKE_MULTIPLE,
//	RULE_MULE_MIN_PAYERS, RULE_STRUCTURING_COUNT   rule thresholds (see README)
//	RULE_LARGE_AMOUNTS        per-currency "large" amounts, e.g. "NZD:2000,JPY:300000"
//	RULE_REPORTING_THRESHOLDS per-currency reporting thresholds, e.g. "NZD:10000"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sillykea/fraud-detection/internal/api"
	"github.com/sillykea/fraud-detection/internal/detector"
	"github.com/sillykea/fraud-detection/internal/metrics"
	"github.com/sillykea/fraud-detection/internal/money"
	"github.com/sillykea/fraud-detection/internal/rules"
	"github.com/sillykea/fraud-detection/internal/store"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	healthcheck := flag.String("healthcheck", "", "check that this URL answers 200, then exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *healthcheck != "" {
		os.Exit(checkHealth(*healthcheck))
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("version", version)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch flag.Arg(0) {
	case "", "serve":
		err = serve(ctx, log)
	case "migrate":
		err = migrate(ctx, log)
	default:
		err = fmt.Errorf("unknown command %q", flag.Arg(0))
	}
	if err != nil {
		log.Error("fraud stopped", "error", err)
		os.Exit(1)
	}
}

func checkHealth(url string) int {
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func open(ctx context.Context) (*pgxpool.Pool, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	return store.Open(ctx, url)
}

func migrate(ctx context.Context, log *slog.Logger) error {
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := store.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	log.Info("migrations applied", "applied", applied)
	return nil
}

// amounts parses "NZD:2000,JPY:300000" into minor units per currency.
func amounts(name string) (map[string]int64, error) {
	out := map[string]int64{}
	v := os.Getenv(name)
	if v == "" {
		return out, nil
	}
	for _, pair := range strings.Split(v, ",") {
		cur, amt, ok := strings.Cut(strings.TrimSpace(pair), ":")
		if !ok {
			return nil, fmt.Errorf("%s: want CUR:amount, got %q", name, pair)
		}
		minor, err := money.Parse(amt, cur)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[cur] = minor
	}
	return out, nil
}

func ruleConfig() (rules.Config, error) {
	var c rules.Config
	ints := map[string]*int{
		"RULE_VELOCITY_PER_MINUTE": &c.VelocityPerMinute,
		"RULE_FAN_OUT_PAYEES":      &c.FanOutPayees,
		"RULE_MULE_MIN_PAYERS":     &c.MuleMinPayers,
		"RULE_STRUCTURING_COUNT":   &c.StructuringCount,
	}
	for name, p := range ints {
		if v := os.Getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return c, fmt.Errorf("%s must be a positive integer", name)
			}
			*p = n
		}
	}
	if v := os.Getenv("RULE_SPIKE_MULTIPLE"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 1 {
			return c, errors.New("RULE_SPIKE_MULTIPLE must be a number above 1")
		}
		c.SpikeMultiple = f
	}
	var err error
	if c.LargeAmount, err = amounts("RULE_LARGE_AMOUNTS"); err != nil {
		return c, err
	}
	c.ReportingThreshold, err = amounts("RULE_REPORTING_THRESHOLDS")
	return c, err
}

func serve(ctx context.Context, log *slog.Logger) error {
	token := os.Getenv("FRAUD_API_TOKEN")
	if len(token) < 32 {
		return errors.New("FRAUD_API_TOKEN must be at least 32 characters")
	}
	secret := os.Getenv("LEDGER_WEBHOOK_SECRET")
	switch {
	case secret == "" && env("ALLOW_UNSIGNED_EVENTS", "false") != "true":
		return errors.New("LEDGER_WEBHOOK_SECRET is required (or ALLOW_UNSIGNED_EVENTS=true for local development)")
	case secret != "" && len(secret) < 32:
		return errors.New("LEDGER_WEBHOOK_SECRET must be at least 32 characters")
	case secret == "":
		log.Warn("accepting unsigned events: anyone who can reach /v1/events can feed in payments")
	}
	cfg, err := ruleConfig()
	if err != nil {
		return err
	}
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if env("AUTO_MIGRATE", "true") == "true" {
		if _, err := store.Migrate(ctx, pool); err != nil {
			return err
		}
	}

	reg := metrics.New()
	det := &detector.Detector{Pool: pool, Rules: cfg}
	bg, cancelBG := context.WithCancel(context.Background())
	defer cancelBG()
	go every(bg, 15*time.Second, func() {
		if n, err := det.OpenAlerts(bg); err == nil {
			reg.Set("fraud_alerts_open", "", float64(n))
		}
	})

	srv := &http.Server{
		Addr: env("FRAUD_LISTEN", ":8090"),
		Handler: (&api.Server{Detector: det, Pool: pool, Metrics: reg, Logger: log,
			Token: token, WebhookSecret: []byte(secret)}).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("fraud listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func every(ctx context.Context, d time.Duration, fn func()) {
	fn()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
