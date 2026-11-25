VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TEST_DB ?= postgres://app:app@localhost:5432/fraud?sslmode=disable
TOKEN ?= demo-fraud-token-0123456789abcdef0123
SECRET ?= demo-webhook-secret-0123456789abcdef0
LEDGER_TOKEN ?= demo-token-change-me-0123456789abcdef

.PHONY: test lint vuln build up down simulate simulate-ledger

test: ## Unit tests, plus Postgres tests when the database is up (make up)
	FRAUD_TEST_DATABASE_URL=$(TEST_DB) go test -race ./...

lint:
	test -z "$$(gofmt -l .)" && go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...

build:
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)" -o bin/fraud ./cmd/fraud
	CGO_ENABLED=0 go build -o bin/simulate ./cmd/simulate

up: ## Postgres, the fraud service and the payments ledger feeding it
	docker compose up --build -d --wait

down:
	docker compose down -v

simulate: ## Two months of labelled traffic; prints recall and false positives
	go run ./cmd/simulate -token $(TOKEN) -secret $(SECRET)

simulate-ledger: ## A scripted day of fraud through the real ledger
	go run ./cmd/simulate -mode ledger -token $(TOKEN) -ledger-token $(LEDGER_TOKEN)
