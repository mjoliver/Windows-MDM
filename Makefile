# Latchz MDM - Build system (POSIX / cross-platform)
# Usage:
#   make            → build everything (web + go)
#   make dev        → run the go server
#   make web        → build React dashboard only
#   make test       → run Go tests
#   make test-race  → run Go tests with the race detector
#   make cover      → run Go tests with a coverage profile + summary
#   make vet fmt-check → static checks
#   make clean      → remove build artifacts

BINARY    := latchz
WEB_SRC   := web
WEB_DIST  := internal/server/web_dist
GO_PKG    := ./cmd/latchz

.PHONY: all web go build dev test test-race cover vet fmt-check tidy clean

all: web go

## Build the React dashboard and copy into the Go embed directory
web:
	cd $(WEB_SRC) && npm install && npm run build
	rm -rf $(WEB_DIST)
	cp -r $(WEB_SRC)/dist $(WEB_DIST)

## Build the Go binary (assumes web is already built / embedded)
go:
	go build -o $(BINARY) $(GO_PKG)

build: web go

## Run the server in development mode
dev:
	go run $(GO_PKG) serve

## Run the Go test suite
test:
	go test ./...

## Run the Go test suite with the race detector
test-race:
	go test -race ./...

## Run tests with coverage and print a per-package + total summary
cover:
	go test -coverprofile=cover.out -covermode=atomic ./...
	go tool cover -func=cover.out | tail -n 1

vet:
	go vet ./...

## Fail if any Go file is not gofmt-clean
fmt-check:
	@unformatted=$$(gofmt -l internal cmd); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

tidy:
	go mod tidy

## Remove build output
clean:
	rm -f $(BINARY) cover.out
	rm -rf $(WEB_SRC)/dist
