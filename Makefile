# Pane MDM - Build system
# Usage:
#   make          → build everything (web + go)
#   make dev      → run go server (web already built)
#   make web      → build React dashboard only
#   make clean    → remove build artifacts

BINARY    := pane
WEB_SRC   := web
WEB_DIST  := internal/server/web_dist
GO_PKG    := ./cmd/pane

.PHONY: all web go clean dev

all: web go

## Build the React dashboard and copy into the Go embed directory
web:
	cd $(WEB_SRC) && npm install && npm run build
	if exist $(WEB_DIST) rmdir /s /q $(WEB_DIST)
	xcopy /e /i /q $(WEB_SRC)\dist $(WEB_DIST)

## Build the Go binary (assumes web is already built)
go:
	go build -o $(BINARY).exe $(GO_PKG)

## Build everything - web first, then go
build: web go

## Run the server in development mode
dev:
	go run $(GO_PKG) serve

## Remove build output
clean:
	if exist $(BINARY).exe del $(BINARY).exe
	if exist $(WEB_SRC)\dist rmdir /s /q $(WEB_SRC)\dist
	if exist $(WEB_DIST) rmdir /s /q $(WEB_DIST)

## Show what would be included in the binary
size:
	go build -o $(BINARY).exe $(GO_PKG)
	dir $(BINARY).exe
