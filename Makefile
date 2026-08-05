BINARY  := ctfd-mcp
VERSION ?= 1.0.0
PKG     := github.com/tjobe4340/ctfd-mcp
LDFLAGS := -s -w -X $(PKG)/internal/config.Version=$(VERSION)

.PHONY: all build test test-short vet lint check clean install cross

all: check build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/ctfd-mcp

# The full suite compiles the binary and drives it over stdio.
test:
	go test ./...

test-short:
	go test -short ./...

vet:
	go vet ./...

# Race detection needs cgo, so it is a separate target rather than part of check.
race:
	CGO_ENABLED=1 go test -race ./internal/...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

check: vet test

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/ctfd-mcp

# Static binaries for the platforms an MCP client is likely to run on.
cross:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64      ./cmd/ctfd-mcp
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64      ./cmd/ctfd-mcp
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64     ./cmd/ctfd-mcp
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64     ./cmd/ctfd-mcp
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/ctfd-mcp

clean:
	rm -rf bin dist coverage.out
