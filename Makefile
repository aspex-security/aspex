BINARY_SCAN  := aspex-scan
BINARY_TRACE := aspex-trace
VERSION      := $(shell cat internal/version/version.go | grep 'Version = ' | cut -d'"' -f2)

.PHONY: build test lint clean install release-dry-run completions

build:
	go build -ldflags="-X github.com/aspex-security/aspex/internal/version.BuildDate=$(shell date -u +%Y-%m-%d)" \
		-o $(BINARY_SCAN) ./cmd/aspex-scan
	go build -ldflags="-X github.com/aspex-security/aspex/internal/version.BuildDate=$(shell date -u +%Y-%m-%d)" \
		-o $(BINARY_TRACE) ./cmd/aspex-trace
	@echo "Built $(BINARY_SCAN) and $(BINARY_TRACE) v$(VERSION)"

test:
	go test ./... -race -count=1

test-cover:
	go test ./... -race -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint:
	@which golangci-lint >/dev/null 2>&1 || (echo "Install golangci-lint: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

clean:
	rm -f $(BINARY_SCAN) $(BINARY_TRACE) coverage.out coverage.html

install: build
	sudo mv $(BINARY_SCAN) /usr/local/bin/$(BINARY_SCAN)
	sudo mv $(BINARY_TRACE) /usr/local/bin/$(BINARY_TRACE)
	@echo "Installed to /usr/local/bin"

completions: build
	mkdir -p completions
	./$(BINARY_SCAN) completion bash  > completions/aspex-scan.bash
	./$(BINARY_SCAN) completion zsh   > completions/aspex-scan.zsh
	./$(BINARY_SCAN) completion fish  > completions/aspex-scan.fish
	./$(BINARY_TRACE) completion bash > completions/aspex-trace.bash
	./$(BINARY_TRACE) completion zsh  > completions/aspex-trace.zsh
	./$(BINARY_TRACE) completion fish > completions/aspex-trace.fish
	@echo "Completions written to completions/"

release-dry-run:
	goreleaser release --snapshot --clean

vuln:
	govulncheck ./...

.DEFAULT_GOAL := build
