.PHONY: help test lint build clean fmt install-tools install-hooks

# Default target
help:
	@echo "Available commands:"
	@echo "  make test          - Run tests with race detection"
	@echo "  make lint          - Run code linting"
	@echo "  make build         - Build the project"
	@echo "  make fmt           - Format code"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make install-tools - Install development tools"
	@echo "  make install-hooks - Install Git hooks"

# Run tests with race detection and coverage
test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Run linting
lint:
	golangci-lint run ./...

# Build all packages
build:
	go build -v ./...

# Format code
fmt:
	gofmt -s -w .
	goimports -w .

# Clean build artifacts
clean:
	go clean ./...
	rm -f coverage.out

# Install development tools
install-tools:
	go install golang.org/x/tools/cmd/goimports@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin

# Install Git hooks
install-hooks:
	bash scripts/install-hooks.sh
