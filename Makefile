# Moon-Gazing-Tower Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=server
BINARY_DIR=bin

# Build flags
LDFLAGS=-ldflags "-s -w"

.PHONY: all build clean test run deps tidy lint fmt install-tools pre-push

all: clean build

# Build the application
build:
	@echo "Building..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./main.go
	@echo "Build complete: $(BINARY_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f coverage.out
	@echo "Clean complete"

# Run tests with coverage
test:
	@echo "Running tests with race detection and coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo "Coverage report:"
	@go tool cover -func=coverage.out

# Run the application
run: build
	./$(BINARY_DIR)/$(BINARY_NAME)

# Download dependencies
deps:
	$(GOMOD) download

# Tidy go modules
tidy:
	$(GOMOD) tidy

# Code formatting
fmt:
	@echo "Formatting code..."
	@gofmt -w .
	@goimports -w .
	@echo "Format complete"

# Run linters
lint:
	@echo "Running linters..."
	@golangci-lint run ./...
	@echo "Lint complete"

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Tools installed"

# Pre-push validation
pre-push:
	@echo "Running pre-push checks..."
	@echo "→ Checking code format..."
	@test -z "$$(gofmt -l . | grep -v vendor)" || (echo "✗ Code not formatted. Run 'make fmt'" && exit 1)
	@echo "→ Checking go.mod..."
	@go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "✗ go.mod/go.sum not tidy" && exit 1)
	@echo "→ Running linters..."
	@golangci-lint run ./...
	@echo "→ Running tests..."
	@go test -race ./...
	@echo "✓ All pre-push checks passed"
