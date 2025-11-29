# Moon-Gazing-Tower Backend Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=server
BINARY_DIR=bin

# Suppress CGO warnings (go-m1cpu warning fix)
export CGO_CFLAGS=-w

# Build flags
LDFLAGS=-ldflags "-s -w"

.PHONY: all build clean test run deps tidy

all: clean build

# Build the application
build:
	@echo "Building..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./main.go
	@echo "Build complete: $(BINARY_DIR)/$(BINARY_NAME)"

# Build for production (smaller binary)
build-prod:
	@echo "Building for production..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) ./main.go
	@echo "Production build complete: $(BINARY_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	@echo "Clean complete"

# Run tests
test:
	$(GOTEST) -v ./...

# Run the application
run: build
	./$(BINARY_DIR)/$(BINARY_NAME)

# Download dependencies
deps:
	$(GOGET) -v ./...

# Tidy go modules
tidy:
	$(GOMOD) tidy

# Install development tools
tools:
	go install github.com/cosmtrek/air@latest

# Run with hot reload (requires air)
dev:
	air

# Build for different platforms
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-amd64 ./main.go

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BINARY_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-amd64 ./main.go
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-darwin-arm64 ./main.go

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-windows-amd64.exe ./main.go

# Build all platforms
build-all: build-linux build-darwin build-windows
	@echo "All platform builds complete"

# Docker build
docker-build:
	docker build -t moongazing-backend .

# Help
help:
	@echo "Available targets:"
	@echo "  make build       - Build the application"
	@echo "  make build-prod  - Build for production (smaller binary)"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test        - Run tests"
	@echo "  make run         - Build and run"
	@echo "  make deps        - Download dependencies"
	@echo "  make tidy        - Tidy go modules"
	@echo "  make dev         - Run with hot reload (requires air)"
	@echo "  make build-all   - Build for all platforms"
	@echo "  make docker-build - Build Docker image"
