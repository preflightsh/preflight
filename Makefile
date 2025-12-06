.PHONY: build test clean release install lint fmt

# Build binary
build:
	go build -o bin/preflight main.go

# Run tests
test:
	go test ./...

# Run tests with coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Release using goreleaser
release:
	goreleaser release --clean

# Release snapshot (for testing)
release-snapshot:
	goreleaser release --snapshot --clean

# Install locally
install: build
	cp bin/preflight /usr/local/bin/preflight

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Tidy dependencies
tidy:
	go mod tidy

# Run the CLI
run:
	go run main.go

# Run init command
run-init:
	go run main.go init

# Run scan command
run-scan:
	go run main.go scan
