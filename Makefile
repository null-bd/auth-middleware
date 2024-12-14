.PHONY: test lint build

# Run tests
test:
    go test -v -race -cover ./...

# Run linter
lint:
    golangci-lint run

# Build
build:
    go build ./...

# Generate docs
docs:
    go doc -all > docs/API.md