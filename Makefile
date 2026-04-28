.PHONY: build test fmt vet tidy lint setup clean

BIN_DIR := bin
BINARY  := $(BIN_DIR)/wisteria

# Use the golangci-lint installed by scripts/setup.sh into $GOPATH/bin so the
# linter is built with the same Go toolchain as `go.mod` declares. A homebrew
# golangci-lint can be built with a newer Go than the local toolchain and then
# fails with "compile: version X does not match go tool version Y" (#36).
GOBIN          := $(shell go env GOPATH)/bin
GOLANGCI_LINT  := $(GOBIN)/golangci-lint

build: | $(BIN_DIR)
	go build -o $(BINARY) .

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test:
	go test ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy

lint:
	@test -x $(GOLANGCI_LINT) || { \
		echo "error: $(GOLANGCI_LINT) not found. Run 'make setup' first." >&2; \
		exit 1; \
	}
	$(GOLANGCI_LINT) run ./...

setup:
	./scripts/setup.sh

clean:
	rm -f $(BINARY)
	rmdir $(BIN_DIR) 2>/dev/null || true
