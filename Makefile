.PHONY: build test fmt vet tidy lint setup clean

BIN_DIR := bin
BINARY  := $(BIN_DIR)/wisteria

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
	golangci-lint run ./...

setup:
	./scripts/setup.sh

clean:
	rm -f $(BINARY)
	rmdir $(BIN_DIR) 2>/dev/null || true
