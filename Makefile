.PHONY: build test fmt vet tidy lint setup clean

BINARY := wisteria

build:
	go build -o $(BINARY) .

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
