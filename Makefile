.PHONY: build test fmt vet tidy clean

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

clean:
	rm -f $(BINARY)
