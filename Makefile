.PHONY: build test fmt vet tidy lint setup clean docker-build docker-pipeline

BIN_DIR := bin
BINARY  := $(BIN_DIR)/wisteria

# Use the golangci-lint installed by scripts/setup.sh into $GOPATH/bin so the
# linter is built with the local Go toolchain. A Homebrew golangci-lint can be
# built with a newer Go than the local toolchain and then fails with
# "compile: version X does not match go tool version Y" (#36).
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

# One-shot pipeline container: fetch + unify run inside the Linux VM with
# the cache on a named volume (out of reach of host antivirus file hooks);
# only the final tarball lands on the host, in ./out/. See Dockerfile.
DOCKER_IMAGE := wisteria-pipeline

docker-build:
	docker build -t $(DOCKER_IMAGE) .

docker-pipeline: docker-build
	mkdir -p out
	docker run --rm \
		-v wisteria-cache:/cache \
		-v "$(CURDIR)/out:/out" \
		$(DOCKER_IMAGE)
