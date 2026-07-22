# syntax=docker/dockerfile:1

# One-shot pipeline container.
#
# The full OSV/CVE corpus is hundreds of thousands of small JSON files;
# host antivirus (e.g. Microsoft Defender) hooks every file operation and
# makes fetch/unify unusably slow — and may quarantine advisory files that
# embed exploit PoCs. Running the pipeline inside the container with the
# cache on a named volume keeps all per-file I/O inside the Linux VM,
# where the host scanner only sees one big disk image. Only the final
# tarball crosses back to the host.
#
# Usage (see also `make docker-pipeline`):
#   docker build -t wisteria-pipeline .
#   docker run --rm \
#     -v wisteria-cache:/cache \
#     -v "$(pwd)/out:/out" \
#     wisteria-pipeline
#
# Any argument other than the default "pipeline" is passed through to the
# wisteria binary, e.g.:
#   docker run --rm -v wisteria-cache:/cache wisteria-pipeline debug index

FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /wisteria .

# debian-slim instead of distroless: the entrypoint needs a shell and tar,
# and fetch needs CA certificates for HTTPS downloads.
FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /wisteria /usr/local/bin/wisteria
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV WISTERIA_CACHE_DIR=/cache
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["pipeline"]
