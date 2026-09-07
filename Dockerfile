# Build stage for Go application
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS go-builder

# eBPF bytecode is generated at build time (tools/bpfgen) and inlined into
# internal/enforcer/bpf_bpf*.go, and regeneration is verified by the CI drift
# check, so no clang/llvm/make/git toolchain is needed in this image.

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o ztap ./cmd/ztap

# Final stage - minimal runtime image
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/msaadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP" \
      org.opencontainers.image.description="Zero Trust Access Platform: eBPF-based microsegmentation and policy enforcement" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates iptables

# Create non-root user
RUN addgroup -g 1000 ztap && \
    adduser -D -u 1000 -G ztap ztap

# Create necessary directories
RUN mkdir -p /etc/ztap /var/lib/ztap /var/log/ztap && \
    chown -R ztap:ztap /etc/ztap /var/lib/ztap /var/log/ztap

# Copy compiled binary
COPY --from=go-builder /app/ztap /usr/local/bin/ztap

# Copy example configs
COPY examples/ /etc/ztap/examples/

# Set user
USER ztap

# Expose metrics port
EXPOSE 9090

# Set working directory
WORKDIR /etc/ztap

# Default command
ENTRYPOINT ["/usr/local/bin/ztap"]
CMD ["--help"]
