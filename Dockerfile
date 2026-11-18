# Use the Docker Official Image; CI configures a Docker Hub cache mirror.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS go-builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG ZTAP_VERSION=dev
ARG ZTAP_COMMIT=unknown
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build -buildvcs=false -trimpath \
    -ldflags="-s -w -X github.com/saadshabir/ZTAP/internal/cli.BuildVersion=${ZTAP_VERSION} -X github.com/saadshabir/ZTAP/internal/cli.buildCommit=${ZTAP_COMMIT}" \
    -o /out/ztap ./cmd/ztap

FROM scratch
ARG ZTAP_VERSION=dev
ARG ZTAP_COMMIT=unknown

LABEL org.opencontainers.image.source="https://github.com/saadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP" \
      org.opencontainers.image.description="Linux eBPF enforcement for Kubernetes NetworkPolicy" \
      org.opencontainers.image.version="${ZTAP_VERSION}" \
      org.opencontainers.image.revision="${ZTAP_COMMIT}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-builder /out/ztap /ztap

EXPOSE 9090
ENTRYPOINT ["/ztap"]
