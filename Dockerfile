# Use the Docker Official Image; CI configures a Docker Hub cache mirror.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS go-builder

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
