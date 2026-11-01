# Use the Docker Official Image; CI configures a Docker Hub cache mirror.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.2-alpine AS go-builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build -trimpath \
    -ldflags="-s -w" \
    -o /out/ztap ./cmd/ztap

FROM scratch

LABEL org.opencontainers.image.source="https://github.com/saadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP" \
      org.opencontainers.image.description="Linux eBPF enforcement for Kubernetes NetworkPolicy" \
      org.opencontainers.image.licenses="MIT"

COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-builder /out/ztap /ztap

EXPOSE 9090
ENTRYPOINT ["/ztap"]
