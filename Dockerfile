FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine AS go-builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /out/ztap ./cmd/ztap

FROM scratch

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.source="https://github.com/saadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP" \
      org.opencontainers.image.description="Linux eBPF enforcement for Kubernetes NetworkPolicy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-builder /out/ztap /ztap

EXPOSE 9090
ENTRYPOINT ["/ztap"]
