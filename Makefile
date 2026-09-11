GO ?= go
GOCACHE ?= $(CURDIR)/.cache/go-build
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint
GOFLAGS ?= -buildvcs=false

BIN_DIR := $(CURDIR)/bin
TOOLS_DIR := $(BIN_DIR)/tools
GOLANGCI_LINT_VERSION := v2.12.2
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint
ACTIONLINT_VERSION := v1.7.12
ACTIONLINT := $(TOOLS_DIR)/actionlint
GO_FILES := $(shell find . -type f -name '*.go' \
	-not -path './vendor/*' \
	-not -path './.cache/*' \
	-not -path './bin/*' \
	-not -path './dist/*')

.PHONY: build test vet fmt-check lint check generate check-generated integration docker phase0-fixture clean

build:
	@mkdir -p "$(BIN_DIR)"
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) build -o "$(BIN_DIR)/ztap" ./cmd/ztap

test:
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) test -race ./...

vet:
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) vet ./...

fmt-check:
	@unformatted="$$(gofmt -l $(GO_FILES))"; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' "$$unformatted"; \
		exit 1; \
	fi

$(GOLANGCI_LINT):
	@mkdir -p "$(TOOLS_DIR)"
	GOBIN="$(TOOLS_DIR)" GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(ACTIONLINT):
	@mkdir -p "$(TOOLS_DIR)"
	GOBIN="$(TOOLS_DIR)" GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

lint: fmt-check $(GOLANGCI_LINT) $(ACTIONLINT)
	GOCACHE="$(GOCACHE)" GOLANGCI_LINT_CACHE="$(GOLANGCI_LINT_CACHE)" GOFLAGS="$(GOFLAGS)" "$(GOLANGCI_LINT)" run --timeout=5m
	"$(ACTIONLINT)" .github/workflows/*.yml

check: build test vet lint

generate:
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) generate ./internal/enforcer/...

check-generated: generate
	git diff --exit-code -- internal/enforcer/bpf_bpfel.go internal/enforcer/bpf_bpfeb.go

integration:
	@test "$$($(GO) env GOOS)" = linux || { printf '%s\n' 'integration requires Linux'; exit 2; }
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) test -race -tags=integration ./internal/enforcer/...

docker:
	docker build -t ztap:dev .

phase0-fixture:
	sh scripts/phase0_reference_fixture.sh --output "$(CURDIR)/dist/phase0-v0.1.0" --force

clean:
	rm -f -- ./ztap ./ztap-operator ./bpfgen ./*.exe ./*.test ./coverage*.out ./coverage.html
	rm -rf -- ./bin ./dist ./.cache ./.pytest_cache ./.ruff_cache ./internal/anomaly/.pytest_cache ./internal/anomaly/.ruff_cache
	$(MAKE) -C bpf clean
