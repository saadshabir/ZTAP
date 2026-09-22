GO ?= go
GOCACHE ?= $(CURDIR)/.cache/go-build
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint
GOFLAGS ?= -buildvcs=false
# Keep CI's explicit clang-18 spelling authoritative, while allowing the
# pinned Homebrew LLVM 18 installation used by macOS contributors to satisfy
# the same generated-code check without an extra environment override.
BPF2GO_CC ?= $(or $(shell command -v clang-18 2>/dev/null),$(wildcard /opt/homebrew/opt/llvm@18/bin/clang),$(wildcard /usr/local/opt/llvm@18/bin/clang),clang-18)
PHASE5_EVIDENCE_DIR ?= dist
PHASE5_EXPECTED_RUN_ID ?=
PHASE5_ENVIRONMENT_FILE ?=
PHASE5_EXPECTED_MIGRATION_RUN_ID ?=
PHASE5_EXPECTED_COMMIT ?=
PHASE5_EXPECTED_RELEASE_REF ?=
PHASE5_EXPECTED_ENVIRONMENT_ARCH ?=
PHASE5_HOSTED_EBPF_DIR ?=
PHASE5_HOSTED_CAPABILITY_DIR ?=
PHASE5_RUN_ID ?= $(if $(GITHUB_RUN_ID),github-$(GITHUB_RUN_ID)-$(GITHUB_SHA),local-$(shell date -u +%Y%m%dT%H%M%S)-$(shell printf '%s' "$$PPID"))
PHASE5_VERIFY_FLAGS = $(if $(PHASE5_EXPECTED_RUN_ID),--run-id "$(PHASE5_EXPECTED_RUN_ID)") $(if $(PHASE5_ENVIRONMENT_FILE),--environment "$(PHASE5_ENVIRONMENT_FILE)") $(if $(PHASE5_EXPECTED_MIGRATION_RUN_ID),--migration-ci-run-id "$(PHASE5_EXPECTED_MIGRATION_RUN_ID)") $(if $(PHASE5_EXPECTED_COMMIT),--commit "$(PHASE5_EXPECTED_COMMIT)") $(if $(PHASE5_EXPECTED_RELEASE_REF),--release-ref "$(PHASE5_EXPECTED_RELEASE_REF)") $(if $(PHASE5_EXPECTED_ENVIRONMENT_ARCH),--environment-arch "$(PHASE5_EXPECTED_ENVIRONMENT_ARCH)") $(if $(PHASE5_HOSTED_EBPF_DIR),--hosted-ebpf-dir "$(PHASE5_HOSTED_EBPF_DIR)") $(if $(PHASE5_HOSTED_CAPABILITY_DIR),--hosted-capability-dir "$(PHASE5_HOSTED_CAPABILITY_DIR)")

BIN_DIR := $(CURDIR)/bin
TOOLS_DIR := $(BIN_DIR)/tools
GOLANGCI_LINT_VERSION := v2.12.2
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint
ACTIONLINT_VERSION := v1.7.12
ACTIONLINT := $(TOOLS_DIR)/actionlint
GOVULNCHECK_VERSION := v1.1.4
GOVULNCHECK := $(TOOLS_DIR)/govulncheck
GO_FILES := $(shell find . -type f -name '*.go' \
	-not -path './vendor/*' \
	-not -path './.cache/*' \
	-not -path './bin/*' \
	-not -path './dist/*')

.PHONY: build test vet fmt-check lint vulncheck check generate check-generated integration performance verify-performance docker clean

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

$(GOVULNCHECK):
	@mkdir -p "$(TOOLS_DIR)"
	GOBIN="$(TOOLS_DIR)" GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

vulncheck: $(GOVULNCHECK)
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" "$(GOVULNCHECK)" ./...

check: build test vet lint vulncheck

generate:
	BPF2GO_CC="$(BPF2GO_CC)" GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) generate ./internal/enforcer/...

# Compare the working-tree snapshot before and after regeneration so a dirty
# source/binding pair is checked for reproducibility without comparing it to
# the pre-Phase-5 bindings in HEAD.
check-generated:
	@ztap_generated_tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$ztap_generated_tmp"' EXIT; \
	git diff --binary HEAD -- internal/enforcer/engine_bpfel.go internal/enforcer/engine_bpfeb.go > "$$ztap_generated_tmp/before.patch"; \
	BPF2GO_CC="$(BPF2GO_CC)" GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) generate ./internal/enforcer/...; \
	git diff --binary HEAD -- internal/enforcer/engine_bpfel.go internal/enforcer/engine_bpfeb.go > "$$ztap_generated_tmp/after.patch"; \
	if ! cmp -s "$$ztap_generated_tmp/before.patch" "$$ztap_generated_tmp/after.patch"; then \
		printf '%s\n' 'generated eBPF bindings changed during regeneration'; \
		diff -u "$$ztap_generated_tmp/before.patch" "$$ztap_generated_tmp/after.patch" || true; \
		exit 1; \
	fi

integration:
	@test "$$($(GO) env GOOS)" = linux || { printf '%s\n' 'integration requires Linux'; exit 2; }
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) vet -tags=integration ./internal/enforcer/... ./internal/cli/...
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) test -race -tags=integration ./internal/enforcer/... ./internal/cli/...

performance:
	@test "$$($(GO) env GOOS)" = linux || { printf '%s\n' 'performance requires Linux'; exit 2; }
	@if [ -L "$(CURDIR)/dist" ]; then printf '%s\n' 'performance evidence directory must not be a symlink' >&2; exit 1; fi
	@if [ -e "$(CURDIR)/dist" ] && [ ! -d "$(CURDIR)/dist" ]; then printf '%s\n' 'performance evidence path must be a directory' >&2; exit 1; fi
	@mkdir -p "$(CURDIR)/dist"
	rm -f -- \
		"$(CURDIR)/dist/phase5-performance.json" \
		"$(CURDIR)/dist/phase5-flow.json" \
		"$(CURDIR)/dist/phase5-packet.json" \
		"$(CURDIR)/dist/phase5-agent.json" \
		"$(CURDIR)/dist/phase5-agent-event.json" \
		"$(CURDIR)/dist/phase5-agent-pod-start.json" \
		"$(CURDIR)/dist/phase5-agent-restart.json" \
		"$(CURDIR)/dist/phase5-agent-crash.json" \
		"$(CURDIR)/dist/phase5-agent-resource.json" \
		"$(CURDIR)/dist/phase5-agent-reconcile.json"
	GOMAXPROCS=2 GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" ZTAP_PHASE5_PERFORMANCE=1 ZTAP_PHASE5_RUN_ID="$(PHASE5_RUN_ID)" \
	ZTAP_PHASE5_PERFORMANCE_OUTPUT="$(CURDIR)/dist/phase5-performance.json" \
	ZTAP_PHASE5_FLOW_OUTPUT="$(CURDIR)/dist/phase5-flow.json" \
	ZTAP_PHASE5_PACKET_OUTPUT="$(CURDIR)/dist/phase5-packet.json" \
	$(GO) test -count=1 -tags=integration -run '^TestPhase5(ReferenceFixtureApply|FlowAccounting|PacketAndTCPPerformance)$$' -timeout=10m -v ./internal/enforcer
	GOMAXPROCS=2 GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" ZTAP_PHASE5_PERFORMANCE=1 ZTAP_PHASE5_RUN_ID="$(PHASE5_RUN_ID)" \
	ZTAP_PHASE5_AGENT_OUTPUT="$(CURDIR)/dist/phase5-agent.json" \
	ZTAP_PHASE5_AGENT_EVENT_OUTPUT="$(CURDIR)/dist/phase5-agent-event.json" \
	ZTAP_PHASE5_AGENT_POD_START_OUTPUT="$(CURDIR)/dist/phase5-agent-pod-start.json" \
	ZTAP_PHASE5_AGENT_RESTART_OUTPUT="$(CURDIR)/dist/phase5-agent-restart.json" \
	ZTAP_PHASE5_AGENT_CRASH_OUTPUT="$(CURDIR)/dist/phase5-agent-crash.json" \
	ZTAP_PHASE5_AGENT_RESOURCE_OUTPUT="$(CURDIR)/dist/phase5-agent-resource.json" \
	ZTAP_PHASE5_AGENT_RECONCILE_OUTPUT="$(CURDIR)/dist/phase5-agent-reconcile.json" \
	$(GO) test -count=1 -tags=integration -run '^TestPhase5Agent(Reconciliation|Activation|EventActivation|PodStartClassification|RestartGap|CrashGap|ResourceUsage)$$' -timeout=10m -v ./internal/cli

verify-performance:
	GOCACHE="$(GOCACHE)" GOFLAGS="$(GOFLAGS)" $(GO) run ./tools/phase5verify --dir "$(PHASE5_EVIDENCE_DIR)" $(PHASE5_VERIFY_FLAGS)

docker:
	docker build -t ztap:dev .

clean:
	@if [ -d ./.cache ]; then chmod -R u+w ./.cache; fi
	rm -f -- ./ztap ./bpfgen ./*.exe ./*.test ./coverage*.out ./coverage.html
	rm -rf -- ./bin ./dist ./.cache ./.pytest_cache ./.ruff_cache
	$(MAKE) -C bpf clean
