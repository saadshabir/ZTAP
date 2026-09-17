package enforcer

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"ztap/internal/alert"
	"ztap/internal/audit"
	"ztap/internal/cluster"
	"ztap/internal/logging"
	"ztap/internal/policy"
)

// PolicyEnforcer manages automatic policy enforcement from cluster synchronization.
type PolicyEnforcer struct {
	mu              sync.RWMutex
	policySync      cluster.PolicySync
	discovery       policy.ServiceDiscovery
	subjectResolver SubjectResolver
	enforcedVersion map[string]int64 // Track which version of each policy is enforced
	activePolicies  map[string]cluster.PolicyUpdate
	running         bool
	stopCh          chan struct{}
	cgroupPath      string             // For eBPF enforcement
	auditLogger     *audit.AuditLogger // Audit logging for policy operations
	alerts          *alert.Manager
	resolveLabels   bool
	dryRun          bool
	retriggerCh     chan struct{}
	compileCache    map[string]compileCacheEntry
	selectorCache   map[string]selectorCacheEntry
	selectorRefs    map[string]selectorRef
}

type compileCacheEntry struct {
	version    int64
	yamlHash   uint64
	normalized []policy.NetworkPolicy
}

type selectorWatch struct {
	tenant string
	labels map[string]string
}

type selectorCacheEntry struct {
	version   int64
	yamlHash  uint64
	selectors map[string]selectorWatch
}

type selectorRef struct {
	tenant string
	labels map[string]string
	refs   int
}

// PolicyEnforcerConfig holds configuration for the policy enforcer.
type PolicyEnforcerConfig struct {
	PolicySync      cluster.PolicySync      // Policy synchronization backend
	Discovery       policy.ServiceDiscovery // Service discovery for label resolution
	SubjectResolver SubjectResolver         // Optional subject->cgroup resolver (Linux eBPF isolation)
	CgroupPath      string                  // Cgroup path for eBPF attachment (Linux only)
	Alerts          *alert.Manager
	ResolveLabels   bool
	DryRun          bool
	AuditLogger     *audit.AuditLogger
}

// NewPolicyEnforcer creates a new policy enforcer that watches for policy updates.
func NewPolicyEnforcer(config PolicyEnforcerConfig) *PolicyEnforcer {
	auditLogger := config.AuditLogger
	if auditLogger == nil {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = os.TempDir()
		}
		logPath := filepath.Join(homeDir, ".ztap", "audit.log")
		al, err := audit.NewAuditLogger(logPath)
		if err != nil {
			logging.Warnf("failed to initialize audit logger: %v", err)
		}
		auditLogger = al
	}

	return &PolicyEnforcer{
		policySync:      config.PolicySync,
		discovery:       config.Discovery,
		subjectResolver: config.SubjectResolver,
		enforcedVersion: make(map[string]int64),
		activePolicies:  make(map[string]cluster.PolicyUpdate),
		stopCh:          make(chan struct{}),
		retriggerCh:     make(chan struct{}, 1),
		cgroupPath:      config.CgroupPath,
		auditLogger:     auditLogger,
		alerts:          config.Alerts,
		resolveLabels:   config.ResolveLabels,
		dryRun:          config.DryRun,
		compileCache:    make(map[string]compileCacheEntry),
		selectorCache:   make(map[string]selectorCacheEntry),
		selectorRefs:    make(map[string]selectorRef),
	}
}

// Start begins watching for policy updates and enforcing them automatically.
func (pe *PolicyEnforcer) Start(ctx context.Context) error {
	pe.mu.Lock()
	if pe.running {
		pe.mu.Unlock()
		return nil
	}
	pe.running = true
	pe.mu.Unlock()

	if pe.alerts != nil {
		pe.alerts.Start(ctx)
	}

	if pe.dryRun {
		logging.Info("Policy enforcer started in DRY-RUN mode, watching for policy updates...", nil)
	} else {
		logging.Info("Policy enforcer started, watching for policy updates...", nil)
	}

	// Subscribe to policy updates
	policyUpdates := pe.policySync.SubscribePolicies(ctx)

	// Start enforcement loop
	go pe.enforcementLoop(ctx, policyUpdates)

	return nil
}

// Stop gracefully shuts down the policy enforcer.
func (pe *PolicyEnforcer) Stop() error {
	pe.mu.Lock()
	if !pe.running {
		pe.mu.Unlock()
		return nil
	}
	pe.running = false
	close(pe.stopCh)
	pe.mu.Unlock()

	if pe.alerts != nil {
		pe.alerts.Close()
	}

	logging.Info("Policy enforcer stopped", nil)
	return nil
}

// enforcementLoop watches for policy updates and applies them.
func (pe *PolicyEnforcer) enforcementLoop(ctx context.Context, updates <-chan cluster.PolicyUpdate) {
	if pe.resolveLabels && pe.discovery != nil {
		go pe.discoveryWatcher(ctx)
	}

	for {
		select {
		case <-pe.stopCh:
			return
		case <-ctx.Done():
			return
		case <-pe.retriggerCh:
			logging.Info("Retriggering enforcement due to discovery update", nil)
			if err := pe.reapplyAllPolicies(ctx); err != nil {
				logging.Warnf("Re-apply all policies failed: %v", err)
			}
		case update, ok := <-updates:
			if !ok {
				logging.Warn("Policy update channel closed, stopping enforcement loop", nil)
				return
			}

			policyKey := update.PolicyKeyString()
			if update.Deleted {
				pe.mu.RLock()
				previous, hadPrevious := pe.activePolicies[policyKey]
				pe.mu.RUnlock()
				var oldSelectors map[string]selectorWatch
				if hadPrevious {
					oldSelectors, _ = pe.selectorsForUpdate(previous)
				}

				pe.mu.Lock()
				delete(pe.activePolicies, policyKey)
				delete(pe.enforcedVersion, policyKey)
				delete(pe.compileCache, policyKey)
				delete(pe.selectorCache, policyKey)
				pe.mu.Unlock()
				pe.adjustSelectorRefs(oldSelectors, nil)

				if err := pe.reapplyAllPolicies(ctx); err != nil {
					logging.Warnf("Failed to re-apply policies after delete %s v%d: %v",
						sanitizeForLog(policyKey), update.Version, err)
					cluster.RecordPolicyEnforcementError(policyKey, "local-node")
					continue
				}

				cluster.RecordPolicyEnforced(policyKey, "local-node")
				pe.emitAlert(alert.Alert{
					Source:   "policy-enforcer",
					Severity: alert.SeverityInfo,
					Title:    fmt.Sprintf("policy %s deleted", sanitizeForLog(policyKey)),
					Message:  fmt.Sprintf("version %d from %s", update.Version, sanitizeForLog(update.Source)),
					DedupKey: fmt.Sprintf("%s:%d:delete:success", policyKey, update.Version),
					Details: map[string]any{
						"version": update.Version,
						"source":  update.Source,
						"dry_run": pe.dryRun,
					},
				})
				if pe.auditLogger != nil {
					details := map[string]any{
						"version": update.Version,
						"source":  update.Source,
						"dry_run": pe.dryRun,
					}
					_ = pe.auditLogger.Log(audit.EventPolicyDeleted, "system",
						policyKey, "delete", details)
				}
				logging.Infof("Successfully deleted policy %s v%d from %s",
					sanitizeForLog(policyKey), update.Version, sanitizeForLog(update.Source))
				continue
			}

			// Check if we've already enforced this version
			pe.mu.RLock()
			currentVersion := pe.enforcedVersion[policyKey]
			pe.mu.RUnlock()

			if update.Version <= currentVersion {
				logging.Debugf("Skipping policy %s v%d (already enforced v%d)",
					sanitizeForLog(policyKey), update.Version, currentVersion)
				continue
			}

			// Apply the policy
			startTime := time.Now()
			if err := pe.applyUpdate(ctx, update); err != nil {
				logging.Warnf("Failed to enforce policy %s v%d: %v",
					sanitizeForLog(policyKey), update.Version, err)
				cluster.RecordPolicyEnforcementError(policyKey, "local-node")
				pe.emitAlert(alert.Alert{
					Source:   "policy-enforcer",
					Severity: alert.SeverityError,
					Title:    fmt.Sprintf("policy %s enforcement failed", sanitizeForLog(policyKey)),
					Message:  err.Error(),
					DedupKey: fmt.Sprintf("%s:%d:enforce:error", policyKey, update.Version),
					Details: map[string]any{
						"version": update.Version,
						"source":  update.Source,
					},
				})

				// Log failure to audit log
				if pe.auditLogger != nil {
					details := map[string]any{
						"version": update.Version,
						"source":  update.Source,
						"dry_run": pe.dryRun,
					}
					_ = pe.auditLogger.LogFailure(audit.EventPolicyEnforced, "system",
						policyKey, "enforce", err.Error(), details)
				}
				continue
			}

			// Record metrics
			duration := time.Since(startTime).Seconds()
			cluster.RecordPolicyEnforcementDuration(policyKey, duration)
			cluster.RecordPolicyEnforced(policyKey, "local-node")
			pe.emitAlert(alert.Alert{
				Source:   "policy-enforcer",
				Severity: alert.SeverityInfo,
				Title:    fmt.Sprintf("policy %s enforced", sanitizeForLog(policyKey)),
				Message:  fmt.Sprintf("version %d from %s", update.Version, sanitizeForLog(update.Source)),
				DedupKey: fmt.Sprintf("%s:%d:enforce:success", policyKey, update.Version),
				Details: map[string]any{
					"version":     update.Version,
					"source":      update.Source,
					"duration_ms": duration * 1000,
					"dry_run":     pe.dryRun,
				},
			})

			// Log success to audit log
			if pe.auditLogger != nil {
				details := map[string]any{
					"version":     update.Version,
					"source":      update.Source,
					"duration_ms": duration * 1000,
					"dry_run":     pe.dryRun,
				}
				_ = pe.auditLogger.Log(audit.EventPolicyEnforced, "system",
					policyKey, "enforce", details)
			}

			logging.Infof("Successfully enforced policy %s v%d from %s",
				sanitizeForLog(policyKey), update.Version, sanitizeForLog(update.Source))
		}
	}
}

func (pe *PolicyEnforcer) reapplyAllPolicies(ctx context.Context) error {
	pe.mu.RLock()
	updates := make([]cluster.PolicyUpdate, 0, len(pe.activePolicies))
	for _, p := range pe.activePolicies {
		updates = append(updates, p)
	}
	pe.mu.RUnlock()
	if err := pe.enforceUpdates(ctx, updates); err != nil {
		return err
	}

	pe.mu.Lock()
	for k, u := range pe.activePolicies {
		pe.enforcedVersion[k] = u.Version
	}
	pe.mu.Unlock()
	return nil
}

func (pe *PolicyEnforcer) applyUpdate(ctx context.Context, update cluster.PolicyUpdate) error {
	key := update.PolicyKeyString()
	pe.mu.RLock()
	previous, hadPrevious := pe.activePolicies[key]
	pe.mu.RUnlock()

	newSelectors, err := pe.selectorsForUpdate(update)
	if err != nil {
		return err
	}
	var oldSelectors map[string]selectorWatch
	if hadPrevious {
		oldSelectors, err = pe.selectorsForUpdate(previous)
		if err != nil {
			return err
		}
	}

	pe.mu.RLock()
	updates := make([]cluster.PolicyUpdate, 0, len(pe.activePolicies)+1)
	for k, p := range pe.activePolicies {
		if k == key {
			continue
		}
		updates = append(updates, p)
	}
	pe.mu.RUnlock()
	updates = append(updates, update)

	if err = pe.enforceUpdates(ctx, updates); err != nil {
		return err
	}

	pe.mu.Lock()
	pe.enforcedVersion[key] = update.Version
	pe.activePolicies[key] = update
	pe.mu.Unlock()
	pe.adjustSelectorRefs(oldSelectors, newSelectors)
	return nil
}

func (pe *PolicyEnforcer) enforceUpdates(ctx context.Context, updates []cluster.PolicyUpdate) error {
	flat, scoped, requiresSubject, err := pe.compilePolicies(ctx, updates)
	if err != nil {
		return err
	}
	if requiresSubject && !IsLinux() {
		return errors.New("ingress named ports require Linux subject-scoped enforcement")
	}

	if IsLinux() {
		if pe.cgroupPath == "" {
			// A compatibility caller without an attachment scope cannot safely
			// request kernel enforcement. Preserve the old bookkeeping behavior
			// for migration tests without invoking the global/demo program.
			return nil
		}

		if pe.subjectResolver != nil {
			if requiresSubject {
				if !CanUseEBPF() {
					return errors.New("ingress named ports require eBPF enforcement, but eBPF is unavailable")
				}
				if !policiesSupportedByEBPF(flat, "") {
					return errors.New("ingress named ports require eBPF enforcement, but policies are not eBPF-compatible")
				}
			}
			return EnforceWithEBPFIfAvailableScoped(ScopedEnforcementOptions{Policies: scoped, DryRun: pe.dryRun, CgroupPath: pe.cgroupPath, Context: ctx})
		}
		if requiresSubject {
			return errors.New("ingress named ports require subject-scoped enforcement")
		}
		return EnforceWithEBPFIfAvailable(EnforcementOptions{Policies: flat, DryRun: pe.dryRun, CgroupPath: pe.cgroupPath, Context: ctx})
	}

	return pe.enforceMacOS(flat)
}

func (pe *PolicyEnforcer) compilePolicies(ctx context.Context, updates []cluster.PolicyUpdate) ([]policy.NetworkPolicy, []ScopedPolicy, bool, error) {
	flat := make([]policy.NetworkPolicy, 0)
	scopedOut := make([]ScopedPolicy, 0)
	requiresSubject := false

	resolver := policy.NewPolicyResolver(pe.discovery)
	_, discoveryScoped := pe.discovery.(policy.ScopedServiceDiscovery)

	for _, update := range updates {
		tenant := cluster.NormalizeTenant(update.Tenant)
		policyKey := update.PolicyKeyString()
		cacheable := !pe.resolveLabels || pe.discovery == nil
		var normalized []policy.NetworkPolicy
		if cacheable {
			if cached, ok := pe.getCompileCache(policyKey, update); ok {
				normalized = cached
			}
		}

		if len(normalized) == 0 {
			policies, err := policy.LoadFromBytes(update.YAML)
			if err != nil {
				return nil, nil, false, err
			}
			if len(policies) == 0 {
				continue
			}

			if pe.resolveLabels && pe.discovery != nil {
				if discoveryScoped {
					resolved, err := resolver.ResolvePodSelectorsToIPBlocksScoped(tenant, policies)
					if err != nil {
						return nil, nil, false, fmt.Errorf("resolving pod selectors (tenant %s): %w", tenant, err)
					}
					policies = resolved
				} else {
					resolved, err := resolver.ResolvePodSelectorsToIPBlocks(policies)
					if err != nil {
						return nil, nil, false, fmt.Errorf("resolving pod selectors: %w", err)
					}
					policies = resolved
				}
			}

			for _, p := range policies {
				if err := p.Validate(); err != nil {
					return nil, nil, false, err
				}
			}

			normalized, err = policy.NormalizePolicies(policies)
			if err != nil {
				return nil, nil, false, err
			}
			if cacheable {
				pe.setCompileCache(policyKey, update, normalized)
			}
		}

		for _, p := range normalized {
			if policyHasIngressNamedPorts(p) {
				requiresSubject = true
			}
		}

		if requiresSubject {
			resolver, ok := pe.subjectResolver.(SubjectPortResolver)
			if !ok || pe.subjectResolver == nil {
				return nil, nil, false, errors.New("ingress named ports require subject-scoped enforcement")
			}
			for _, p := range normalized {
				if !policyHasIngressNamedPorts(p) {
					flat = append(flat, p)
					var subjectIDs []uint64
					ids, err := pe.subjectResolver.ResolveCgroupIDs(ctx, tenant, p.Spec.PodSelector)
					if err != nil {
						return nil, nil, false, err
					}
					subjectIDs = ids
					scopedOut = append(scopedOut, ScopedPolicy{Tenant: tenant, Policy: p, SubjectCgroupIDs: subjectIDs})
					continue
				}

				subjects, err := resolver.ResolveSubjectPorts(ctx, tenant, p.Spec.PodSelector)
				if err != nil {
					return nil, nil, false, err
				}
				if len(subjects) == 0 {
					continue
				}
				for _, subject := range subjects {
					portMap, err := policy.BuildNamedPortMap(subject.Ports)
					if err != nil {
						logging.Warnf("named ports for subject %s in policy %s are ambiguous: %v", subject.PodName, p.Metadata.Name, err)
						continue
					}
					resolvedPolicy, missing := resolveIngressNamedPorts(p, portMap)
					if len(missing) > 0 {
						logging.Warnf("policy %s: named ports %v not found on subject %s", p.Metadata.Name, missing, subject.PodName)
					}
					if len(resolvedPolicy.Spec.Egress) == 0 && len(resolvedPolicy.Spec.Ingress) == 0 {
						continue
					}
					flat = append(flat, resolvedPolicy)
					scopedOut = append(scopedOut, ScopedPolicy{Tenant: tenant, Policy: resolvedPolicy, SubjectCgroupIDs: []uint64{subject.CgroupID}})
				}
			}
			continue
		}

		for _, p := range normalized {
			flat = append(flat, p)

			var subjectIDs []uint64
			if pe.subjectResolver != nil {
				ids, err := pe.subjectResolver.ResolveCgroupIDs(ctx, tenant, p.Spec.PodSelector)
				if err != nil {
					return nil, nil, false, err
				}
				subjectIDs = ids
			}
			scopedOut = append(scopedOut, ScopedPolicy{Tenant: tenant, Policy: p, SubjectCgroupIDs: subjectIDs})
		}
	}

	return flat, scopedOut, requiresSubject, nil
}

func (pe *PolicyEnforcer) getCompileCache(policyKey string, update cluster.PolicyUpdate) ([]policy.NetworkPolicy, bool) {
	pe.mu.RLock()
	entry, ok := pe.compileCache[policyKey]
	pe.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if entry.version != update.Version || entry.yamlHash != hashYAML(update.YAML) {
		return nil, false
	}
	return append([]policy.NetworkPolicy(nil), entry.normalized...), true
}

func (pe *PolicyEnforcer) setCompileCache(policyKey string, update cluster.PolicyUpdate, normalized []policy.NetworkPolicy) {
	pe.mu.Lock()
	pe.compileCache[policyKey] = compileCacheEntry{
		version:    update.Version,
		yamlHash:   hashYAML(update.YAML),
		normalized: append([]policy.NetworkPolicy(nil), normalized...),
	}
	pe.mu.Unlock()
}

func hashYAML(yaml []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(yaml)
	return h.Sum64()
}

func copyLabels(labels map[string]string) map[string]string {
	copied := make(map[string]string, len(labels))
	maps.Copy(copied, labels)
	return copied
}

func (pe *PolicyEnforcer) selectorsForUpdate(update cluster.PolicyUpdate) (map[string]selectorWatch, error) {
	policyKey := update.PolicyKeyString()
	yamlHash := hashYAML(update.YAML)

	pe.mu.RLock()
	cached, ok := pe.selectorCache[policyKey]
	pe.mu.RUnlock()
	if ok && cached.version == update.Version && cached.yamlHash == yamlHash {
		out := make(map[string]selectorWatch, len(cached.selectors))
		for k, v := range cached.selectors {
			out[k] = selectorWatch{tenant: v.tenant, labels: copyLabels(v.labels)}
		}
		return out, nil
	}

	tenant := cluster.NormalizeTenant(update.Tenant)
	policies, err := policy.LoadFromBytes(update.YAML)
	if err != nil {
		return nil, err
	}
	selectors := make(map[string]selectorWatch)
	for _, p := range policies {
		if len(p.Spec.PodSelector.MatchLabels) > 0 && len(p.Spec.PodSelector.MatchExpressions) == 0 {
			key := fmt.Sprintf("%s|subject|%s", tenant, policy.SelectorKeySpec(p.Spec.PodSelector))
			selectors[key] = selectorWatch{tenant: tenant, labels: copyLabels(p.Spec.PodSelector.MatchLabels)}
		}
		for _, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 && len(egress.To.PodSelector.MatchExpressions) == 0 {
				key := fmt.Sprintf("%s|egress|%s", tenant, policy.SelectorKeySpec(egress.To.PodSelector))
				selectors[key] = selectorWatch{tenant: tenant, labels: copyLabels(egress.To.PodSelector.MatchLabels)}
			}
		}
		for _, ingress := range p.Spec.Ingress {
			if len(ingress.From.PodSelector.MatchLabels) > 0 && len(ingress.From.PodSelector.MatchExpressions) == 0 {
				key := fmt.Sprintf("%s|ingress|%s", tenant, policy.SelectorKeySpec(ingress.From.PodSelector))
				selectors[key] = selectorWatch{tenant: tenant, labels: copyLabels(ingress.From.PodSelector.MatchLabels)}
			}
		}
	}

	pe.mu.Lock()
	pe.selectorCache[policyKey] = selectorCacheEntry{
		version:   update.Version,
		yamlHash:  yamlHash,
		selectors: selectors,
	}
	pe.mu.Unlock()

	out := make(map[string]selectorWatch, len(selectors))
	for k, v := range selectors {
		out[k] = selectorWatch{tenant: v.tenant, labels: copyLabels(v.labels)}
	}
	return out, nil
}

func sortedSelectorKeys(selectors map[string]selectorWatch) []string {
	keys := make([]string, 0, len(selectors))
	for key := range selectors {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func (pe *PolicyEnforcer) adjustSelectorRefs(remove map[string]selectorWatch, add map[string]selectorWatch) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	for key := range remove {
		ref, ok := pe.selectorRefs[key]
		if !ok {
			continue
		}
		ref.refs--
		if ref.refs <= 0 {
			delete(pe.selectorRefs, key)
			continue
		}
		pe.selectorRefs[key] = ref
	}
	for key, sel := range add {
		ref, ok := pe.selectorRefs[key]
		if !ok {
			ref = selectorRef{tenant: sel.tenant, labels: copyLabels(sel.labels)}
		}
		ref.refs++
		pe.selectorRefs[key] = ref
	}
}

func (pe *PolicyEnforcer) snapshotSelectorRefs() map[string]selectorWatch {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	selectors := make(map[string]selectorWatch, len(pe.selectorRefs))
	for key, ref := range pe.selectorRefs {
		if ref.refs <= 0 {
			continue
		}
		selectors[key] = selectorWatch{
			tenant: ref.tenant,
			labels: copyLabels(ref.labels),
		}
	}
	return selectors
}

func (pe *PolicyEnforcer) discoveryWatcher(ctx context.Context) {
	activeWatches := make(map[string]context.CancelFunc)
	watchEndedCh := make(chan string, 128)
	defer func() {
		for _, cancel := range activeWatches {
			cancel()
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	scopedDisc, isScoped := pe.discovery.(policy.ScopedServiceDiscovery)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pe.stopCh:
			return
		case endedKey := <-watchEndedCh:
			if cancel, ok := activeWatches[endedKey]; ok {
				cancel()
				delete(activeWatches, endedKey)
			}
		case <-ticker.C:
			selectors := pe.snapshotSelectorRefs()
			selectorKeys := sortedSelectorKeys(selectors)
			for _, key := range selectorKeys {
				sel := selectors[key]
				if _, ok := activeWatches[key]; ok {
					continue
				}
				watchCtx, cancel := context.WithCancel(ctx)
				var ch <-chan []string
				var err error
				if isScoped {
					ch, err = scopedDisc.WatchScoped(watchCtx, sel.tenant, sel.labels)
				} else {
					ch, err = pe.discovery.Watch(watchCtx, sel.labels)
				}
				if err != nil {
					cancel()
					logging.Warnf("failed to start watch for %s %v: %v", sel.tenant, sel.labels, err)
					continue
				}
				activeWatches[key] = cancel
				keyCopy := key
				go func(ch <-chan []string) {
					for range ch {
						select {
						case pe.retriggerCh <- struct{}{}:
						default:
						}
					}
					select {
					case watchEndedCh <- keyCopy:
					default:
					}
				}(ch)
			}

			for key, cancel := range activeWatches {
				if _, ok := selectors[key]; !ok {
					cancel()
					delete(activeWatches, key)
				}
			}
		}
	}
}

// enforceMacOS applies policies using pf on macOS.
func (pe *PolicyEnforcer) enforceMacOS(policies []policy.NetworkPolicy) error {
	opts := EnforcementOptions{
		Policies: policies,
		DryRun:   pe.dryRun,
	}
	return EnforceWithPF(opts)
}

// GetEnforcedVersions returns a map of policy identifiers to enforced versions.
// Default-tenant policies use the unqualified name; non-default tenants use tenant/name.
func (pe *PolicyEnforcer) GetEnforcedVersions() map[string]int64 {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	versions := make(map[string]int64, len(pe.enforcedVersion))
	for k, v := range pe.enforcedVersion {
		key, err := cluster.ParsePolicyKey(k)
		if err != nil {
			versions[k] = v
			continue
		}
		key = key.Normalized()
		if key.Tenant == cluster.DefaultTenant {
			versions[key.Name] = v
			continue
		}
		versions[key.String()] = v
	}
	return versions
}

// GetEnforcedVersion returns the enforced version for a specific policy.
func (pe *PolicyEnforcer) GetEnforcedVersion(policyName string) int64 {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	key, err := cluster.ParsePolicyKey(policyName)
	if err != nil {
		key = cluster.PolicyKey{Tenant: cluster.DefaultTenant, Name: policyName}
	}
	return pe.enforcedVersion[key.String()]
}

func (pe *PolicyEnforcer) emitAlert(a alert.Alert) {
	if pe.alerts == nil {
		return
	}
	_ = pe.alerts.Emit(a)
}
