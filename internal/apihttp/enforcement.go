package apihttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"ztap/internal/alert"
	"ztap/internal/audit"
	"ztap/internal/cluster"
	"ztap/internal/enforcer"
	"ztap/internal/policy"
)

type enforcementStartRequest struct {
	PolicyYAML string `json:"policy_yaml"`
	PolicyName string `json:"policy_name"`
	CgroupPath string `json:"cgroup"`
	BPFObject  string `json:"bpf_object"`
	DebugEBPF  bool   `json:"debug_ebpf"`
}

type enforcementStartResponse struct {
	Enforced bool   `json:"enforced"`
	Platform string `json:"platform"`
}

func (s *Server) handleEnforcementStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req enforcementStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if strings.TrimSpace(req.PolicyYAML) == "" {
		writeError(w, http.StatusBadRequest, errors.New("policy_yaml is required"))
		return
	}
	policyName := strings.TrimSpace(req.PolicyName)
	if policyName == "" {
		policyName = "api"
	}
	policyTenant := cluster.DefaultTenant
	policyShortName := policyName
	policyKey := cluster.PolicyKey{Tenant: policyTenant, Name: policyShortName}.String()
	if parsed, err := cluster.ParsePolicyKey(policyName); err == nil {
		policyTenant = parsed.Tenant
		policyShortName = parsed.Name
		policyKey = parsed.String()
	}

	basePolicies, err := policy.LoadFromBytes([]byte(req.PolicyYAML))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to parse policy yaml: %w", err))
		return
	}
	if len(basePolicies) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no policies found"))
		return
	}

	needsResolution := policiesNeedTargetResolution(basePolicies)

	s.enforcementMu.Lock()
	defer s.enforcementMu.Unlock()

	policies := basePolicies
	if needsResolution {
		if s.discovery == nil {
			writeError(w, http.StatusBadRequest, errors.New("policy contains podSelector targets but no discovery backend is configured"))
			return
		}
		if err := s.ensureDiscoveryStarted(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to start discovery backend: %w", err))
			return
		}
		enforcer.WarnNoMatchPolicyTargets(s.discovery, enforcer.SelectorRefreshOptions{Scope: policyTenant}, basePolicies)
		resolver := policy.NewPolicyResolver(s.discovery)
		resolved, err := resolver.ResolvePodSelectorsToIPBlocksScoped(policyTenant, basePolicies)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("failed to resolve pod selectors: %w", err))
			return
		}
		policies = resolved
	}
	normalized, err := policy.NormalizePolicies(policies)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("failed to normalize ipBlocks: %w", err))
		return
	}
	policies = normalized

	named := make([]policy.NamedPolicy, 0, len(basePolicies))
	for _, p := range basePolicies {
		if err := p.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		named = append(named, policy.NamedPolicy{Tenant: policyTenant, PolicyName: policyShortName, Policy: p})
	}
	for i, np := range named {
		if err := policy.CheckConflicts(named[:i], np); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("policy conflict: %w", err))
			return
		}
	}
	if enforcer.IsLinux() {
		writeError(w, http.StatusNotImplemented, enforcer.ErrLegacyLinuxEnforcementRetired)
		return
	}

	if enforcer.IsWindows() {
		platform := "windows"
		ctx := s.runCtx
		if ctx == nil {
			ctx = context.Background()
		}
		opts := enforcer.EnforcementOptions{
			Policies: policies,
			Context:  ctx,
		}
		if err := enforcer.EnforceWithWFP(opts); err != nil {
			s.emitAlert(alert.Alert{
				Source:   "api-http",
				Severity: alert.SeverityError,
				Title:    "policy enforcement failed",
				Message:  err.Error(),
				DedupKey: fmt.Sprintf("%s:%s:error", policyKey, platform),
				Details:  map[string]any{"platform": platform, "count": len(policies)},
			})
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enforce via WFP: %w", err))
			return
		}

		s.stopEnforcementRefreshLocked()

		_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyKey, "enforce", map[string]any{"platform": platform, "count": len(policies)})
		s.emitAlert(alert.Alert{
			Source:   "api-http",
			Severity: alert.SeverityInfo,
			Title:    "policy enforced",
			Message:  fmt.Sprintf("%s enforced on %s", policyKey, platform),
			DedupKey: fmt.Sprintf("%s:%s:success", policyKey, platform),
			Details:  map[string]any{"platform": platform, "count": len(policies)},
		})
		writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: platform})

		if needsResolution && s.resolveLabelsInterval > 0 {
			refreshCtx, refreshCancel := context.WithCancel(ctx)
			s.refreshCancelFn = refreshCancel
			go enforcer.RunSelectorRefresh(refreshCtx, s.discovery, basePolicies, enforcer.SelectorRefreshOptions{Scope: policyTenant, PollInterval: s.resolveLabelsInterval}, func(next []policy.NetworkPolicy) error {
				select {
				case <-refreshCtx.Done():
					return nil
				default:
				}
				s.enforcementMu.Lock()
				defer s.enforcementMu.Unlock()
				return enforcer.EnforceWithWFP(enforcer.EnforcementOptions{Policies: next, Context: refreshCtx})
			})
		}
		return
	}

	platform := runtime.GOOS
	ctx := s.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := enforcer.EnforceWithPF(enforcer.EnforcementOptions{
		Policies: policies,
		Context:  ctx,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to enforce via pf: %w", err))
		return
	}
	_ = s.audit.Log(audit.EventPolicyEnforced, "system", policyKey, "enforce", map[string]any{"platform": platform, "count": len(policies)})
	s.emitAlert(alert.Alert{
		Source:   "api-http",
		Severity: alert.SeverityInfo,
		Title:    "policy enforced",
		Message:  fmt.Sprintf("%s enforced on %s", policyKey, platform),
		DedupKey: fmt.Sprintf("%s:%s:success", policyKey, platform),
		Details:  map[string]any{"platform": platform, "count": len(policies)},
	})
	writeJSON(w, http.StatusOK, enforcementStartResponse{Enforced: true, Platform: platform})
}

func (s *Server) handleEnforcementStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	s.enforcementMu.Lock()
	defer s.enforcementMu.Unlock()
	s.stopEnforcementRefreshLocked()

	if enforcer.IsLinux() {
		writeError(w, http.StatusNotImplemented, enforcer.ErrLegacyLinuxEnforcementRetired)
		return
	}
	if enforcer.IsWindows() {
		if err := enforcer.StopWFPEnforcement(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("failed to stop WFP enforcement: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"stopped": true})
		return
	}
	writeError(w, http.StatusNotImplemented, errors.New("stop is only supported for eBPF on linux or WFP on windows"))
}

func policiesNeedTargetResolution(policies []policy.NetworkPolicy) bool {
	return policy.NeedsTargetResolution(policies)
}
