package enforcer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"ztap/internal/logging"
	"ztap/internal/policy"
)

// ErrLegacyLinuxEnforcementRetired identifies the file-based/global Linux
// enforcement surface that predates the instance-owned Kubernetes agent.
// Keeping this as a shared sentinel lets command and API callers expose one
// actionable migration message while the compatibility implementation stays
// parked for dedicated migration tests.
var ErrLegacyLinuxEnforcementRetired = errors.New("direct Linux enforcement is retired; run ztap agent --node-name <node> on Kubernetes")

// sanitizeForLogPlain removes characters that could break log formatting.
// In particular, it strips newline and carriage return characters so that
// user-controlled values cannot inject additional log lines.
func sanitizeForLogPlain(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// EnforcementOptions holds parameters for enforcement operations.
type EnforcementOptions struct {
	Policies   []policy.NetworkPolicy
	DryRun     bool
	CgroupPath string // Used for Linux eBPF
	// SelfIPs are IPv4 workload addresses explicitly associated with CgroupPath.
	// They are allowed only when both packet endpoints equal the mapped address.
	SelfIPs []string
	// BPFObjectPath optionally overrides the embedded eBPF object on Linux.
	BPFObjectPath string
	// DebugEBPF enables extra debug logging for eBPF loading/attachment.
	DebugEBPF bool
	// DefaultAction is the action for traffic not matching any policy rule:
	// "block" (default) or "allow". Currently honored by the pf backend;
	// the eBPF and WFP backends are default-deny by design.
	DefaultAction string
	Context       context.Context
}

// ScopedPolicy is a network policy paired with subject cgroups.
//
// SubjectCgroupIDs are Linux cgroup IDs (inode numbers on cgroup v2) for the
// workloads selected by the policy's spec.podSelector in the given tenant.
type ScopedPolicy struct {
	Tenant           string
	Policy           policy.NetworkPolicy
	SubjectCgroupIDs []uint64
	// QuarantinedDirections is a Direction*Mask bitset. Quarantine takes
	// precedence over ordinary rules but not the explicit self bypass.
	QuarantinedDirections uint8
}

// ScopedEnforcementOptions is the tenant-aware enforcement request.
type ScopedEnforcementOptions struct {
	Policies      []ScopedPolicy
	DryRun        bool
	CgroupPath    string // Used for Linux eBPF
	BPFObjectPath string
	DebugEBPF     bool
	Context       context.Context
}

// IsLinux returns true if running on Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsWindows returns true if running on Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// EnforceWithEBPF (Linux) - placeholder for real eBPF logic
func EnforceWithEBPF(opts EnforcementOptions) {
	fmt.Printf("Applying %d eBPF-based policies on Linux\n", len(opts.Policies))
	if opts.DryRun {
		fmt.Println("[DRY-RUN] Mode: Skipping kernel modifications")
	}
	// In production: load eBPF programs, attach to cgroup/socket hooks
	// For demonstration: simulate with logs
	for _, p := range opts.Policies {
		fmt.Printf("  Policy '%s': %s\n", p.Metadata.Name, p.Spec.PodSelector.MatchLabels)
		if len(p.Spec.Egress) > 0 {
			fmt.Printf("    Egress rules: %d\n", len(p.Spec.Egress))
			for _, egress := range p.Spec.Egress {
				if egress.To.IPBlock.CIDR != "" {
					if opts.DryRun {
						fmt.Printf("[DRY-RUN] Would apply: -> %s (ports: %v)\n", egress.To.IPBlock.CIDR, egress.Ports)
					} else {
						fmt.Printf("      -> %s (ports: %v)\n", egress.To.IPBlock.CIDR, egress.Ports)
					}
				}
				if len(egress.To.PodSelector.MatchLabels) > 0 {
					if opts.DryRun {
						fmt.Printf("[DRY-RUN] Would apply: -> pods: %v (ports: %v)\n", egress.To.PodSelector.MatchLabels, egress.Ports)
					} else {
						fmt.Printf("      -> pods: %v (ports: %v)\n", egress.To.PodSelector.MatchLabels, egress.Ports)
					}
				}
			}
		}
		if len(p.Spec.Ingress) > 0 {
			fmt.Printf("    Ingress rules: %d\n", len(p.Spec.Ingress))
			for _, ingress := range p.Spec.Ingress {
				if ingress.From.IPBlock.CIDR != "" {
					if opts.DryRun {
						fmt.Printf("[DRY-RUN] Would apply: <- %s (ports: %v)\n", ingress.From.IPBlock.CIDR, ingress.Ports)
					} else {
						fmt.Printf("      <- %s (ports: %v)\n", ingress.From.IPBlock.CIDR, ingress.Ports)
					}
				}
				if len(ingress.From.PodSelector.MatchLabels) > 0 {
					if opts.DryRun {
						fmt.Printf("[DRY-RUN] Would apply: <- pods: %v (ports: %v)\n", ingress.From.PodSelector.MatchLabels, ingress.Ports)
					} else {
						fmt.Printf("      <- pods: %v (ports: %v)\n", ingress.From.PodSelector.MatchLabels, ingress.Ports)
					}
				}
			}
		}
	}
}

// EnforceWithPF (macOS) - uses pfctl to manage rules
func EnforceWithPF(opts EnforcementOptions) error {
	fmt.Printf("Applying %d pf-based policies on macOS\n", len(opts.Policies))

	if os.Getenv("ZTAP_SKIP_PF") == "1" {
		logging.Warn("Skipping pf enforcement due to ZTAP_SKIP_PF environment override", nil)
		return nil
	}

	if os.Geteuid() != 0 {
		logging.Warn("pf enforcement requires root privileges; skipping rule application", nil)
		return nil
	}

	if opts.DryRun {
		logging.Info("[DRY-RUN] Mode: Skipping pfctl execution", nil)
	}

	// Create anchor file content
	var anchorContent strings.Builder
	anchorContent.WriteString("# ZTAP Managed Rules\n")

	for _, p := range opts.Policies {
		_, _ = fmt.Fprintf(&anchorContent, "# Policy: %s\n", sanitizeForLogPlain(p.Metadata.Name))

		// Process egress rules (outbound traffic)
		for _, egress := range p.Spec.Egress {
			if len(egress.To.PodSelector.MatchLabels) > 0 {
				// In real world: resolve labels to IPs (via DNS or inventory)
				anchorContent.WriteString("# Note: Label-based egress rules require inventory resolution\n")
				anchorContent.WriteString("block out quick from any to 192.168.0.0/16\n")
			}
			if egress.To.IPBlock.CIDR != "" {
				for _, port := range egress.Ports {
					if port.PortName != "" {
						return errors.New("named ports are not supported by pf enforcement")
					}
					portExpr := strconv.Itoa(port.Port)
					if port.EndPort != nil {
						portExpr = fmt.Sprintf("%d:%d", port.Port, *port.EndPort)
					}
					_, _ = fmt.Fprintf(&anchorContent, "pass out quick proto %s from any to %s port = %s\n",
						sanitizeForLogPlain(port.Protocol), sanitizeForLogPlain(egress.To.IPBlock.CIDR), portExpr)
				}
			}
		}

		// Process ingress rules (inbound traffic)
		for _, ingress := range p.Spec.Ingress {
			if len(ingress.From.PodSelector.MatchLabels) > 0 {
				// In real world: resolve labels to IPs (via DNS or inventory)
				anchorContent.WriteString("# Note: Label-based ingress rules require inventory resolution\n")
				anchorContent.WriteString("block in quick from 192.168.0.0/16 to any\n")
			}
			if ingress.From.IPBlock.CIDR != "" {
				for _, port := range ingress.Ports {
					if port.PortName != "" {
						return errors.New("named ports are not supported by pf enforcement")
					}
					portExpr := strconv.Itoa(port.Port)
					if port.EndPort != nil {
						portExpr = fmt.Sprintf("%d:%d", port.Port, *port.EndPort)
					}
					_, _ = fmt.Fprintf(&anchorContent, "pass in quick proto %s from %s to any port = %s\n",
						sanitizeForLogPlain(port.Protocol), sanitizeForLogPlain(ingress.From.IPBlock.CIDR), portExpr)
				}
			}
		}
	}

	// Default action for traffic not matched by any policy rule.
	switch strings.ToLower(strings.TrimSpace(opts.DefaultAction)) {
	case "allow":
		anchorContent.WriteString("\n# ZTAP default action: allow (catch-all)\n")
		anchorContent.WriteString("pass out quick from any to any\n")
		anchorContent.WriteString("pass in quick from any to any\n")
	case "", "block":
		// Default-deny: traffic not matching a policy rule remains subject to
		// the system pf ruleset (historical behavior).
	}

	if opts.DryRun {
		safeAnchorContent := sanitizeForLogPlain(anchorContent.String())
		fmt.Printf("[DRY-RUN] Would have written the following to /etc/pf.anchors/ztap:\n%s\n", safeAnchorContent)
		return nil
	}

	anchorFile := "/etc/pf.anchors/ztap"
	if err := os.MkdirAll(filepath.Dir(anchorFile), 0o750); err != nil {
		logging.Warnf("failed to create pf anchors directory: %v", err)
		return err
	}
	if err := os.WriteFile(anchorFile, []byte(anchorContent.String()), 0o600); err != nil {
		logging.Warnf("failed to write pf anchor file: %v", err)
		return err
	}

	// Ensure anchor is loaded in pf.conf
	pfConf := "/etc/pf.conf"
	pfContent := "anchor \"ztap\"\nload anchor \"ztap\" from \"/etc/pf.anchors/ztap\"\n"
	if existing, err := os.ReadFile(pfConf); err == nil {
		if !strings.Contains(string(existing), "anchor \"ztap\"") {
			if f, openErr := os.OpenFile(pfConf, os.O_APPEND|os.O_WRONLY, 0); openErr == nil {
				_, _ = f.WriteString("\n" + pfContent)
				_ = f.Close()
			}
		}
	}

	fmt.Println("Note: Full enforcement requires sudo. See docs for production setup.")
	return nil
}
