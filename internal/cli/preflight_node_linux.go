package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/saadshabir/ZTAP/internal/enforcer"
	"golang.org/x/sys/unix"
)

func checkNodePreflight(r *preflightReport, cgroupRoot, bpffsRoot string) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		r.check("node architecture", fmt.Errorf("unsupported architecture %s", runtime.GOARCH))
		return
	}
	mountErr := enforcer.CheckKernelMounts(cgroupRoot, bpffsRoot)
	r.check("cgroup v2 and bpffs mounts", mountErr)
	parents, layoutErr := kubernetesCgroupParents(cgroupRoot)
	var target string
	if uid := os.Getenv("POD_UID"); uid != "" && layoutErr == nil {
		var owner enforcer.WorkloadIdentity
		owner, layoutErr = findBootstrapProcessIdentity(cgroupRoot, uid)
		if layoutErr == nil {
			target = filepath.Join(cgroupRoot, owner.Path)
		}
	}
	r.check("Kubernetes systemd cgroup layout", layoutErr)
	cookie, err := socketNetnsCookie()
	if err == nil && cookie == 0 {
		err = errors.New("kernel returned an empty network namespace cookie")
	}
	r.check("socket network namespace cookie", err)
	capsErr := preflightCapabilities()
	r.check("effective Linux capabilities", capsErr)
	if mountErr == nil && layoutErr == nil && capsErr == nil {
		r.check("Kubernetes cgroup parent BPF attachments", enforcer.CheckGuardParents(cgroupRoot, parents))
		r.check("eBPF verifier and pinnable cgroup links", enforcer.ProbeKernel(cgroupRoot, bpffsRoot, target))
	} else {
		_, _ = fmt.Fprintln(r.out, "SKIP eBPF checks until mounts, cgroup layout, and capabilities pass")
	}
}

func preflightCapabilities() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	var missing []string
	for _, cap := range []struct {
		number uint
		name   string
	}{
		{unix.CAP_BPF, "CAP_BPF"}, {unix.CAP_NET_ADMIN, "CAP_NET_ADMIN"},
		{unix.CAP_PERFMON, "CAP_PERFMON"}, {unix.CAP_SYS_RESOURCE, "CAP_SYS_RESOURCE"},
	} {
		if caps[cap.number/32].Effective&(1<<(cap.number%32)) == 0 {
			missing = append(missing, cap.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s; use a node administrator or the agent container security context", strings.Join(missing, ", "))
	}
	return nil
}
