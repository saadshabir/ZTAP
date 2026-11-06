package enforcer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// CheckKernelMounts verifies the same filesystem types required by the engine.
func CheckKernelMounts(cgroupRoot, bpffsRoot string) error {
	return errors.Join(
		requireFilesystemType(cgroupRoot, cgroup2SuperMagic, "cgroup v2"),
		requireFilesystemType(bpffsRoot, bpfSuperMagic, "bpffs"),
	)
}

// CheckGuardParents checks whether a fresh install can claim the guard hooks.
// It queries direct attachments without loading or attaching anything there.
func CheckGuardParents(cgroupRoot string, parents []string) error {
	var result error
	for _, parent := range parents {
		if err := checkGuardParent(filepath.Join(cgroupRoot, parent)); err != nil {
			result = errors.Join(result, fmt.Errorf("%s: %w", parent, err))
		}
	}
	return result
}

func checkGuardParent(path string) (resultErr error) {
	cgroup, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cgroup.Close()) }()
	for _, attach := range guardAttachTypes {
		programs, err := link.QueryPrograms(link.QueryOptions{Target: int(cgroup.Fd()), Attach: attach})
		if err != nil {
			return fmt.Errorf("query %s programs: %w", attach, err)
		}
		if len(programs.Programs) != 0 {
			return fmt.Errorf("%s already has a directly attached BPF program (ID %d); a fresh install requires an unused guard hook", attach, programs.Programs[0].ID)
		}
	}
	return nil
}

// ProbeKernel loads the shipped collection without pinning or attaching it.
// Link operations use allow-only programs in an isolated cgroup. A supplied
// target is the verified cgroup of the preflight Pod itself.
func ProbeKernel(cgroupRoot, bpffsRoot, target string) (resultErr error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove eBPF memlock limit: %w", err)
	}
	spec, err := loadEngine()
	if err != nil {
		return err
	}
	durableMapSpecs(spec)
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load agent eBPF maps and programs (kernel features, permissions or seccomp): %w", err)
	}
	defer collection.Close()

	var child *os.File
	if target == "" {
		target, err = os.MkdirTemp(cgroupRoot, "ztap-preflight-")
		if err != nil {
			return fmt.Errorf("create temporary probe cgroup: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, os.Remove(target)) }()
		childPath := filepath.Join(target, "child")
		if err := os.Mkdir(childPath, 0o700); err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, os.Remove(childPath)) }()
		child, err = os.Open(childPath)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, child.Close()) }()
	}
	cgroup, err := os.Open(target)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cgroup.Close()) }()
	pinDir, err := os.MkdirTemp(bpffsRoot, "ztap-preflight-")
	if err != nil {
		return fmt.Errorf("create temporary bpffs directory: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, os.Remove(pinDir)) }()

	for i, attach := range guardAttachTypes {
		programType := spec.Programs[guardProgramNames[i]].Type
		if err := probeCgroupLink(cgroup, child, filepath.Join(pinDir, "link"), programType, attach); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%s link: %w", attach, err))
		}
	}
	return resultErr
}

func probeCgroupLink(cgroup, child *os.File, pin string, programType ebpf.ProgramType, attach ebpf.AttachType) (resultErr error) {
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: programType, AttachType: attach, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, program.Close()) }()
	if err := rejectIncompatibleCgroupProgram(cgroup, attach, program); err != nil {
		return err
	}
	handle, err := link.AttachRawLink(link.RawLinkOptions{Target: int(cgroup.Fd()), Program: program, Attach: attach})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	if err := handle.Pin(pin); err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Unpin()) }()
	reopened, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		return fmt.Errorf("reopen: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, reopened.Close()) }()
	if err := reopened.Update(program); err != nil {
		return fmt.Errorf("replace program: %w", err)
	}
	if child != nil {
		info, err := reopened.Info()
		if err != nil {
			return err
		}
		effective, err := link.QueryPrograms(link.QueryOptions{
			Target: int(child.Fd()), Attach: attach, QueryFlags: unix.BPF_F_QUERY_EFFECTIVE,
		})
		if err != nil {
			return fmt.Errorf("query inherited programs: %w", err)
		}
		if !slices.ContainsFunc(effective.Programs, func(p link.AttachedProgram) bool { return p.ID == info.Program }) {
			return errors.New("probe program was not inherited by the child cgroup")
		}
	}
	return nil
}
