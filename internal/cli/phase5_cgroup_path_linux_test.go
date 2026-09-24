//go:build linux && integration
// +build linux,integration

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPhase5CgroupDirectoryCreationRejectsSymlinkedParent(t *testing.T) {
	target := t.TempDir()
	linkedParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(target, linkedParent); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := createPhase5CgroupDirNoFollow(filepath.Join(linkedParent, "child")); err == nil {
		t.Fatal("cgroup directory creation followed a symlinked parent")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received cgroup entries: %v", entries)
	}
}

func TestPhase5CgroupDirectoryLifecycleRejectsSymlinkedFinalPath(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create cgroup target: %v", err)
	}
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := phase5CgroupDirectoryFD(link); err == nil {
		t.Fatal("cgroup directory inspection followed a symlinked final path")
	}
	if err := createPhase5CgroupDirNoFollow(link); err == nil {
		t.Fatal("cgroup directory creation accepted a symlinked final path")
	}
	if err := removePhase5CgroupDir(link); err == nil {
		t.Fatal("cgroup directory cleanup accepted a symlinked final path")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target was altered: %v", err)
	}
}

func TestPhase5CgroupDirectoryLifecycleCreatesAndRemovesDirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "created")
	if err := createPhase5CgroupDirNoFollow(path); err != nil {
		t.Fatalf("create cgroup directory: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat created cgroup directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("created cgroup path mode = %s, want directory", info.Mode())
	}
	if err := removePhase5CgroupDir(path); err != nil {
		t.Fatalf("remove cgroup directory: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("cgroup directory after removal error = %v, want not exist", err)
	}
}

func TestPhase5CgroupProcsRejectsSymlinkedControlFile(t *testing.T) {
	cgroup := t.TempDir()
	target := filepath.Join(t.TempDir(), "redirected-procs")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("create redirected cgroup.procs target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(cgroup, "cgroup.procs")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := openPhase5CgroupProcs(cgroup); err == nil {
		t.Fatal("cgroup.procs opener followed a symlink")
	}
}

func TestPhase5CgroupProcsOpensRelativeToValidatedDirectory(t *testing.T) {
	cgroup := t.TempDir()
	path := filepath.Join(cgroup, "cgroup.procs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create cgroup.procs fixture: %v", err)
	}
	file, err := openPhase5CgroupProcs(cgroup)
	if err != nil {
		t.Fatalf("open cgroup.procs fixture: %v", err)
	}
	if _, err := file.WriteString("123\n"); err != nil {
		_ = file.Close()
		t.Fatalf("write cgroup.procs fixture: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close cgroup.procs fixture: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cgroup.procs fixture: %v", err)
	}
	if string(data) != "123\n" {
		t.Fatalf("cgroup.procs fixture = %q, want %q", data, "123\n")
	}
}
