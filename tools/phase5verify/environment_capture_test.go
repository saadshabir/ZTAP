package main

import (
	"os"
	"path"
	"strings"
	"testing"
)

func TestFindCgroup2MountParsesMountInfoAndSelectsCgroup2(t *testing.T) {
	mountInfo := strings.Join([]string{
		"30 20 0:29 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw",
		"31 20 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw",
	}, "\n")
	mount, err := findCgroup2Mount([]byte(mountInfo))
	if err != nil {
		t.Fatalf("find cgroup2 mount: %v", err)
	}
	if mount.Root != "/" || mount.MountPath != "/sys/fs/cgroup" {
		t.Fatalf("unexpected cgroup2 mount: %#v", mount)
	}
}

func TestFindCgroup2MountUnescapesMountPaths(t *testing.T) {
	mountInfo := []byte("30 20 0:29 / /sys/fs/cgroup\\040nested rw - cgroup2 cgroup rw\n")
	_, err := findCgroup2Mount(mountInfo)
	if err == nil {
		t.Fatal("finder accepted a cgroup2 mount outside /sys/fs/cgroup")
	}
	if !strings.Contains(err.Error(), "/sys/fs/cgroup nested") {
		t.Fatalf("mount error did not retain the actual decoded path: %v", err)
	}
}

func TestCgroupPathMappingSupportsMountRootAndNamespacePaths(t *testing.T) {
	tests := []struct {
		name       string
		membership string
		root       string
		want       string
	}{
		{name: "host path under delegated root", membership: "/actions/job/runner", root: "/actions", want: "/sys/fs/cgroup/job/runner"},
		{name: "namespace relative path", membership: "/job/runner", root: "/actions", want: "/sys/fs/cgroup/job/runner"},
		{name: "namespace root", membership: "/", root: "/actions", want: "/sys/fs/cgroup"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := mapCgroupPathToMount(test.membership, test.root, "/sys/fs/cgroup")
			if err != nil {
				t.Fatalf("map cgroup path: %v", err)
			}
			if got != test.want {
				t.Fatalf("mapped path = %q, want %q", got, test.want)
			}
		})
	}
	if _, err := mapCgroupPathToMount("/../outside", "/", "/sys/fs/cgroup"); err == nil {
		t.Fatal("cgroup mapper accepted a traversal path")
	}
}

func TestObserveCPUQuotaHierarchyFindsNestedLimitWhenMountRootHasNone(t *testing.T) {
	mountPoint := path.Join(t.TempDir(), "sys", "fs", "cgroup")
	processPath := path.Join(mountPoint, "runner", "job")
	for _, directory := range []string{mountPoint, path.Dir(processPath), processPath} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create cgroup fixture %s: %v", directory, err)
		}
	}
	if err := os.WriteFile(path.Join(processPath, "cpu.max"), []byte("max 100000\n"), 0o600); err != nil {
		t.Fatalf("write process cpu.max: %v", err)
	}
	if err := os.WriteFile(path.Join(path.Dir(processPath), "cpu.max"), []byte("250000 100000\n"), 0o600); err != nil {
		t.Fatalf("write ancestor cpu.max: %v", err)
	}
	observations, err := observeCPUQuotaHierarchy(mountPoint, processPath)
	if err != nil {
		t.Fatalf("observe cgroup quota hierarchy: %v", err)
	}
	if observations[len(observations)-1].Status != "missing" {
		t.Fatalf("mount root cpu.max status = %q, want missing", observations[len(observations)-1].Status)
	}
	selected, ok := limitingCPUQuota(observations)
	if !ok {
		t.Fatal("quota hierarchy produced no readable quota evidence")
	}
	if selected.Path != path.Dir(processPath) || selected.Value != "250000 100000" {
		t.Fatalf("selected quota = %#v, want the readable nested ancestor", selected)
	}
}

func TestObserveCPUQuotaHierarchyRejectsMissingProcessCgroup(t *testing.T) {
	mountPoint := path.Join(t.TempDir(), "sys", "fs", "cgroup")
	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		t.Fatalf("create cgroup mount fixture: %v", err)
	}
	if _, err := observeCPUQuotaHierarchy(mountPoint, path.Join(mountPoint, "missing")); err == nil {
		t.Fatal("quota observer accepted a nonexistent process cgroup")
	}
}
