//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

func TestNewK8sSubjectResolver_LinuxDefaults(t *testing.T) {
	resolver := newK8sSubjectResolver(fake.NewClientset(), "")
	if resolver.cgroupRoot != "/sys/fs/cgroup" {
		t.Fatalf("expected default cgroup root, got %s", resolver.cgroupRoot)
	}

	resolver = newK8sSubjectResolver(fake.NewClientset(), "/custom/cgroup")
	if resolver.cgroupRoot != "/custom/cgroup" {
		t.Fatalf("expected custom cgroup root, got %s", resolver.cgroupRoot)
	}
}

func TestCgroupFilesystemIdentityRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cgroup")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create non-directory cgroup path: %v", err)
	}
	if _, err := cgroupFilesystemIdentityForPath(path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("cgroupFilesystemIdentityForPath accepted non-directory path: %v", err)
	}
}
