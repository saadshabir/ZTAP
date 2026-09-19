//go:build linux

package cli

import (
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
