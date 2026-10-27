//go:build linux

package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saadshabir/ZTAP/internal/enforcer"
)

func TestWorkloadSnapshotRejectsConflictingIdentitiesBeforePublication(t *testing.T) {
	r := newK8sSubjectResolver(t.TempDir())
	path := filepath.Join(r.cgroupRoot, "scope")
	a, b := cgroupCacheKey{podUID: "pod-a", containerID: "a"}, cgroupCacheKey{podUID: "pod-b", containerID: "b"}
	cached := cachedPodCgroup{value: resolvedPodCgroup{ID: 42, Path: path}, identity: cgroupFilesystemIdentity{device: 1, inode: 42}}
	r.cacheCgroup(a, cached)
	if err := r.publishWorkloadSnapshot(map[uint64]string{42: path}, map[cgroupCacheKey]struct{}{a: {}}); err != nil {
		t.Fatal(err)
	}
	previous, err := r.ResolveWorkloadIdentity(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	r.cacheCgroup(b, cached)
	err = r.publishWorkloadSnapshot(map[uint64]string{42: path}, map[cgroupCacheKey]struct{}{a: {}, b: {}})
	if err == nil || !strings.Contains(err.Error(), "conflicting workload identities") {
		t.Fatalf("conflict error = %v", err)
	}
	current, err := r.ResolveWorkloadIdentity(context.Background(), 42)
	if err != nil || current != previous {
		t.Fatalf("failed candidate changed published ownership: %+v %v", current, err)
	}
	if err := r.publishWorkloadSnapshot(map[uint64]string{42: path}, map[cgroupCacheKey]struct{}{b: {}}); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateWorkloadIdentity(context.Background(), previous); err == nil {
		t.Fatal("replacement authorized old ownership")
	}
	if err := r.publishWorkloadSnapshot(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveWorkloadIdentity(context.Background(), 42); err == nil {
		t.Fatal("removed identity remained indexed")
	}
}

func BenchmarkWorkloadIdentityLookup(b *testing.B) {
	r := newK8sSubjectResolver("/sys/fs/cgroup")
	r.workloadIdentities = make(map[uint64]enforcer.WorkloadIdentity, 250)
	for i := uint64(1); i <= 250; i++ {
		r.workloadIdentities[i] = enforcer.WorkloadIdentity{CgroupID: i, PodUID: "pod", ContainerID: "container", Path: "scope"}
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.ResolveWorkloadIdentity(ctx, uint64(i%250+1)); err != nil {
			b.Fatal(err)
		}
	}
}
