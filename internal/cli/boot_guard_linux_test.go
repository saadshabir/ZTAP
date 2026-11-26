//go:build linux

package cli

import (
	"encoding/json"
	"testing"
)

func TestValidateBootGuardKubeletExecStart(t *testing.T) {
	const kubelet = "/usr/bin/kubelet"
	for _, tc := range []struct {
		name string
		path string
		args []string
		want bool
	}{
		{"root slice", kubelet, []string{kubelet, "$KUBELET_EXTRA_ARGS", "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/"}, true},
		{"nested slice", kubelet, []string{kubelet, "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/kubelet"}, true},
		{"unsupported slice", kubelet, []string{kubelet, "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/other"}, false},
		{"missing explicit flags", kubelet, []string{kubelet, "--config=/var/lib/kubelet/config.yaml"}, false},
		{"overridable flags", kubelet, []string{kubelet, "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/", "$KUBELET_EXTRA_ARGS"}, false},
		{"positional arguments", kubelet, []string{kubelet, "--", "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/"}, false},
		{"wrapper", "/bin/sh", []string{kubelet, "--cgroup-driver=systemd", "--cgroups-per-qos=true", "--cgroup-root=/"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := json.Marshal(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			err = validateBootGuardKubeletExecStart([][]json.RawMessage{{path, args}})
			if (err == nil) != tc.want {
				t.Fatalf("validation = %v, want success = %v", err, tc.want)
			}
		})
	}
}
