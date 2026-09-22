package kubernetes_test

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func TestNativeAgentManifestsUseTheCapabilityOnlyProfile(t *testing.T) {
	for _, path := range []string{"ztap-agent.yaml"} {
		t.Run(path, func(t *testing.T) {
			objects, err := loadManifestObjects(path)
			if err != nil {
				t.Fatalf("load manifest: %v", err)
			}
			daemonset := findObject(objects, "DaemonSet", "ztap-agent")
			if daemonset == nil {
				t.Fatal("manifest does not contain the ztap-agent DaemonSet")
			}
			spec, ok := nestedMap(daemonset, "spec", "template", "spec")
			if !ok {
				t.Fatal("agent pod spec is missing")
			}
			assertPrometheusAnnotations(t, daemonset)
			assertHostNamespaceIsolation(t, spec)
			assertRollingUpdateStrategy(t, daemonset)

			volumes, ok := spec["volumes"].([]interface{})
			if !ok {
				t.Fatal("agent pod volumes are missing")
			}
			assertHostPathVolume(t, volumes, "cgroup", "/sys/fs/cgroup", "Directory")
			assertHostPathVolume(t, volumes, "bpffs", "/sys/fs/bpf", "Directory")
			assertHostPathVolume(t, volumes, "run-dir", "/run/ztap", "DirectoryOrCreate")

			containers, ok := spec["containers"].([]interface{})
			if !ok || len(containers) != 1 {
				t.Fatalf("agent containers = %#v, want one container", spec["containers"])
			}
			container, ok := containers[0].(map[string]interface{})
			if !ok {
				t.Fatal("agent container has an invalid shape")
			}
			image, ok := container["image"].(string)
			if !ok || strings.TrimSpace(image) == "" {
				t.Fatalf("agent image = %#v, want an explicit release image", container["image"])
			}
			if strings.HasSuffix(image, ":latest") || (!strings.Contains(image, "@sha256:") && !strings.Contains(image, ":v0.1.0")) {
				t.Fatalf("agent image = %q, want v0.1.0 or an immutable digest", image)
			}
			assertHTTPPort(t, container)
			assertHTTPProbe(t, container, "livenessProbe", "/healthz")
			assertHTTPProbe(t, container, "readinessProbe", "/readyz")
			args := stringSlice(container["args"])
			for _, want := range []string{"agent", "--node-name=$(NODE_NAME)", "--cgroup-root=/host/sys/fs/cgroup", "--bpffs-root=/host/sys/fs/bpf", "--run-dir=/run/ztap"} {
				if !contains(args, want) {
					t.Errorf("agent args %q do not contain %q", args, want)
				}
			}
			for _, old := range []string{"--all-namespaces", "--namespaces", "--namespace", "--cgroup="} {
				for _, arg := range args {
					if strings.HasPrefix(arg, old) {
						t.Errorf("agent args retain legacy flag %q", arg)
					}
				}
			}

			env, ok := container["env"].([]interface{})
			if !ok || !hasNodeNameDownwardAPI(env) {
				t.Fatal("agent does not receive NODE_NAME from spec.nodeName")
			}
			security, ok := container["securityContext"].(map[string]interface{})
			if !ok {
				t.Fatal("agent securityContext is missing")
			}
			if security["privileged"] != false || security["allowPrivilegeEscalation"] != false {
				t.Fatal("native agent must disable privileged mode and privilege escalation")
			}
			if security["readOnlyRootFilesystem"] != true {
				t.Fatal("native agent must use a read-only root filesystem")
			}
			assertCapabilities(t, security)

			mounts, ok := container["volumeMounts"].([]interface{})
			if !ok {
				t.Fatal("agent volume mounts are missing")
			}
			assertReadOnlyVolumeMount(t, mounts, "cgroup", "/host/sys/fs/cgroup")
		})
	}
}

func assertHostNamespaceIsolation(t *testing.T, spec map[string]interface{}) {
	t.Helper()
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		value, exists := spec[field]
		if !exists {
			t.Fatalf("agent pod spec %s is omitted, want an explicit false value", field)
		}
		shared, ok := value.(bool)
		if !ok || shared {
			t.Fatalf("agent pod spec %s = %#v, want explicit false", field, value)
		}
	}
}

func assertPrometheusAnnotations(t *testing.T, daemonset map[string]interface{}) {
	t.Helper()
	metadata, ok := nestedMap(daemonset, "spec", "template", "metadata")
	if !ok {
		t.Fatal("agent pod metadata is missing")
	}
	annotations, ok := metadata["annotations"].(map[string]interface{})
	if !ok || annotations["prometheus.io/scrape"] != "true" || annotations["prometheus.io/port"] != "9090" || annotations["prometheus.io/path"] != "/metrics" {
		t.Fatalf("agent Prometheus annotations = %#v, want scrape=true port=9090 path=/metrics", metadata)
	}
}

func assertRollingUpdateStrategy(t *testing.T, daemonset map[string]interface{}) {
	t.Helper()
	strategy, ok := nestedMap(daemonset, "spec", "updateStrategy")
	if !ok || strategy["type"] != "RollingUpdate" {
		t.Fatalf("agent update strategy = %#v, want RollingUpdate", daemonset["spec"])
	}
	rolling, ok := nestedMap(daemonset, "spec", "updateStrategy", "rollingUpdate")
	if !ok || rolling["maxUnavailable"] != float64(1) || rolling["maxSurge"] != float64(0) {
		t.Fatalf("agent rolling update = %#v, want maxUnavailable=1/maxSurge=0", strategy["rollingUpdate"])
	}
}

func loadManifestObjects(path string) ([]map[string]interface{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
	objects := make([]map[string]interface{}, 0)
	for document := 1; ; document++ {
		object := make(map[string]interface{})
		if err := decoder.Decode(&object); err != nil {
			if err == io.EOF {
				return objects, nil
			}
			return nil, fmt.Errorf("decode document %d: %w", document, err)
		}
		if len(object) != 0 {
			objects = append(objects, object)
		}
	}
}

func findObject(objects []map[string]interface{}, kind, name string) map[string]interface{} {
	for _, object := range objects {
		if object["kind"] == kind {
			metadata, _ := object["metadata"].(map[string]interface{})
			if metadata != nil && metadata["name"] == name {
				return object
			}
		}
	}
	return nil
}

func nestedMap(object map[string]interface{}, path ...string) (map[string]interface{}, bool) {
	current := object
	for _, key := range path {
		value, ok := current[key].(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func assertHostPathVolume(t *testing.T, volumes []interface{}, name, path, volumeType string) {
	t.Helper()
	for _, raw := range volumes {
		volume, ok := raw.(map[string]interface{})
		if !ok || volume["name"] != name {
			continue
		}
		hostPath, ok := volume["hostPath"].(map[string]interface{})
		if !ok || hostPath["path"] != path || hostPath["type"] != volumeType {
			t.Fatalf("volume %q = %#v, want hostPath %s (%s)", name, volume, path, volumeType)
		}
		return
	}
	t.Fatalf("volume %q is missing", name)
}

func assertReadOnlyVolumeMount(t *testing.T, mounts []interface{}, name, path string) {
	t.Helper()
	for _, raw := range mounts {
		mount, ok := raw.(map[string]interface{})
		if !ok || mount["name"] != name {
			continue
		}
		if mount["mountPath"] != path || mount["readOnly"] != true {
			t.Fatalf("volume mount %q = %#v, want read-only mount at %s", name, mount, path)
		}
		return
	}
	t.Fatalf("volume mount %q is missing", name)
}

func hasNodeNameDownwardAPI(env []interface{}) bool {
	for _, raw := range env {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["name"] != "NODE_NAME" {
			continue
		}
		valueFrom, ok := entry["valueFrom"].(map[string]interface{})
		if !ok {
			return false
		}
		fieldRef, ok := valueFrom["fieldRef"].(map[string]interface{})
		return ok && fieldRef["fieldPath"] == "spec.nodeName"
	}
	return false
}

func assertCapabilities(t *testing.T, security map[string]interface{}) {
	t.Helper()
	capabilities, ok := security["capabilities"].(map[string]interface{})
	if !ok {
		t.Fatal("native agent capabilities are missing")
	}
	drop := stringSlice(capabilities["drop"])
	sort.Strings(drop)
	if strings.Join(drop, ",") != "ALL" {
		t.Fatalf("capability drop list = %#v, want exactly [ALL]", capabilities["drop"])
	}
	got := stringSlice(capabilities["add"])
	sort.Strings(got)
	want := []string{"BPF", "NET_ADMIN", "PERFMON", "SYS_RESOURCE"}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("capability add list = %v, want %v", got, want)
	}
	seccomp, ok := security["seccompProfile"].(map[string]interface{})
	if !ok || seccomp["type"] != "RuntimeDefault" {
		t.Fatalf("seccomp profile = %#v, want RuntimeDefault", security["seccompProfile"])
	}
}

func assertHTTPPort(t *testing.T, container map[string]interface{}) {
	t.Helper()
	ports, ok := container["ports"].([]interface{})
	if !ok {
		t.Fatal("agent HTTP port is missing")
	}
	for _, raw := range ports {
		port, ok := raw.(map[string]interface{})
		if ok && port["name"] == "http" && port["containerPort"] == float64(9090) && port["protocol"] == "TCP" {
			return
		}
	}
	t.Fatalf("agent ports = %#v, want named TCP port 9090", ports)
}

func assertHTTPProbe(t *testing.T, container map[string]interface{}, name, path string) {
	t.Helper()
	probe, ok := container[name].(map[string]interface{})
	if !ok {
		t.Fatalf("agent %s is missing", name)
	}
	httpGet, ok := probe["httpGet"].(map[string]interface{})
	if !ok || httpGet["path"] != path || httpGet["port"] != "http" {
		t.Fatalf("agent %s = %#v, want HTTP probe %s on named port", name, probe, path)
	}
}

func stringSlice(value interface{}) []string {
	values, _ := value.([]interface{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if stringValue, ok := value.(string); ok {
			result = append(result, stringValue)
		}
	}
	return result
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
