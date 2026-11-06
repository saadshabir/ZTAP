package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientconfig "k8s.io/client-go/tools/clientcmd/api"
)

func TestClusterPreflightReportsIndependentFailures(t *testing.T) {
	output, err := runClusterPreflight(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var reply string
		switch r.URL.Path {
		case "/apis/admissionregistration.k8s.io/v1":
			reply = `{"kind":"APIResourceList","groupVersion":"admissionregistration.k8s.io/v1","resources":[{"name":"validatingadmissionpolicies"},{"name":"validatingadmissionpolicybindings"}]}`
		case "/api/v1/namespaces/default/services/kubernetes":
			reply = `{"kind":"Service","apiVersion":"v1","spec":{"clusterIP":"fd00::1","clusterIPs":["fd00::1","10.96.0.1"]}}`
		case "/api/v1/nodes":
			reply = `{"kind":"NodeList","apiVersion":"v1","items":[{"metadata":{"name":"worker","labels":{"kubernetes.io/os":"linux"}},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64","containerRuntimeVersion":"cri-o://1"}}}]}`
		case "/api/v1/pods":
			if r.URL.Query().Get("continue") == "" {
				reply = `{"kind":"PodList","apiVersion":"v1","metadata":{"continue":"next"},"items":[{"metadata":{"name":"unsafe-one","namespace":"first"},"spec":{"containers":[{"name":"regular"}]}}]}`
			} else {
				reply = `{"kind":"PodList","apiVersion":"v1","items":[{"metadata":{"name":"unsafe-two","namespace":"second"},"spec":{"initContainers":[{"name":"init"}]}}]}`
			}
		case "/api/v1/namespaces/ztap-system/serviceaccounts/ztap-agent":
			w.WriteHeader(http.StatusForbidden)
			reply = `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`
		case "/apis/apps/v1/namespaces/ztap-system/daemonsets/ztap-node-init":
			reply = `{"kind":"DaemonSet","apiVersion":"apps/v1","metadata":{"name":"ztap-node-init"}}`
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			review := decodePreflightAccessReview(t, w, r)
			if review == nil {
				return
			}
			access := review.Spec.ResourceAttributes
			switch {
			case access.Verb == "create" && access.Name != "":
				t.Error("create permission review is scoped to a resource name")
			case access.Verb == "patch" && access.Resource == "daemonsets" && access.Name == "ztap-node-init",
				access.Verb == "get" && access.Resource == "endpoints",
				access.Verb == "bind" && access.Resource == "roles":
				reply = `{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","status":{"allowed":false}}`
			}
			if reply == "" {
				reply = `{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","status":{"allowed":true}}`
			}
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(reply))
	})
	if err == nil {
		t.Fatal("preflight succeeded despite failed checks")
	}
	for _, want := range []string{
		"PASS ValidatingAdmissionPolicy API",
		"requires a primary IPv4 ClusterIP for Service default/kubernetes, found \"fd00::1\"",
		"require containerd, found \"cri-o://1\"",
		"pod first/unsafe-one container regular",
		"pod second/unsafe-two container init",
		"installer can get serviceaccounts ztap-system/ztap-agent",
		"installer can patch daemonsets ztap-system/ztap-node-init",
		"installer can bind ztap-bootstrap-api",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q in preflight report:\n%s", want, output)
		}
	}
}

func TestClusterPreflightAllowsCreateOrPatchAsNeeded(t *testing.T) {
	output, err := runClusterPreflight(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var reply string
		switch r.URL.Path {
		case "/apis/admissionregistration.k8s.io/v1":
			reply = `{"kind":"APIResourceList","groupVersion":"admissionregistration.k8s.io/v1","resources":[{"name":"validatingadmissionpolicies"},{"name":"validatingadmissionpolicybindings"}]}`
		case "/api/v1/namespaces/default/services/kubernetes":
			reply = `{"kind":"Service","apiVersion":"v1","spec":{"clusterIP":"10.96.0.1"}}`
		case "/api/v1/nodes":
			reply = `{"kind":"NodeList","apiVersion":"v1","items":[{"metadata":{"name":"worker","labels":{"kubernetes.io/os":"linux"}},"status":{"nodeInfo":{"operatingSystem":"linux","architecture":"arm64","containerRuntimeVersion":"containerd://2"}}}]}`
		case "/api/v1/pods":
			reply = `{"kind":"PodList","apiVersion":"v1","items":[]}`
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles/ztap-bootstrap-api":
			reply = `{"kind":"Role","apiVersion":"rbac.authorization.k8s.io/v1","metadata":{"name":"ztap-bootstrap-api"}}`
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			review := decodePreflightAccessReview(t, w, r)
			if review == nil {
				return
			}
			access := review.Spec.ResourceAttributes
			allowed := true
			switch access.Verb {
			case "create":
				allowed = access.Resource != "roles" && access.Name == ""
			case "patch":
				allowed = access.Resource == "roles" && access.Name == "ztap-bootstrap-api"
			case "get":
				// Force checks of explicit bind and escalate grants for both roles.
				allowed = access.Resource != "endpoints" && access.Resource != "networkpolicies"
			case "escalate":
				allowed = (access.Resource == "roles" && access.Name == "ztap-bootstrap-api") ||
					(access.Resource == "clusterroles" && access.Name == "")
			}
			review.Status.Allowed = allowed
			review.Kind, review.APIVersion = "SelfSubjectAccessReview", "authorization.k8s.io/v1"
			if err := json.NewEncoder(w).Encode(review); err != nil {
				t.Error(err)
			}
			return
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(reply))
	})
	if err != nil {
		t.Fatalf("preflight rejected a delegated installer: %v\n%s", err, output)
	}
}

func decodePreflightAccessReview(t *testing.T, w http.ResponseWriter, r *http.Request) *authv1.SelfSubjectAccessReview {
	t.Helper()
	var review authv1.SelfSubjectAccessReview
	body, err := io.ReadAll(r.Body)
	if err == nil {
		_, _, err = scheme.Codecs.UniversalDeserializer().Decode(body, nil, &review)
	}
	if err != nil {
		t.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil
	}
	return &review
}

func runClusterPreflight(t *testing.T, handler http.HandlerFunc) (string, error) {
	t.Helper()
	api := httptest.NewServer(handler)
	defer api.Close()
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(clientconfig.Config{
		Clusters: map[string]*clientconfig.Cluster{"test": {Server: api.URL}},
		Contexts: map[string]*clientconfig.Context{"test": {Cluster: "test"}},
	}, kubeconfig); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd("test")
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"preflight", "cluster", "--kubeconfig", kubeconfig, "--context", "test"})
	err := root.Execute()
	return output.String(), err
}
