package apihttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/internal/audit"
	"ztap/internal/auth"
	"ztap/internal/enforcer"
)

func newEnforcementTestServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() {
		_ = am.Close()
		_ = al.Close()
	})

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestEnforcementStart_RequiresPolicyYAML(t *testing.T) {
	srv := newEnforcementTestServer(t)

	body, _ := json.Marshal(map[string]string{"policy_yaml": "   "})
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStart_InvalidJSON(t *testing.T) {
	srv := newEnforcementTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewBufferString("not-json"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStart_NoPoliciesFound(t *testing.T) {
	srv := newEnforcementTestServer(t)

	body, _ := json.Marshal(map[string]string{"policy_yaml": "---\n"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStart_InvalidPolicyYAML(t *testing.T) {
	srv := newEnforcementTestServer(t)

	body, _ := json.Marshal(map[string]string{"policy_yaml": "invalid: ["})
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStart_SelectorWithoutDiscovery(t *testing.T) {
	srv := newEnforcementTestServer(t)

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: selector\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      podSelector:\n        matchLabels:\n          app: db\n    ports:\n    - protocol: TCP\n      port: 5432\n"
	body, _ := json.Marshal(map[string]string{"policy_yaml": policyYAML})
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStart_LinuxDirectPathRetired(t *testing.T) {
	if !enforcer.IsLinux() {
		t.Skip("Linux direct enforcement retirement only applies on Linux")
	}
	srv := newEnforcementTestServer(t)
	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: retired\nspec:\n  podSelector:\n    matchLabels:\n      app: retired\n"
	body, _ := json.Marshal(map[string]string{"policy_yaml": policyYAML})
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/start", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("ztap agent")) {
		t.Fatalf("retirement response does not point to ztap agent: %s", rr.Body.String())
	}
}

func TestEnforcementStart_MethodNotAllowed(t *testing.T) {
	srv := newEnforcementTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/enforcement/start", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStop_MethodNotAllowed(t *testing.T) {
	srv := newEnforcementTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/enforcement/stop", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStop_LinuxDirectPathRetired(t *testing.T) {
	if !enforcer.IsLinux() {
		t.Skip("Linux direct enforcement retirement only applies on Linux")
	}
	srv := newEnforcementTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/stop", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("ztap agent")) {
		t.Fatalf("retirement response does not point to ztap agent: %s", rr.Body.String())
	}
}

func TestEnforcementStop_WindowsStubError(t *testing.T) {
	if enforcer.IsLinux() || enforcer.IsWindows() {
		t.Skip("stub path not applicable on windows")
	}
	srv := newEnforcementTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/stop", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented && rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 501/500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEnforcementStop_UnsupportedPlatform(t *testing.T) {
	if enforcer.IsLinux() || enforcer.IsWindows() {
		t.Skip("unsupported platform path not applicable")
	}
	srv := newEnforcementTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/enforcement/stop", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}
