package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oarkflow/secure-http/pkg/security"
)

func TestStrictPolicyRejectsWithOpaqueNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	m := &Middleware{policy: &security.SecurityPolicy{OpaqueErrors: true}}

	m.respondNotFound(rec, "internal_code", "internal detail")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	if payload["error"] != "not_found" {
		t.Fatalf("error = %q, want not_found", payload["error"])
	}
	if _, ok := payload["detail"]; ok {
		t.Fatalf("strict response leaked detail: %#v", payload)
	}
}
