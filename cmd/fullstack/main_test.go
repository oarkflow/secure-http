package main

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestSanitizeUploadName(t *testing.T) {
	got := sanitizeUploadName("../unsafe name.txt")
	if got != "unsafe_name.txt" {
		t.Fatalf("sanitizeUploadName() = %q", got)
	}
}

func TestUploadPolicyAllowedType(t *testing.T) {
	policy := uploadPolicy{
		AllowedTypes: map[string]struct{}{
			"application/json": {},
		},
	}
	if !policy.isAllowedType("application/json; charset=utf-8") {
		t.Fatalf("expected content type to be allowed")
	}
	if policy.isAllowedType("text/html") {
		t.Fatalf("expected content type to be rejected")
	}
}

func TestHandleListFilesRespectsPolicy(t *testing.T) {
	app := fiber.New()
	app.Get("/files", handleListFiles(uploadPolicy{AllowListing: false}))

	req := httptest.NewRequest("GET", "/files", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusForbidden)
	}
}
