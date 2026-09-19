package demo

import (
	"testing"

	"github.com/ctophs/keyvault-cert-tool/pkg/keyvault"
)

func TestPlanTestsAllCombinations(t *testing.T) {
	tests, err := planTests(true, "", false)
	if err != nil {
		t.Fatalf("planTests: %v", err)
	}

	want := []TestRun{
		{ContentType: keyvault.ContentTypePEM, PreserveCertOrder: false},
		{ContentType: keyvault.ContentTypePEM, PreserveCertOrder: true},
		{ContentType: keyvault.ContentTypePFX, PreserveCertOrder: false},
		{ContentType: keyvault.ContentTypePFX, PreserveCertOrder: true},
	}

	if len(tests) != len(want) {
		t.Fatalf("got %d runs, want %d", len(tests), len(want))
	}
	for i := range want {
		if tests[i].ContentType != want[i].ContentType || tests[i].PreserveCertOrder != want[i].PreserveCertOrder {
			t.Errorf("run %d = (%s, %t), want (%s, %t)", i,
				tests[i].ContentType, tests[i].PreserveCertOrder,
				want[i].ContentType, want[i].PreserveCertOrder)
		}
	}
}

func TestPlanTestsSingleRun(t *testing.T) {
	tests, err := planTests(false, "pfx", true)
	if err != nil {
		t.Fatalf("planTests: %v", err)
	}

	if len(tests) != 1 {
		t.Fatalf("got %d runs, want 1", len(tests))
	}
	if tests[0].ContentType != keyvault.ContentTypePFX {
		t.Errorf("ContentType = %q, want %q", tests[0].ContentType, keyvault.ContentTypePFX)
	}
	if !tests[0].PreserveCertOrder {
		t.Error("PreserveCertOrder = false, want true")
	}
}

// Bad arguments must be rejected before the demo opens any connection.
func TestPlanTestsRejectsBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
	}{
		{"no content type", ""},
		{"unsupported content type", "der"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planTests(false, tc.contentType, false); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestLabel(t *testing.T) {
	if got := label(keyvault.ContentTypePFX); got != "PFX" {
		t.Errorf("label(PFX) = %q, want %q", got, "PFX")
	}
	if got := label(keyvault.ContentTypePEM); got != "PEM" {
		t.Errorf("label(PEM) = %q, want %q", got, "PEM")
	}
}
