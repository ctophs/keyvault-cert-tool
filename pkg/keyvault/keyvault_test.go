package keyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/ctophs/keyvault-cert-tool/pkg/pki"
)

// newChain builds a leaf/sub-issuing/issuing/root chain in leaf-first order.
func newChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	root, err := pki.GenerateRootCA()
	if err != nil {
		t.Fatalf("generate root CA: %v", err)
	}
	issuing, err := pki.GenerateIssuingCA(root)
	if err != nil {
		t.Fatalf("generate issuing CA: %v", err)
	}
	subIssuing, err := pki.GenerateSubIssuingCA(issuing)
	if err != nil {
		t.Fatalf("generate sub-issuing CA: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	signed, err := pki.SignCSR(csr, subIssuing, []*x509.Certificate{issuing.Cert}, root)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}

	return []*x509.Certificate{signed.Leaf, subIssuing.Cert, issuing.Cert, root.Cert}
}

// infoFor builds a PKCS12Info holding certs in the given order, as ParsePKCS12
// would after decoding a file with that bag order.
func infoFor(certs []*x509.Certificate) *PKCS12Info {
	return &PKCS12Info{
		Certificate: certs[0],
		CACerts:     certs[1:],
		CertChain:   certs,
	}
}

func reverse(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	for i, cert := range certs {
		out[len(certs)-1-i] = cert
	}
	return out
}

func TestParseContentType(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"pem", ContentTypePEM, false},
		{"PEM", ContentTypePEM, false},
		{"  pem  ", ContentTypePEM, false},
		{ContentTypePEM, ContentTypePEM, false},
		{"pfx", ContentTypePFX, false},
		{"pkcs12", ContentTypePFX, false},
		{ContentTypePFX, ContentTypePFX, false},
		{"", "", true},
		{"der", "", true},
		{"application/x-bogus", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseContentType(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseContentType(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseContentType(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseContentType(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDecodeCertificatesFromPEMSkipsPrivateKey(t *testing.T) {
	certs := newChain(t)

	// Key Vault returns the private key ahead of the chain in the PEM secret.
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a real key"),
	})...)
	for _, cert := range certs {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	got, err := DecodeCertificatesFromPEM(buf)
	if err != nil {
		t.Fatalf("DecodeCertificatesFromPEM: %v", err)
	}

	if len(got) != len(certs) {
		t.Fatalf("got %d certificates, want %d", len(got), len(certs))
	}
	for i := range got {
		if !got[i].Equal(certs[i]) {
			t.Errorf("certificate %d does not match input order", i)
		}
	}
}

func TestDecodeCertificatesFromPEMWithoutCertificates(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty input", nil},
		{"no PEM blocks", []byte("plain text")},
		{"key only", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeCertificatesFromPEM(tc.in); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestCheckBagOrderAcceptsCorrectOrder(t *testing.T) {
	ok, msg := infoFor(newChain(t)).CheckBagOrder()
	if !ok {
		t.Errorf("CheckBagOrder() = false, want true (%s)", msg)
	}
}

// This is the Azure PFX bug: every bag is reversed, yet the certificates still
// form a valid chain. The message must distinguish that from a broken chain.
func TestCheckBagOrderDetectsReversedButValidChain(t *testing.T) {
	ok, msg := infoFor(reverse(newChain(t))).CheckBagOrder()

	if ok {
		t.Fatal("CheckBagOrder() = true, want false for reversed bags")
	}
	if !strings.Contains(msg, "reversed") || !strings.Contains(msg, "cryptographically valid") {
		t.Errorf("message %q should report a reversed but cryptographically valid chain", msg)
	}
}

func TestCheckBagOrderRejectsUnrelatedCertificates(t *testing.T) {
	// A leaf from one hierarchy with CAs from another: order looks right, but
	// no signature links them.
	mixed := append([]*x509.Certificate{newChain(t)[0]}, newChain(t)[1:]...)

	if ok, _ := infoFor(mixed).CheckBagOrder(); ok {
		t.Error("CheckBagOrder() = true, want false for an unlinked chain")
	}
}

func TestCheckBagOrderWithoutLeaf(t *testing.T) {
	if ok, msg := (&PKCS12Info{}).CheckBagOrder(); ok || msg == "" {
		t.Errorf("CheckBagOrder() = (%t, %q), want (false, non-empty)", ok, msg)
	}
}

func TestFormatPermissionsIsSorted(t *testing.T) {
	perms := map[string]bool{"Get": true, "Create": false, "Merge": true}

	want := "  ✗ Create\n  ✓ Get\n  ✓ Merge\n"
	for i := 0; i < 10; i++ {
		if got := formatPermissions(perms); got != want {
			t.Fatalf("formatPermissions() = %q, want %q", got, want)
		}
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("Not Found"), true},
		{errors.New("404 Not Found"), true},
		{errors.New("CertificateNotFound: not found in this key vault"), true},
		{errors.New("SecretNotFound"), true},
		{errors.New("Forbidden"), false},
		{errors.New("409 Conflict"), false},
	}

	for _, tc := range tests {
		got := isNotFound(tc.err)
		if got != tc.want {
			t.Errorf("isNotFound(%v) = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestCanRunDemo(t *testing.T) {
	full := func() *PermissionCheck {
		return &PermissionCheck{
			Certificates: map[string]bool{"Get": true, "Create": true, "Update": true},
			Secrets:      map[string]bool{"Get": true},
		}
	}

	if ok, missing := full().CanRunDemo(); !ok {
		t.Errorf("CanRunDemo() = false with all permissions, missing %v", missing)
	}

	for _, tc := range []struct {
		key  string
		want string
	}{
		{"Get", "Certificates.Get"},
		{"Create", "Certificates.Create"},
		{"Update", "Certificates.Update"},
		{"secret", "Secrets.Get"},
	} {
		perms := full()
		if tc.key == "secret" {
			perms.Secrets["Get"] = false
		} else {
			perms.Certificates[tc.key] = false
		}
		ok, missing := perms.CanRunDemo()
		if ok || len(missing) != 1 || missing[0] != tc.want {
			t.Errorf("without %s: CanRunDemo() = (%t, %v), want (false, [%s])", tc.want, ok, missing, tc.want)
		}
	}
}

// Azure reports a pending CSR as "inProgress"; an exact match on "InProgress"
// used to report it as completed, and the demo then cancelled the pending CSR.
func TestIsPending(t *testing.T) {
	for status, want := range map[string]bool{
		"inProgress": true,
		"InProgress": true,
		"completed":  false,
		"failed":     false,
		"cancelled":  false,
		"":           false,
	} {
		if got := isPending(status); got != want {
			t.Errorf("isPending(%q) = %t, want %t", status, got, want)
		}
	}
}

// Order checks must name the actual defect: a chain that is merely misordered is
// neither "reversed" nor "broken".
func TestCheckBagOrderClassifiesOrder(t *testing.T) {
	c := newChain(t) // leaf, sub-issuing, issuing, root
	leaf, sub, issuing, root := c[0], c[1], c[2], c[3]

	tests := []struct {
		name    string
		certs   []*x509.Certificate
		wantOK  bool
		wantMsg string
	}{
		{"correct", []*x509.Certificate{leaf, sub, issuing, root}, true, "correct"},
		{"reversed", []*x509.Certificate{root, issuing, sub, leaf}, false, "reversed"},
		{"scrambled, CA first", []*x509.Certificate{issuing, leaf, root, sub}, false, "out of order"},
		{"leaf first, CAs reversed", []*x509.Certificate{leaf, root, issuing, sub}, false, "out of order"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, msg := infoFor(tc.certs).CheckBagOrder()
			if ok != tc.wantOK || !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("CheckBagOrder() = (%t, %q), want (%t, containing %q)", ok, msg, tc.wantOK, tc.wantMsg)
			}
			if !tc.wantOK && strings.Contains(msg, "broken") {
				t.Errorf("valid chain reported as broken: %q", msg)
			}
		})
	}
}

// responseError builds the error the Azure SDK returns for an HTTP failure.
func responseError(status int, code, message string) error {
	req, _ := http.NewRequest(http.MethodGet, "https://vault.example/certificates/test", nil)
	body := fmt.Sprintf(`{"error":{"code":%q,"message":%q}}`, code, message)
	return runtime.NewResponseError(&http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	})
}

// Only an authorization failure may mark a permission as missing, and a failure
// unrelated to authorization must surface instead of being read as a denial.
func TestAllowed(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    bool
		wantErr bool
	}{
		{"success", nil, true, false},
		{"invalid request (create probe)", responseError(400, "BadParameter", "Either subjectName or san must be present"), true, false},
		{"not found", responseError(404, "CertificateNotFound", "not found"), true, false},
		{"conflict (pending CSR)", responseError(409, "Conflict", "pending operation"), true, false},
		{"disabled secret (pending CSR)", responseError(403, "Forbidden", "Operation get is not allowed on a disabled secret."), true, false},
		{"update on a completed operation", responseError(403, "Forbidden", "Pending status must be in progress to allow update."), true, false},
		{"denied", responseError(403, "Forbidden", "Caller is not authorized to perform action on resource."), false, false},
		{"unauthenticated", responseError(401, "Unauthorized", "AKV10000"), false, false},
		{"server error", responseError(500, "InternalServerError", "boom"), false, true},
		{"network error", errors.New("dial tcp: i/o timeout"), false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := allowed(tc.err)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("allowed() = (%t, %v), want (%t, error=%t)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
