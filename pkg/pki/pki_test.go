package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// newCSR builds a certificate request suitable for signing by a CA.
func newCSR(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	return csr
}

// newHierarchy builds the Root -> Issuing -> Sub-Issuing chain used by the demo.
func newHierarchy(t *testing.T) (root, issuing, subIssuing *CA) {
	t.Helper()

	root, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("generate root CA: %v", err)
	}

	issuing, err = GenerateIssuingCA(root)
	if err != nil {
		t.Fatalf("generate issuing CA: %v", err)
	}

	subIssuing, err = GenerateSubIssuingCA(issuing)
	if err != nil {
		t.Fatalf("generate sub-issuing CA: %v", err)
	}

	return root, issuing, subIssuing
}

func TestHierarchyIsSignedTopDown(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)

	if err := root.Cert.CheckSignatureFrom(root.Cert); err != nil {
		t.Errorf("root should be self-signed: %v", err)
	}
	if err := issuing.Cert.CheckSignatureFrom(root.Cert); err != nil {
		t.Errorf("issuing should be signed by root: %v", err)
	}
	if err := subIssuing.Cert.CheckSignatureFrom(issuing.Cert); err != nil {
		t.Errorf("sub-issuing should be signed by issuing: %v", err)
	}

	for _, ca := range []*CA{root, issuing, subIssuing} {
		if !ca.Cert.IsCA {
			t.Errorf("%s should be a CA", ca.Cert.Subject.CommonName)
		}
	}
}

// A MaxPathLen of 0 is only encoded when MaxPathLenZero is set; without it the
// constraint is silently omitted and the sub-issuing CA could issue further CAs.
func TestSubIssuingCAEncodesPathLenZero(t *testing.T) {
	_, _, subIssuing := newHierarchy(t)

	parsed, err := x509.ParseCertificate(subIssuing.Cert.Raw)
	if err != nil {
		t.Fatalf("parse sub-issuing cert: %v", err)
	}

	if parsed.MaxPathLen != 0 || !parsed.MaxPathLenZero {
		t.Errorf("want pathlen:0 constraint, got MaxPathLen=%d MaxPathLenZero=%t",
			parsed.MaxPathLen, parsed.MaxPathLenZero)
	}
}

func TestSignCSRProducesVerifiableLeaf(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)

	chain, err := SignCSR(newCSR(t, "leaf.example"), subIssuing, []*x509.Certificate{issuing.Cert}, root)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}

	if chain.Leaf.IsCA {
		t.Error("leaf must not be a CA")
	}
	if got := chain.Leaf.Subject.CommonName; got != "leaf.example" {
		t.Errorf("leaf CN = %q, want %q", got, "leaf.example")
	}
	if err := chain.Leaf.CheckSignatureFrom(subIssuing.Cert); err != nil {
		t.Errorf("leaf should be signed by sub-issuing CA: %v", err)
	}
	if chain.Root != root.Cert {
		t.Error("chain root should be the root CA")
	}
}

func TestSignCSRRejectsMalformedCSR(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)

	if _, err := SignCSR([]byte("not a csr"), subIssuing, []*x509.Certificate{issuing.Cert}, root); err == nil {
		t.Error("want error for malformed CSR, got nil")
	}
}

// Serial numbers were previously derived from the current Unix second, so
// certificates issued within the same second collided.
func TestSignCSRAssignsUniqueSerials(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)
	intermediates := []*x509.Certificate{issuing.Cert}

	first, err := SignCSR(newCSR(t, "a.example"), subIssuing, intermediates, root)
	if err != nil {
		t.Fatalf("sign first CSR: %v", err)
	}
	second, err := SignCSR(newCSR(t, "b.example"), subIssuing, intermediates, root)
	if err != nil {
		t.Fatalf("sign second CSR: %v", err)
	}

	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Errorf("serials collided: %s", first.Leaf.SerialNumber)
	}
}

func TestVerifyChainOrder(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)

	chain, err := SignCSR(newCSR(t, "leaf.example"), subIssuing, []*x509.Certificate{issuing.Cert}, root)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}

	ordered := []*x509.Certificate{chain.Leaf, subIssuing.Cert, issuing.Cert, root.Cert}
	reversed := []*x509.Certificate{root.Cert, issuing.Cert, subIssuing.Cert, chain.Leaf}

	tests := []struct {
		name  string
		certs []*x509.Certificate
		want  bool
	}{
		{"correct order", ordered, true},
		{"reversed order", reversed, false},
		{"empty chain", nil, false},
		{"missing root", ordered[:3], false},
		{"leaf only", ordered[:1], false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := VerifyChainOrder(tc.certs)
			if got != tc.want {
				t.Errorf("VerifyChainOrder() = %t, want %t (%s)", got, tc.want, msg)
			}
			if msg == "" {
				t.Error("want a non-empty explanation")
			}
		})
	}
}

// A misordered but valid chain must be reported as reversed or out of order,
// never as broken.
func TestVerifyChainOrderClassifiesOrder(t *testing.T) {
	root, issuing, subIssuing := newHierarchy(t)
	chain, err := SignCSR(newCSR(t, "leaf.example"), subIssuing, []*x509.Certificate{issuing.Cert}, root)
	if err != nil {
		t.Fatalf("sign CSR: %v", err)
	}
	leaf, sub, iss, rt := chain.Leaf, subIssuing.Cert, issuing.Cert, root.Cert

	tests := []struct {
		name    string
		certs   []*x509.Certificate
		wantOK  bool
		wantMsg string
	}{
		{"correct", []*x509.Certificate{leaf, sub, iss, rt}, true, "correct"},
		{"reversed", []*x509.Certificate{rt, iss, sub, leaf}, false, "reversed"},
		{"scrambled, CA first", []*x509.Certificate{iss, leaf, rt, sub}, false, "out of order"},
		{"leaf first, CAs reversed", []*x509.Certificate{leaf, rt, iss, sub}, false, "out of order"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, msg := VerifyChainOrder(tc.certs)
			if ok != tc.wantOK || !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("VerifyChainOrder() = (%t, %q), want (%t, containing %q)", ok, msg, tc.wantOK, tc.wantMsg)
			}
			if !tc.wantOK && strings.Contains(msg, "broken") {
				t.Errorf("valid chain reported as broken: %q", msg)
			}
		})
	}
}
