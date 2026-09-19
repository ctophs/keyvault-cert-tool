// Package pki provides local certificate generation and validation for testing.
// It simulates a PKI hierarchy (Root CA → Issuing CA → Sub-Issuing CA) to sign
// CSRs and validate certificate chains during demo workflows.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// CA holds a certificate authority's certificate and private key.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// CertChain represents a certificate and its chain of intermediates and root.
type CertChain struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Root          *x509.Certificate
}

// GenerateRootCA creates a self-signed Root CA.
// Root CA is valid for 10 years and can issue up to 2 levels of intermediates.
func GenerateRootCA() (*CA, error) {
	return generateCA("Demo Root CA", 10, 2, nil, nil)
}

// GenerateIssuingCA creates an Issuing CA signed by Root CA.
// Issuing CA is valid for 5 years and can issue 1 level of intermediates.
func GenerateIssuingCA(rootCA *CA) (*CA, error) {
	return generateCA("Demo Issuing CA", 5, 1, rootCA.Cert, rootCA.Key)
}

// GenerateSubIssuingCA creates a Sub-Issuing CA signed by parent CA.
// Sub-Issuing CA is valid for 3 years and can only sign leaf certificates (pathlen:0).
func GenerateSubIssuingCA(parentCA *CA) (*CA, error) {
	return generateCA("Demo Sub-Issuing CA", 3, 0, parentCA.Cert, parentCA.Key)
}

// newSerialNumber returns a random 128-bit certificate serial number.
func newSerialNumber() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serial, nil
}

// generateCA is the common CA generation function used by all CA types.
// If signerCert/Key are nil, creates a self-signed root certificate.
func generateCA(cn string, validityYears int, maxPathLen int, signerCert *x509.Certificate, signerKey *rsa.PrivateKey) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		// Without this, x509 treats MaxPathLen==0 as "unset" and omits the
		// constraint entirely instead of encoding pathlen:0.
		MaxPathLenZero: maxPathLen == 0,
	}

	// Self-sign if no signer provided, otherwise sign with parent CA
	parent := template
	parentKey := key
	if signerCert != nil {
		parent = signerCert
		parentKey = signerKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate (CN=%s): %w", cn, err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (CN=%s): %w", cn, err)
	}

	return &CA{Cert: cert, Key: key}, nil
}

// SignCSR signs a CSR using the provided signing CA and builds a complete certificate chain.
// The returned chain includes the signed leaf certificate, all intermediates from the signing CA upward,
// and the root CA. This chain should be merged back into Key Vault.
// Parameters: CSR bytes, signing CA, list of intermediate CAs, root CA
func SignCSR(csrBytes []byte, signingCA *CA, intermediates []*x509.Certificate, rootCA *CA) (*CertChain, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature validation failed: %w", err)
	}

	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Copy SANs from CSR if present
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
		template.DNSNames = csr.DNSNames
		template.IPAddresses = csr.IPAddresses
	}

	leafBytes, err := x509.CreateCertificate(rand.Reader, template, signingCA.Cert, csr.PublicKey, signingCA.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	// Build chain: signing CA + any additional intermediates
	chain := make([]*x509.Certificate, 0, 1+len(intermediates))
	chain = append(chain, signingCA.Cert)
	chain = append(chain, intermediates...)

	return &CertChain{
		Leaf:          leafCert,
		Intermediates: chain,
		Root:          rootCA.Cert,
	}, nil
}

// ChainOrder describes how a list of certificates is ordered relative to the
// chain their signatures form.
type ChainOrder int

const (
	LeafFirst  ChainOrder = iota // leaf, then each issuer up to the root
	Reversed                     // root first, leaf last
	OutOfOrder                   // any other permutation
)

// ClassifyChainOrder rebuilds the chain from signature links and reports how
// certs is ordered relative to it. It returns an error only if the certificates
// do not form one valid chain, so a misordered chain is never reported as broken.
func ClassifyChainOrder(certs []*x509.Certificate) (ChainOrder, error) {
	chain, err := chainBySignature(certs)
	if err != nil {
		return 0, err
	}

	sameOrder := func(a, b []*x509.Certificate) bool {
		return slices.EqualFunc(a, b, func(x, y *x509.Certificate) bool { return x.Equal(y) })
	}
	reversed := slices.Clone(chain)
	slices.Reverse(reversed)

	switch {
	case sameOrder(certs, chain):
		return LeafFirst, nil
	case sameOrder(certs, reversed):
		return Reversed, nil
	default:
		return OutOfOrder, nil
	}
}

// chainBySignature orders certs from leaf to root by following issuer links and
// verifying each signature. It fails if a signature does not verify, if the
// chain does not end at a self-signed root, or if any certificate is not part of
// the chain.
func chainBySignature(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	bySubject := make(map[string]*x509.Certificate, len(certs))
	var leaf *x509.Certificate
	for _, cert := range certs {
		bySubject[cert.Subject.String()] = cert
		if leaf == nil && !cert.IsCA {
			leaf = cert
		}
	}
	if leaf == nil {
		return nil, fmt.Errorf("no leaf certificate, every certificate is a CA")
	}

	chain := []*x509.Certificate{leaf}
	for current := leaf; ; {
		issuer, found := bySubject[current.Issuer.String()]
		if !found || issuer == current {
			break
		}
		if err := current.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("CN=%s is not signed by CN=%s", current.Subject.CommonName, issuer.Subject.CommonName)
		}
		chain = append(chain, issuer)
		if len(chain) > len(certs) {
			return nil, fmt.Errorf("issuer links form a cycle")
		}
		current = issuer
	}

	if last := chain[len(chain)-1]; last.CheckSignatureFrom(last) != nil {
		return nil, fmt.Errorf("chain ends at CN=%s, which is not a self-signed root", last.Subject.CommonName)
	}
	if len(chain) != len(certs) {
		return nil, fmt.Errorf("%d certificate(s) are not part of the chain", len(certs)-len(chain))
	}
	return chain, nil
}

// VerifyChainOrder reports whether certs are in leaf-first order and form a
// valid chain ending at a self-signed root.
func VerifyChainOrder(certs []*x509.Certificate) (bool, string) {
	if len(certs) == 0 {
		return false, "no certificates in chain"
	}

	order, err := ClassifyChainOrder(certs)
	if err != nil {
		return false, "cryptographic chain broken: " + err.Error()
	}

	switch order {
	case LeafFirst:
		return true, fmt.Sprintf("chain order correct (leaf at 0), cryptographic chain valid (%d certs)", len(certs))
	case Reversed:
		return false, "incorrect - certificates reversed (but cryptographically valid)"
	default:
		return false, "incorrect - certificates out of order (but cryptographically valid)"
	}
}
