package keyvault

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/ctophs/keyvault-cert-tool/pkg/pki"
	"software.sslmate.com/src/go-pkcs12"
)

// PKCS12Info holds the contents of a parsed PKCS#12 file.
type PKCS12Info struct {
	PrivateKey  crypto.PrivateKey
	Certificate *x509.Certificate   // The first certificate bag, expected to be the leaf
	CACerts     []*x509.Certificate // Remaining certificate bags, in file order
	CertChain   []*x509.Certificate // Certificate and CACerts combined, in file order
}

// ParsePKCS12 parses a PKCS#12 file, preserving the order the certificate bags
// appear in. That order is the subject of the checks in CheckBagOrder.
func ParsePKCS12(pfxData []byte, password string) (*PKCS12Info, error) {
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS#12: %w", err)
	}

	info := &PKCS12Info{
		PrivateKey:  privateKey,
		Certificate: certificate,
		CACerts:     caCerts,
	}

	if certificate != nil {
		info.CertChain = append(info.CertChain, certificate)
	}
	info.CertChain = append(info.CertChain, caCerts...)

	return info, nil
}

// CheckBagOrder reports whether the certificate bags are in leaf-first order. The
// chain is rebuilt from signature links first, so a chain that is merely
// misordered is reported as reversed or out of order, not as broken.
func (info *PKCS12Info) CheckBagOrder() (bool, string) {
	if len(info.CertChain) == 0 {
		return false, "no certificates in PKCS#12"
	}

	order, err := pki.ClassifyChainOrder(info.CertChain)
	if err != nil {
		return false, "cryptographic chain broken: " + err.Error()
	}

	switch order {
	case pki.LeafFirst:
		return true, fmt.Sprintf("bag order correct: leaf (CN=%s) before %d CA(s), cryptographic chain valid", info.CertChain[0].Subject.CommonName, len(info.CertChain)-1)
	case pki.Reversed:
		return false, "incorrect - certificates reversed (but cryptographically valid)"
	default:
		return false, "incorrect - certificates out of order (but cryptographically valid)"
	}
}
