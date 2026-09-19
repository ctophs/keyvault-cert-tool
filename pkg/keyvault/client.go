// Package keyvault provides Azure Key Vault integration for certificate operations.
// It handles CSR creation, certificate merging, PEM/PFX downloads, and PKCS#12 validation.
package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// Client wraps Azure Key Vault SDK clients for certificate and secret operations.
type Client struct {
	certClient   *azcertificates.Client
	secretClient *azsecrets.Client
}

// Content types Key Vault accepts for a certificate's backing secret.
// The choice is made at CSR creation and determines the download format.
const (
	ContentTypePEM = "application/x-pem-file"
	ContentTypePFX = "application/x-pkcs12"
)

// ParseContentType resolves a user-supplied content-type to its Key Vault value.
// It accepts the short forms "pem" and "pfx" as well as the full media types.
func ParseContentType(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pem", ContentTypePEM:
		return ContentTypePEM, nil
	case "pfx", "pkcs12", ContentTypePFX:
		return ContentTypePFX, nil
	default:
		return "", fmt.Errorf("unsupported content-type %q (want pem or pfx)", s)
	}
}

// CreateCSROptions configures CSR creation parameters.
type CreateCSROptions struct {
	ContentType       string // ContentTypePEM or ContentTypePFX
	PreserveCertOrder bool   // Ask Azure to preserve certificate order (not honored for PFX)
}

// NewClient creates a new Key Vault client using Azure CLI credentials
func NewClient(vaultURL string) (*Client, error) {
	cred, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure CLI credential: %w", err)
	}

	kvClient, err := azcertificates.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	secretClient, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets client: %w", err)
	}

	return &Client{certClient: kvClient, secretClient: secretClient}, nil
}

// CreateCSR initiates a Certificate Signing Request in Key Vault.
// The certificate subject is derived from certName as "CN=<certName>".
func (c *Client) CreateCSR(ctx context.Context, certName string, opts *CreateCSROptions) ([]byte, error) {
	contentType := opts.ContentType
	preserveOrder := opts.PreserveCertOrder

	issuerName := "Unknown"
	subject := "CN=" + certName
	policy := &azcertificates.CertificatePolicy{
		SecretProperties: &azcertificates.SecretProperties{
			ContentType: &contentType,
		},
		X509CertificateProperties: &azcertificates.X509CertificateProperties{
			Subject: &subject,
		},
		IssuerParameters: &azcertificates.IssuerParameters{
			Name: &issuerName,
		},
	}

	// Always send the flag explicitly: omitting it and sending false are distinct
	// cases on the Azure side, and distinguishing them is the point of the tests.
	params := azcertificates.CreateCertificateParameters{
		CertificatePolicy: policy,
		PreserveCertOrder: &preserveOrder,
	}

	resp, err := c.certClient.CreateCertificate(ctx, certName, params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	if len(resp.CertificateOperation.CSR) == 0 {
		return nil, fmt.Errorf("CSR not returned from Key Vault")
	}

	return resp.CertificateOperation.CSR, nil
}

// MergeCertificate merges a signed certificate chain back and returns the version
// of the secret backing the new certificate version, so callers can download
// exactly what was merged rather than whatever is latest.
func (c *Client) MergeCertificate(ctx context.Context, certName string, leafCert *x509.Certificate, chainCerts []*x509.Certificate) (string, error) {
	x5c := make([][]byte, 0, 1+len(chainCerts))
	x5c = append(x5c, leafCert.Raw)
	for _, cert := range chainCerts {
		x5c = append(x5c, cert.Raw)
	}

	params := azcertificates.MergeCertificateParameters{
		X509Certificates: x5c,
	}

	resp, err := c.certClient.MergeCertificate(ctx, certName, params, nil)
	if err != nil {
		return "", fmt.Errorf("failed to merge certificate: %w", err)
	}

	if resp.SID == nil || resp.SID.Version() == "" {
		return "", fmt.Errorf("merge response did not identify the new secret version")
	}
	return resp.SID.Version(), nil
}

// CertificateStatus reports whether a certificate is absent, awaiting a CSR merge,
// or fully merged. Returns "not_found", "pending", or "completed".
func (c *Client) CertificateStatus(ctx context.Context, certName string) (string, error) {
	_, err := c.certClient.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		if isNotFound(err) {
			return "not_found", nil
		}
		return "", fmt.Errorf("failed to get certificate: %w", err)
	}

	// Anything but a pending operation, including a 404 or an operation that has
	// finished, means the certificate is complete.
	op, err := c.certClient.GetCertificateOperation(ctx, certName, nil)
	if err != nil {
		if isNotFound(err) {
			return "completed", nil
		}
		return "", fmt.Errorf("failed to get certificate operation: %w", err)
	}

	if op.CertificateOperation.Status != nil && isPending(*op.CertificateOperation.Status) {
		return "pending", nil
	}

	return "completed", nil
}

// isPending reports whether a certificate operation status means a CSR is still
// awaiting merge. Azure sends "inProgress"; the SDK does not define constants
// for the values, so the comparison ignores case.
func isPending(status string) bool {
	return strings.EqualFold(status, "inProgress")
}

// isNotFound reports whether an Azure error represents a 404. The SDK does not
// expose a typed sentinel for this, so the message is matched. Covers both
// CertificateNotFound and SecretNotFound.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	// Azure reports this as prose ("not found in this key vault") and as error
	// codes (CertificateNotFound, SecretNotFound), so match both spellings.
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "notfound") ||
		strings.Contains(errStr, "404")
}

// getSecretValue retrieves a certificate's backing secret. Key Vault stores the
// merged certificate here in whichever format the policy's content-type selected.
func (c *Client) getSecretValue(ctx context.Context, certName, version string) (string, error) {
	resp, err := c.secretClient.GetSecret(ctx, certName, version, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}

	if resp.Value == nil || *resp.Value == "" {
		return "", fmt.Errorf("secret %q is empty", certName)
	}

	return *resp.Value, nil
}

// GetCertificatePEM retrieves the full certificate chain in PEM format.
// Only valid when the certificate was created with the PEM content-type.
// version selects the secret version, as returned by MergeCertificate.
func (c *Client) GetCertificatePEM(ctx context.Context, certName, version string) ([]byte, error) {
	value, err := c.getSecretValue(ctx, certName, version)
	if err != nil {
		return nil, err
	}

	// Secret value is the raw PEM (private key + chain)
	return []byte(value), nil
}

// GetCertificatePFX retrieves the certificate as PKCS#12 (includes private key).
// Only valid when the certificate was created with the PFX content-type.
// version selects the secret version, as returned by MergeCertificate.
func (c *Client) GetCertificatePFX(ctx context.Context, certName, version string) ([]byte, error) {
	value, err := c.getSecretValue(ctx, certName, version)
	if err != nil {
		return nil, err
	}

	pfxData, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode PFX: %w", err)
	}

	return pfxData, nil
}

// CancelCertificateOperation cancels a pending certificate operation.
// Callers may ignore the error when clearing a possibly-absent operation.
func (c *Client) CancelCertificateOperation(ctx context.Context, certName string) error {
	if _, err := c.certClient.DeleteCertificateOperation(ctx, certName, nil); err != nil {
		return fmt.Errorf("failed to cancel certificate operation: %w", err)
	}
	return nil
}

// DecodeCertificatesFromPEM extracts certificates from PEM data (skips private keys)
func DecodeCertificatesFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var rest []byte = pemData

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}

		// Only process CERTIFICATE blocks, skip PRIVATE KEY etc.
		if block.Type == "CERTIFICATE" {
			parsedCerts, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate in PEM: %w", err)
			}
			certs = append(certs, parsedCerts...)
		}

		rest = remaining
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}
