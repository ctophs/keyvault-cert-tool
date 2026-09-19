package keyvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

// PermissionCheck holds the results of pre-flight permission validation.
// It probes real data-plane calls, so it reports what the caller can actually do
// regardless of whether the vault uses RBAC, access policies, or both. The
// data plane gives no signal about which model granted access, so the
// authorization mode itself is deliberately not inferred here.
type PermissionCheck struct {
	Certificates map[string]bool // operation -> granted
	Secrets      map[string]bool // operation -> granted
}

// CheckPermissions probes every permission the demo uses, without changing
// anything in the vault.
func (c *Client) CheckPermissions(ctx context.Context, certName string) (*PermissionCheck, error) {
	perms := &PermissionCheck{
		Certificates: make(map[string]bool),
		Secrets:      make(map[string]bool),
	}

	record := func(perm map[string]bool, name string, err error) error {
		ok, err := allowed(err)
		if err != nil {
			return fmt.Errorf("permission probe for %s failed: %w", name, err)
		}
		perm[name] = ok
		return nil
	}

	// certificates/get: GetCertificate and GetCertificateOperation.
	_, err := c.certClient.GetCertificate(ctx, certName, "", nil)
	if err := record(perms.Certificates, "Get", err); err != nil {
		return nil, err
	}

	// certificates/create: CreateCertificate and MergeCertificate. The policy has
	// no subject, so an authorized call fails validation with 400 and creates
	// nothing.
	issuer := "Unknown"
	_, err = c.certClient.CreateCertificate(ctx, certName, azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{Name: &issuer},
		},
	}, nil)
	if err == nil {
		return nil, fmt.Errorf("create probe unexpectedly started a CSR on %q; cancel its pending operation", certName)
	}
	if err := record(perms.Certificates, "Create", err); err != nil {
		return nil, err
	}

	// certificates/update: DeleteCertificateOperation. Setting
	// cancellationRequested to false is a no-op on a pending operation and a 404
	// without one, so unlike a cancel it can never discard a CSR.
	keep := false
	_, err = c.certClient.UpdateCertificateOperation(ctx, certName, azcertificates.UpdateCertificateOperationParameter{
		CancellationRequested: &keep,
	}, nil)
	if err := record(perms.Certificates, "Update", err); err != nil {
		return nil, err
	}

	// secrets/get: GetSecret.
	_, err = c.secretClient.GetSecret(ctx, certName, "", nil)
	if err := record(perms.Secrets, "Get", err); err != nil {
		return nil, err
	}

	return perms, nil
}

// allowed interprets a permission probe's result. Key Vault authorizes a request
// before validating or executing it, so a 400, 404 or 409 shows the call got past
// authorization. A 401 or 403 means denied, except for two state errors Key Vault
// also reports as 403 to authorized callers: a disabled object (the secret behind
// a pending CSR) and updating an operation that is not in progress. Any other
// failure says nothing about permissions and is returned.
func allowed(err error) (bool, error) {
	if err == nil {
		return true, nil
	}

	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false, err
	}

	switch respErr.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		msg := strings.ToLower(err.Error())
		return strings.Contains(msg, "disabled") || strings.Contains(msg, "pending status must be in progress"), nil
	default:
		return false, err
	}
}

// Report generates a human-readable permission report.
func (p *PermissionCheck) Report() string {
	report := "Permission Check Results:\n"
	report += "Certificates:\n"
	report += formatPermissions(p.Certificates)
	report += "Secrets:\n"
	report += formatPermissions(p.Secrets)
	return report
}

// formatPermissions formats a permission map as indented lines with status symbols,
// sorted by operation name so the report is stable across runs.
func formatPermissions(perms map[string]bool) string {
	ops := make([]string, 0, len(perms))
	for op := range perms {
		ops = append(ops, op)
	}
	sort.Strings(ops)

	result := ""
	for _, op := range ops {
		status := "✓"
		if !perms[op] {
			status = "✗"
		}
		result += fmt.Sprintf("  %s %s\n", status, op)
	}
	return result
}

// CanRunDemo checks if user has minimum permissions for demo
func (p *PermissionCheck) CanRunDemo() (bool, []string) {
	var missing []string

	if !p.Certificates["Get"] {
		missing = append(missing, "Certificates.Get")
	}
	if !p.Certificates["Create"] {
		missing = append(missing, "Certificates.Create")
	}
	if !p.Certificates["Update"] {
		missing = append(missing, "Certificates.Update")
	}
	if !p.Secrets["Get"] {
		missing = append(missing, "Secrets.Get")
	}

	return len(missing) == 0, missing
}
