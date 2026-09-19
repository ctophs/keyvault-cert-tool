// Package demo provides end-to-end testing of Azure Key Vault certificate workflows.
// It orchestrates CSR creation, signing, merging, and validation using both PEM and PFX formats,
// with an in-memory PKI hierarchy to sign CSRs and test chain ordering.
package demo

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"

	"github.com/ctophs/keyvault-cert-tool/pkg/keyvault"
	"github.com/ctophs/keyvault-cert-tool/pkg/pki"
)

// TestRun represents a single test case configuration and its results.
type TestRun struct {
	ContentType       string // keyvault.ContentTypePEM or keyvault.ContentTypePFX
	PreserveCertOrder bool   // Preserve order flag sent during CSR creation
	Results           TestResults
}

// TestResults records how far a workflow got and what the downloaded chain looked like.
type TestResults struct {
	CSRCreated   bool
	Signed       bool
	Merged       bool
	Downloaded   bool
	OrderCorrect bool
	OrderMessage string
	Chain        []*x509.Certificate // Certificates in the order the download contained them
	Err          error
}

// label returns the short display name for a content type.
func label(contentType string) string {
	if contentType == keyvault.ContentTypePFX {
		return "PFX"
	}
	return "PEM"
}

// planTests resolves the requested flags into the test matrix to execute.
// testAll runs every content-type and preserveCertOrder combination; otherwise
// contentType selects a single run.
func planTests(testAll bool, contentType string, preserveCertOrd bool) ([]TestRun, error) {
	if testAll {
		return []TestRun{
			{ContentType: keyvault.ContentTypePEM, PreserveCertOrder: false},
			{ContentType: keyvault.ContentTypePEM, PreserveCertOrder: true},
			{ContentType: keyvault.ContentTypePFX, PreserveCertOrder: false},
			{ContentType: keyvault.ContentTypePFX, PreserveCertOrder: true},
		}, nil
	}

	if contentType == "" {
		return nil, fmt.Errorf("either --test-all-combinations or --content-type must be specified")
	}

	resolved, err := keyvault.ParseContentType(contentType)
	if err != nil {
		return nil, err
	}

	return []TestRun{{ContentType: resolved, PreserveCertOrder: preserveCertOrd}}, nil
}

// Run executes the complete demo workflow in four phases:
// Phase 0: Verify Key Vault access and permissions
// Phase 1: Generate in-memory PKI hierarchy (Root CA → Issuing CA → Sub-Issuing CA)
// Phase 2-3: Execute test runs with different content-types and flags
// Each test validates certificate chain ordering (positional and cryptographic).
func Run(vaultName, certName string, testAll bool, contentType string, preserveCertOrd bool) error {
	ctx := context.Background()

	// Resolve the test matrix first so bad arguments fail before any network
	// calls or key generation.
	tests, err := planTests(testAll, contentType, preserveCertOrd)
	if err != nil {
		return err
	}

	fmt.Println("=== Phase 0: Verifying Azure Key Vault access ===")
	vaultURL := fmt.Sprintf("https://%s.vault.azure.net/", vaultName)

	client, err := keyvault.NewClient(vaultURL)
	if err != nil {
		return fmt.Errorf("failed to connect to Key Vault: %w", err)
	}

	// Check permissions first
	fmt.Println("Checking permissions...")
	perms, err := client.CheckPermissions(ctx, certName)
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	fmt.Println(perms.Report())

	canRun, missing := perms.CanRunDemo()
	if !canRun {
		return fmt.Errorf("insufficient permissions. missing: %v", missing)
	}
	fmt.Println("✓ All required permissions granted")

	status, err := client.CertificateStatus(ctx, certName)
	if err != nil {
		return fmt.Errorf("failed to check certificate status: %w", err)
	}

	fmt.Printf("Certificate '%s' status: %s\n", certName, status)

	if status == "pending" {
		return fmt.Errorf("certificate has pending CSR - please complete the merge or delete it first")
	}

	if status == "not_found" {
		fmt.Printf("Certificate '%s' will be created\n", certName)
	} else {
		fmt.Printf("Certificate '%s' exists - will create new versions\n", certName)
	}

	// Phase 1: Local PKI simulation
	fmt.Println("\n=== Phase 1: Generating local PKI (Root CA → Issuing CA → Sub-Issuing CA) ===")

	rootCA, err := pki.GenerateRootCA()
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}
	fmt.Printf("Root CA generated: CN=%s\n", rootCA.Cert.Subject.CommonName)

	issuingCA, err := pki.GenerateIssuingCA(rootCA)
	if err != nil {
		return fmt.Errorf("failed to generate issuing CA: %w", err)
	}
	fmt.Printf("Issuing CA generated: CN=%s\n", issuingCA.Cert.Subject.CommonName)

	subIssuingCA, err := pki.GenerateSubIssuingCA(issuingCA)
	if err != nil {
		return fmt.Errorf("failed to generate sub-issuing CA: %w", err)
	}
	fmt.Printf("Sub-Issuing CA generated: CN=%s\n", subIssuingCA.Cert.Subject.CommonName)

	// Phase 2 & 3: Run test workflows
	fmt.Println("\n=== Phase 2 & 3: Running test workflows ===")

	for i := range tests {
		test := &tests[i]
		testNum := i + 1

		fmt.Printf("\n--- Test Run %d: %s, preserveCertOrder=%t ---\n", testNum, label(test.ContentType), test.PreserveCertOrder)

		if err := runTestWorkflow(ctx, client, rootCA, issuingCA, subIssuingCA, certName, test); err != nil {
			test.Results.Err = err
			fmt.Printf("Test Run %d FAILED: %v\n", testNum, err)
		} else {
			fmt.Printf("Test Run %d COMPLETED\n", testNum)
		}

		printTestResults(testNum, test)
	}

	return nil
}

// runTestWorkflow executes a single test: CSR creation, signing, merge, and verification.
// It manages the complete lifecycle for one (content-type, preserveCertOrder) combination.
// Steps:
// 1. Cancel any pending CSR operation
// 2. Create new CSR in Azure Key Vault
// 3. Sign CSR with local CA hierarchy
// 4. Merge signed chain back to Key Vault
// 5. Download and verify (format-specific: PEM order check or PFX bag order check)
func runTestWorkflow(ctx context.Context, client *keyvault.Client, rootCA, issuingCA, subIssuingCA *pki.CA, certName string, test *TestRun) error {
	// A CSR left pending by an earlier run would make CreateCSR fail with 409.
	_ = client.CancelCertificateOperation(ctx, certName)

	csrBytes, err := client.CreateCSR(ctx, certName, &keyvault.CreateCSROptions{
		ContentType:       test.ContentType,
		PreserveCertOrder: test.PreserveCertOrder,
	})
	if err != nil {
		return fmt.Errorf("CSR creation failed: %w", err)
	}
	test.Results.CSRCreated = true

	// Step 2: Parse CSR and sign it
	// CSR is returned as base64 or raw bytes, try to decode as PEM first
	var csrPem *pem.Block
	csrPem, _ = pem.Decode(csrBytes)
	if csrPem == nil {
		// If not PEM, assume raw bytes and wrap in PEM
		csrPem = &pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		}
	}

	chain, err := pki.SignCSR(csrPem.Bytes, subIssuingCA, []*x509.Certificate{issuingCA.Cert}, rootCA)
	if err != nil {
		return fmt.Errorf("CSR signing failed: %w", err)
	}
	test.Results.Signed = true

	// Step 3: Merge certificate back (with full chain including root)
	allCerts := append(chain.Intermediates, chain.Root)
	version, err := client.MergeCertificate(ctx, certName, chain.Leaf, allCerts)
	if err != nil {
		return fmt.Errorf("merge failed: %w", err)
	}
	test.Results.Merged = true

	// Step 4: Download the exact version just merged. Every run shares the
	// certificate name and CA hierarchy, so "latest" could return an earlier run's
	// certificate and still pass every check. The content-type chosen at CSR
	// creation determines the download format and the verification path.
	if test.ContentType == keyvault.ContentTypePFX {
		pfxBytes, err := client.GetCertificatePFX(ctx, certName, version)
		if err != nil {
			return fmt.Errorf("failed to download PFX: %w", err)
		}
		test.Results.Downloaded = true

		pfxInfo, err := keyvault.ParsePKCS12(pfxBytes, "")
		if err != nil {
			return fmt.Errorf("failed to parse PKCS#12: %w", err)
		}

		test.Results.OrderCorrect, test.Results.OrderMessage = pfxInfo.CheckBagOrder()
		test.Results.Chain = pfxInfo.CertChain
	} else {
		pemBytes, err := client.GetCertificatePEM(ctx, certName, version)
		if err != nil {
			return fmt.Errorf("failed to download PEM: %w", err)
		}
		test.Results.Downloaded = true

		certs, err := keyvault.DecodeCertificatesFromPEM(pemBytes)
		if err != nil {
			return fmt.Errorf("failed to decode certificates from PEM: %w", err)
		}

		test.Results.OrderCorrect, test.Results.OrderMessage = pki.VerifyChainOrder(certs)
		test.Results.Chain = certs
	}

	if !slices.ContainsFunc(test.Results.Chain, chain.Leaf.Equal) {
		return fmt.Errorf("downloaded version %s does not contain the leaf merged in this run", version)
	}

	return nil
}

func printTestResults(testNum int, test *TestRun) {
	r := &test.Results
	isPFX := test.ContentType == keyvault.ContentTypePFX

	fmt.Printf("\n### Test Run %d Results: %s, preserveCertOrder=%t ###\n", testNum, label(test.ContentType), test.PreserveCertOrder)

	for _, step := range []struct {
		done bool
		name string
	}{
		{r.CSRCreated, "CSR created"},
		{r.Signed, "Signed"},
		{r.Merged, "Merged"},
		{r.Downloaded, "Downloaded"},
	} {
		if step.done {
			fmt.Printf("  ✓ %s\n", step.name)
		} else {
			fmt.Printf("  ✗ %s\n", step.name)
		}
	}

	if r.Err != nil {
		fmt.Printf("  Status: FAILED\n  Error: %v\n", r.Err)
		return
	}

	symbol := "✓"
	if !r.OrderCorrect {
		symbol = "✗"
	}

	if isPFX {
		fmt.Printf("  %s Bag order: %s\n", symbol, r.OrderMessage)
	} else {
		fmt.Printf("  %s Chain order: %s\n", symbol, r.OrderMessage)
	}

	if len(r.Chain) > 0 {
		if isPFX {
			fmt.Printf("    Actual order in PKCS#12:\n")
		} else {
			fmt.Printf("    Certificate chain:\n")
		}
		for i, cert := range r.Chain {
			fmt.Printf("      [%d] %s\n", i, cert.Subject.CommonName)
		}
	}
}
