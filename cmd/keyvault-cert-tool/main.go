// Command-line tool for testing Azure Key Vault certificate workflows.
// Supports CSR creation, signing, merging, and chain order validation for both PEM and PFX formats.
package main

import (
	"fmt"
	"os"

	"github.com/ctophs/keyvault-cert-tool/pkg/demo"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keyvault-cert-tool",
	Short: "Azure Key Vault certificate management and validation tool",
	Long: `Test Azure Key Vault certificate workflows including CSR creation,
certificate signing, chain merging, and leaf-first chain order validation.`,
}

// demoCmd: Execute end-to-end certificate workflows with local PKI and Azure Key Vault.
var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run demo: test CSR/merge workflows with Azure Key Vault",
	Long: `Execute complete certificate workflows:
- Create CSR in Azure Key Vault
- Sign with local CA hierarchy
- Merge back to Key Vault
- Validate chain order (PEM: X.509 order, PFX: PKCS#12 bag order)`,
	RunE: runDemo,
}

// Command flags for demo mode.
var (
	vaultName       string // Key Vault name (not full URL)
	certName        string // Certificate name in Key Vault
	testAll         bool   // Run all test combinations (2 content-types × 2 preserve flags = 4 tests)
	contentType     string // Single test content-type: "pem" or "pfx"
	preserveCertOrd bool   // Preserve certificate order flag (passed to Azure Key Vault during CSR creation)
)

func init() {
	rootCmd.AddCommand(demoCmd)

	demoCmd.Flags().StringVar(&vaultName, "vault", "", "Azure Key Vault name (required)")
	demoCmd.Flags().StringVar(&certName, "cert-name", "test-cert", "Certificate name in Key Vault")
	demoCmd.Flags().BoolVar(&testAll, "test-all-combinations", false, "Run all 4 test combinations")
	demoCmd.Flags().StringVar(&contentType, "content-type", "", "pem or pfx (required if not --test-all-combinations)")
	demoCmd.Flags().BoolVar(&preserveCertOrd, "preserve-cert-order", false, "Set preserveCertOrder flag")

	if err := demoCmd.MarkFlagRequired("vault"); err != nil {
		panic(err)
	}
}

// runDemo executes the demo command by delegating to the demo package.
func runDemo(cmd *cobra.Command, args []string) error {
	return demo.Run(vaultName, certName, testAll, contentType, preserveCertOrd)
}

// main is the entry point for the CLI.
func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
