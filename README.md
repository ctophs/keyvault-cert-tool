# keyvault-cert-tool

A Go CLI tool for managing certificates in Azure Key Vault, with a focus on certificate chain validation and testing against known Azure PFX bag-order bugs.

## The bug

A certificate created in Key Vault through a CSR and then merged is served back
as a PFX with the **entire chain reversed**: root first, leaf last. The PEM
export of the same certificate is correctly ordered.

| | Position 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Expected | leaf | sub-issuing | issuing | root |
| PFX from Key Vault | root | issuing | sub-issuing | leaf |

- It contradicts Key Vault's own API documentation. `preserveCertOrder` is
  documented as *"Specifies whether the certificate chain preserves its original
  order. The default value is false, which sets the leaf certificate at index
  0"* ([`CreateCertificateParameters`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates#CreateCertificateParameters)).
  For PFX neither setting holds: with the default, omitted or explicit `false`,
  the leaf is at index 3, and with `true` the leaf-first chain that was merged
  still comes back reversed. The PEM export follows the documented order.
- The certificates remain cryptographically valid; only their order is wrong.
- The reversal is in the file itself: `openssl pkcs12 -info` shows the same
  root-first order.
- A PFX **imported** into Key Vault keeps the order it was uploaded with. Only
  certificates created through CSR and merge come out reversed.

**Likely origin: Windows' built-in PKCS#12 export.** Given a leaf-first chain,
it writes the certificates in reverse, and its output matches Azure's file in
every property compared: order, encryption and MAC parameters, layout, and the
Windows CryptoAPI provider attribute on the key. Because Windows also reverses
on load, it explains why imported certificates keep their order. Key Vault's
code is not public, so this is inferred, not confirmed; see
[docs/impact.md](docs/impact.md#likely-origin).

Leaf-first is what TLS expects. TLS 1.2 requires the server certificate first
and each following certificate to certify the one before it
([RFC 5246 §7.4.2](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2));
TLS 1.3 keeps the leaf-first rule but tolerates any CA order
([RFC 8446 §4.4.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2)).
PKCS#12 itself ([RFC 7292](https://www.rfc-editor.org/rfc/rfc7292)) prescribes
no order.

## Who is affected

| Consumer | Affected by default? | Symptom | Fix |
|---|---|---|---|
| Secrets Store CSI Driver, Azure provider v1.8.2 | No | — | keep `constructPEMChain` on (the default) |
| akv2k8s controller-1.8.4 | **Yes**, for CSR-created PFX | `tls.crt` root-first; nginx: `key values mismatch` | PEM cert. `chainOrder: ensureserverfirst` fixes CSR-created certificates but breaks imported ones |
| PFX → PEM via `openssl pkcs12`, for nginx, Caddy or Go servers | **Yes** | server refuses to start: `key values mismatch` / `private key does not match public key` | PEM cert, or extract the leaf first (below) |
| go-pkcs12 `DecodeChain` | **Yes** | Root CA returned as the leaf | PEM cert |
| OpenSSL or Python `cryptography` servers | Partly | CA certificates sent in reversed order; modern clients accept it | PEM cert |
| Java 25, .NET 10, Azure SDK for Go | No | — | — |

Test details, versions and the likely origin of the bug are in
[docs/impact.md](docs/impact.md).

### Workarounds

**New certificates:** create them with the PEM content-type. Every consumer
above then gets a correctly ordered chain, with no per-tool settings.

**Existing PFX certificates:** extract the leaf first when converting (Azure
exports use an empty password):

```bash
openssl pkcs12 -in cert.pfx -clcerts -nokeys -passin pass: -out fullchain.pem   # leaf
openssl pkcs12 -in cert.pfx -cacerts -nokeys -passin pass: >> fullchain.pem     # CAs
openssl pkcs12 -in cert.pfx -nocerts -nodes -passin pass: -out key.pem
```

nginx and Go servers, Caddy included, load this and serve the correct leaf. The
CA certificates stay root-first, which modern clients accept.

## Demo Output Example

This demonstrates the Azure PFX bag-order bug. The PFX tests (3-4) show reversed order; PEM tests (1-2) pass:

```
### Test Run 3 Results: PFX, preserveCertOrder=false ###
  ✓ CSR created
  ✓ Signed
  ✓ Merged
  ✓ Downloaded
  ✗ Bag order: incorrect - certificates reversed (but cryptographically valid)
    Actual order in PKCS#12:
      [0] Demo Root CA
      [1] Demo Issuing CA
      [2] Demo Sub-Issuing CA
      [3] test-cert

### Test Run 4 Results: PFX, preserveCertOrder=true ###
  ✓ CSR created
  ✓ Signed
  ✓ Merged
  ✓ Downloaded
  ✗ Bag order: incorrect - certificates reversed (but cryptographically valid)
    Actual order in PKCS#12:
      [0] Demo Root CA
      [1] Demo Issuing CA
      [2] Demo Sub-Issuing CA
      [3] test-cert

### Test Run 1 Results: PEM, preserveCertOrder=false ###
  ✓ CSR created
  ✓ Signed
  ✓ Merged
  ✓ Downloaded
  ✓ Chain order: chain order correct (leaf at 0), cryptographic chain valid (4 certs)
    Certificate chain:
      [0] test-cert
      [1] Demo Sub-Issuing CA
      [2] Demo Issuing CA
      [3] Demo Root CA

### Test Run 2 Results: PEM, preserveCertOrder=true ###
  ✓ CSR created
  ✓ Signed
  ✓ Merged
  ✓ Downloaded
  ✓ Chain order: chain order correct (leaf at 0), cryptographic chain valid (4 certs)
    Certificate chain:
      [0] test-cert
      [1] Demo Sub-Issuing CA
      [2] Demo Issuing CA
      [3] Demo Root CA
```

## Features

- **Certificate Signing Requests (CSR)** — Create CSRs directly in Azure Key Vault
- **Certificate Merging** — Merge signed certificates and chains back into Key Vault
- **Chain Validation** — Verify leaf-first certificate order and the signature link between each certificate
- **PEM & PFX Support** — Test both content types with automatic format-specific verification
- **Permission Pre-flight Checks** — Probe required operations before running, on RBAC and Access Policy vaults alike
- **Demo Mode** — Complete end-to-end workflow simulation with local PKI

## Installation

```bash
go install github.com/ctophs/keyvault-cert-tool/cmd/keyvault-cert-tool@latest
```

Or clone and build:
```bash
git clone https://github.com/ctophs/keyvault-cert-tool.git
cd keyvault-cert-tool
go build -o keyvault-cert-tool ./cmd/keyvault-cert-tool/
```

## Requirements

- Go 1.27.1+ (per `go.mod`)
- Azure CLI installed and authenticated (`az login`)
- Key Vault access for the certificate being operated on:
  - **Certificates** — `get` (read the certificate and its pending operation),
    `create` (create the CSR and merge the signed chain) and `update` (cancel a
    pending operation between runs)
  - **Secrets** — read. Required for *every* download, not only PFX. Key Vault
    serves the merged certificate through the secrets endpoint, and that is the
    only place the full chain and the private key are available; the
    certificates endpoint returns the leaf on its own.

  Under RBAC these are covered by **Key Vault Certificates Officer** and
  **Key Vault Secrets User**.

## Usage

### Demo Mode

Runs a complete workflow against a local PKI hierarchy (Root CA → Issuing CA → Sub-Issuing CA) and tests certificate chain ordering:

```bash
# Run all 4 test combinations
keyvault-cert-tool demo \
  --vault <vault-name> \
  --cert-name test-cert \
  --test-all-combinations

# Run single test (PEM)
keyvault-cert-tool demo \
  --vault <vault-name> \
  --cert-name test-cert \
  --content-type pem

# Run single test (PFX with preserveCertOrder flag)
keyvault-cert-tool demo \
  --vault <vault-name> \
  --cert-name test-cert \
  --content-type pfx \
  --preserve-cert-order true
```

`--content-type` accepts `pem` / `pfx` or the full media types
(`application/x-pem-file`, `application/x-pkcs12`). The certificate subject is
derived from `--cert-name` as `CN=<cert-name>`.

**Demo Phases:**

1. **Phase 0** — Permission verification
2. **Phase 1** — Local PKI generation (Root CA → Issuing CA → Sub-Issuing CA, in-memory)
3. **Phases 2-3** — Sequential test runs (configurable content-type and flags)

## Authorization Modes

Azure Key Vault supports multiple authorization models:
- **RBAC** — Role-based access control (Key Vault Certificates Officer, etc.)
- **Access Policies** — Per-secret/certificate explicit permissions
- **Hybrid** — Both modes enabled simultaneously

The pre-flight check probes the data plane, so it works under any of these
without configuration. It tests every permission the demo uses (certificates
`get`, `create` and `update`, secrets `get`) with requests that change nothing
in the vault. It reports which *operations* are permitted rather than
which model granted them — the data plane exposes no signal that distinguishes
RBAC from access policies.

## Architecture

```
cmd/keyvault-cert-tool/
  └── main.go              # CLI entry point (Cobra)

pkg/
  ├── keyvault/
  │   ├── client.go          # Azure SDK integration
  │   ├── permissions.go     # Pre-flight permission checking
  │   ├── pkcs12.go          # PKCS#12 parsing & bag-order validation
  │   └── keyvault_test.go
  ├── pki/
  │   ├── pki.go             # Local CA generation & CSR signing
  │   └── pki_test.go
  └── demo/
      ├── demo.go            # Demo mode orchestration
      └── demo_test.go
```

## Testing

Unit tests cover the chain-validation logic and need no Azure access:

```bash
go test ./...
```

They exercise CA hierarchy generation, CSR signing, PEM decoding, and both the
correct and reversed bag-order paths against a locally generated chain.

Demo mode additionally validates against a live vault:
- CSR creation and signing workflows
- Certificate chain merge operations
- PEM chain order (leaf first)
- PKCS#12 bag order (leaf first)
- Certificate verification and parsing
- That the downloaded certificate is the one the run just merged: each run
  downloads the exact secret version its merge created, and fails unless that
  version contains the leaf it signed. All runs share a certificate name and
  CA hierarchy, so without this a stale "latest" version would pass every check

**Test Combinations:**
1. PEM + preserveCertOrder=false
2. PEM + preserveCertOrder=true
3. PFX + preserveCertOrder=false (detects Azure bug)
4. PFX + preserveCertOrder=true (confirms flag ineffective)

The flag is always sent explicitly, so `false` is tested as an explicit value
rather than as an omitted field.

## Implementation Notes

### Azure SDK Gotchas

- `CreateCertificate()` is synchronous, not async (`BeginCreateCertificate()`)
- Certificate policy requires `X509CertificateProperties.Subject` field
- CSR returned as raw bytes (may not be PEM-wrapped)
- Cannot create new CSR while previous operation is pending (409 Conflict)
- The merged certificate is served from the secrets endpoint in both formats:
  PEM as the private key followed by the chain, PFX as base64-encoded PKCS#12

### Dependencies

- `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates` — Certificate operations
- `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets` — Secret retrieval (all certificate downloads, PEM and PFX)
- `github.com/spf13/cobra` — CLI framework
- `software.sslmate.com/src/go-pkcs12` — PKCS#12 parsing with certificate chain support

## Limitations

- Demo mode creates certificates in Key Vault (not deleted automatically)
- Local PKI is in-memory only (no persistence)
- PKCS#12 parsing requires empty password (no support for password-protected PFX)

## References

- [RFC 7292 — PKCS #12: Personal Information Exchange Syntax v1.1](https://www.rfc-editor.org/rfc/rfc7292) (defines the format; no bag-order rule)
- [RFC 5246 §7.4.2 — TLS 1.2 Server Certificate](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2) (sender certificate first, each certified by the next)
- [RFC 8446 §4.4.2 — TLS 1.3 Certificate](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2) (sender certificate first)
- [Azure Key Vault REST API Documentation](https://learn.microsoft.com/en-us/rest/api/keyvault/)
- [Azure SDK for Go — Key Vault](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/security/keyvault)
