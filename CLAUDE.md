# keyvault-cert-tool

A Go-based CLI tool for interacting with Azure Key Vault, primarily for certificate workflows (CSR creation, chain merging, bag-order validation).

## Planning & References

- **Read `PLAN.md` at session start** to understand current implementation scope and progress
- PLAN.md documents the demo mode implementation for testing Azure Key Vault certificate handling
- Focus: validating certificate chain order (bag order) and testing the PEM vs PFX content-type behavior

## Known Azure Key Vault Behaviors (Confirmed via Demo)

- **PFX content-type bug:** ✓ CONFIRMED — When using PFX during CSR creation, the downloaded PKCS#12 has **completely reversed bag order**
  - Expected: [leaf, sub-issuing, issuing, root]
  - Actual: [root, issuing, sub-issuing, leaf]
  - Total reversal, not partial swap
  - Opposite of leaf-first order (required by TLS, RFC 5246 §7.4.2 / RFC 8446 §4.4.2). PKCS#12 (RFC 7292) prescribes no bag order, positional consumers get the root as leaf: go-pkcs12 DecodeChain, and — most commonly — PFX converted to PEM with openssl pkcs12 (file order), which makes nginx 1.24 refuse to start with 'key values mismatch', and Caddy 2.11 / any stdlib Go server fail in tls.X509KeyPair ('private key does not match public key') (workaround: -clcerts first, then -cacerts; see README); Azure tags the leaf with a matching localKeyID, so key-matching parsers (OpenSSL, Python cryptography, azidentity/MSAL) pick the right leaf but pass the CAs through reversed, e.g. onto the TLS wire (tolerated by OpenSSL/Node clients, forbidden by TLS 1.2). Java 25 and .NET 10 rebuild the chain and are unaffected. Likely origin: Windows PKCS#12 export (CryptoAPI). Tested on the WSL host: .NET Framework 4.8 Export of a leaf-first chain matches Azure's file in every property (order, SHA1 MAC/3DES 2000, layout, localKeyID, Microsoft CSP Name, size); Windows also reverses on load (explains import). Inferred, not confirmed. See README "Real-world impact". Reversal independently confirmed with openssl pkcs12 -info. Do NOT cite RFC 5958 — that is Asymmetric Key Packages
  - Tested with `preserveCertOrder=true` and `false` — flag does NOT fix it
  - Contradicts Microsoft's own API docs: preserveCertOrder "default value is false, which sets the leaf certificate at index 0" (azcertificates CreateCertificateParameters). PFX puts leaf at index 3 with default; true also reversed. Strongest argument that it is a real bug (not a PKCS#12 violation — RFC 7292 has no order rule).
  - Pattern confirmed with 2-level, 3-level chains
- **Secrets Store CSI Driver Azure provider (v1.8.2, driver v1.6.1):** unaffected by default — constructPEMChain=true rebuilds the chain by AKI/SKI, correct for reversed and fixed PFX. Breaks only with constructPEMChain=false or a gap in the middle of the chain (code reading).
- **akv2k8s (controller-1.8.4 = master):** PFX cert → tls.crt root-first → nginx rejects. `chainOrder: ensureserverfirst` = blind rotate of last cert to front: fixes CSR-created certs, BREAKS imported certs (tested). PEM cert → correct order, no option needed. Tested with its own code, not a cluster.
- **Import keeps order:** ✓ TESTED — a PFX imported into Key Vault is re-encoded but keeps its uploaded (leaf-first) order; only CSR+merge certs are reversed.
- **PEM workaround:** ✓ VALIDATED — Using PEM content-type during CSR creation produces correctly-ordered certificate chains
- **Pending CSR state:** operation status is `inProgress` (lowercase i — compare case-insensitively); the backing secret is disabled, so GetSecret returns 403 "not allowed on a disabled secret", which is not a permission failure.
- **Permissions the demo needs:** certificates get/create/update, secrets get. Pre-flight probes all four without side effects (invalid create → 400; update with cancellation_requested=false). Key Vault returns 403 for some state errors (disabled secret; "Pending status must be in progress to allow update"), so not every 403 is a denial.
- **preserveCertOrder flag:** Settable only during CSR creation (CreateCertificate), not during merge; does not fix PFX bag order bug
