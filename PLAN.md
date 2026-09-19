# keyvault-cert-tool: Demo Mode Implementation Plan

## Overview

`keyvault-cert-tool` is a Go CLI for managing certificates in Azure Key Vault with a focus on validation and testing. Demo mode creates a local PKI infrastructure (Root CA → Issuing CA → Sub-Issuing CA) in-memory and uses it to test certificate workflows. It validates certificate chain ordering (bag order) for both PEM and PFX content types, helping identify and verify the workaround for the Azure Key Vault PFX bag-order bug.

## Phase 0: Verify Azure Key Vault Access + Certificate Status

### Authorization Modes
Key Vaults use one of two authorization models:
1. **RBAC Mode** — role-based (Key Vault Certificates Officer, Key Vault Secrets Officer)
2. **Access Policies Mode** — per-secret/cert permissions (Get, List, Create, Update, Merge, Delete)
3. **Hybrid** — both modes can be enabled

**Tool must work with both modes.** Check permissions regardless of which the vault uses.

### Permission Verification (Pre-flight)
Before running demo, verify user has:
- **Certificates:** get (read certificate and operation), create (CSR and merge), update (cancel a pending operation)
- **Secrets:** Get (for every download — PEM and PFX alike; the secrets
  endpoint is the only source of the full chain and the private key)

Test each with actual API calls that change nothing:
- GET /certificates/test-cert → certificates/get
- POST /certificates/test-cert/create with an invalid policy (no subject) → certificates/create
  (an authorized call fails validation with 400; 409 if the name is soft-deleted)
- PATCH /certificates/test-cert/pending with cancellation_requested=false → certificates/update
  (no-op on a pending operation; 404 without one)
- GET /secrets/test-cert → secrets/get

Key Vault also answers some **state errors with 403** to authorized callers, so a 403 is
only a denial if it is not one of these: "not allowed on a disabled secret" (pending CSR),
"Pending status must be in progress to allow update" (operation already completed).

1. Authenticate to Azure (using CLI credentials)
2. Verify permissions (both RBAC and Access Policies) via test API calls
3. Report what's available and what's missing
4. Check certificate "test-cert" status:
   - If doesn't exist → create empty certificate resource → proceed
   - If exists with status **pending/waiting for merge** → ⛔ STOP
     - Inform user: "Certificate has pending CSR. Please complete the merge or delete the certificate first."
     - Exit
   - If exists with status **completed/merged** → ✓ Proceed
     - Inform user: "Certificate already exists (version X). Will create new versions during demo."
4. Exit if any checks fail; proceed to Phase 1 if all pass

## Phase 1: Local PKI Simulation (In-Memory)

- Generate Root CA (self-signed)
  - X.509 v3, subject "CN=Demo Root CA"
  - RSA 2048-bit
  - Keep in memory (no disk writes)
- Generate Issuing CA (signed by Root CA)
  - Subject "CN=Demo Issuing CA"
  - RSA 2048-bit
  - Signed by Root CA private key
  - Keep in memory
- Implement helper function to sign arbitrary CSRs with Issuing CA
- Build chain helper (assemble leaf → issuing → root)

## Phase 2 + 3: Sequential Test Runs

For each test variant, run the complete workflow on certificate "test-cert":

### Test Run 1: PEM, preserveCertOrder=false (default)
```
1. Create CSR (content-type=PEM, preserveCertOrder=false)
2. Download CSR
3. Sign CSR with Issuing CA
4. Build chain: [signed-leaf, issuing-ca, root-ca]
5. Merge chain back to KV
6. Download merged certificate
7. Verify chain order
8. Expected: ✓ CORRECT (leaf at position 0, intermediate at 1, root at 2)
```

### Test Run 2: PEM, preserveCertOrder=true
```
Same as Test Run 1, but with preserveCertOrder=true
Expected: ? (verify it doesn't break PEM behavior)
```

### Test Run 3: PFX, preserveCertOrder=false (default)
```
Same workflow but with content-type=PFX
Expected: ✗ WRONG ORDER (intermediate at position 0, leaf at 1, root at 2)
This reproduces the known Azure bug
```

### Test Run 4: PFX, preserveCertOrder=true
```
Same workflow but with content-type=PFX and preserveCertOrder=true
Expected: ? (test if flag fixes the bug)
```

## Phase 4: Analysis & Reporting

For each test run, analyze downloaded certificate:
- Extract all certificates (leaf, intermediate, root)
- Identify each certificate's position in the chain
- Verify position matches leaf-first order (leaf at 0)
- Report:
  ```
  Test Run 1: PEM, preserveCertOrder=false
    ├── CSR created: ✓
    ├── Signed: ✓
    ├── Merged: ✓
    ├── Downloaded: ✓
    └── Chain order: ✓ CORRECT (leaf at 0, intermediate at 1, root at 2)
  ```

## CLI Usage

```bash
# Run all test combinations
keyvault-cert-tool demo \
  --vault <name> \
  --cert-name test-cert \
  --test-all-combinations

# Run individual test
keyvault-cert-tool demo \
  --vault <name> \
  --cert-name test-cert \
  --content-type [pem|pfx] \
  --preserve-cert-order [true|false]
```

## Expected Outcomes

After demo completes:
1. Confirm PEM content-type works correctly (baseline)
2. Confirm PFX content-type has incorrect bag order (validates known bug)
3. Determine if `preserveCertOrder=true` flag fixes the PFX bug (hypothesis test)
4. Adjust full implementation plan based on findings

## Notes

- Certificate "test-cert" accumulates versions with each test run (no cleanup needed)
- All local PKI operations stay in-memory (no disk artifacts)
- Each test run is independent and sequentially executed
- Results guide final design decisions for full CLI tool

## Azure SDK Implementation Notes

### Key Findings (Validated Against Live API)

**SDK Methods (azcertificates v1.5.0):**
- Use `CreateCertificate()` NOT `BeginCreateCertificate()` — it's synchronous
- Use `MergeCertificate()` NOT `BeginMergeCertificate()`
- Use `DeleteCertificateOperation()` to cancel pending CSRs

**Certificate Policy Requirements:**
- Must include `X509CertificateProperties` with `Subject` field
- A subject is required, not optional; the tool derives it from `--cert-name`
  as `CN=<cert-name>`
- Without it: `BadParameter: Either subjectName or san must be present`

**CSR Format:**
- Returned as raw bytes, not necessarily PEM-encoded
- Must handle both PEM-wrapped and raw byte formats

**Pending Operations:**
- Cannot create new CSR while previous one is `inProgress` (409 Conflict). Azure sends the status as `inProgress`; compare case-insensitively
- Must call `DeleteCertificateOperation()` between test runs
- Use `GetCertificateOperation()` to check status
- While a CSR is pending, the certificate's backing secret is **disabled**: `GetSecret` returns
  403 `Operation get is not allowed on a disabled secret`. That is not a permission failure

**Access Control:**
- A vault may use RBAC, access policies, or both; the tool probes the data plane
  so it works under any of them
- Verified working under RBAC with **Key Vault Certificates Officer** plus
  **Key Vault Secrets User**
- Secrets read access is needed for *every* download, not just PFX — an early
  misdiagnosis here looked like an RBAC failure when it was a missing secrets role
- Operations actually called: GetCertificate, GetCertificateOperation,
  CreateCertificate, MergeCertificate, DeleteCertificateOperation, GetSecret
  (note: no UpdateCertificate)

**Error Handling:**
- 404 CertificateNotFound: Check error message contains `"not found in this key vault"`
- 400 BadParameter: Usually missing required policy fields
- 409 Conflict: Pending operation exists, must cancel first

### Testing Findings

**Test Results (Verified with Raw Byte Inspection):**
- ✓ **Tests 1-2 (PEM):** Correct order — leaf certificate first, then CAs
- ✗ **Tests 3-4 (PFX):** **Completely reversed bag order**
  - Expected: [leaf, sub-issuing, issuing, root]
  - Actual: [root, issuing, sub-issuing, leaf]
  - Total reversal of entire certificate chain
- **Azure PFX Bug Confirmed:** When using PFX content-type, Azure reverses the entire PKCS#12 bag order
- **preserveCertOrder Flag:** Does NOT fix the bug (tested both true and false). The
  flag is always serialized explicitly — omitting it and sending `false` are
  distinct requests, and only the explicit form actually tests the `false` case
- **Root Cause:** The bug manifests identically with 2-level and 3-level chains, indicating systematic reversal in Azure's PKCS#12 serialization
- **Imported PFX:** keeps its uploaded order (re-encoded, leaf-first stays leaf-first). Only CSR + merge certificates are reversed
- **Workaround:** Use PEM content-type during CSR creation for correctly-ordered certificates

### Gotchas to Avoid

1. Don't use `BeginCreateCertificate` — doesn't exist in current SDK
2. Always include Subject in X509CertificateProperties
3. Handle both PEM and raw bytes from CSR
4. Cancel pending ops before creating new CSRs in batch operations
5. Check Access Policies, not just RBAC, for permission issues
6. Don't assume error messages are simple strings — check `.Error()` output carefully
7. Send `PreserveCertOrder` explicitly even when false; a nil pointer omits the
   field, which is a different request than `false`
8. Azure spells "not found" both as prose and as error codes
   (`CertificateNotFound`, `SecretNotFound`) — match both when detecting 404s

### Go crypto/x509 Gotchas

- `MaxPathLen: 0` alone does **not** encode `pathlen:0` — x509 treats it as
  "unset" and omits the constraint. `MaxPathLenZero: true` is required. Parsing a
  certificate built without it yields `MaxPathLen: -1`, confirming the omission.
- Certificate serial numbers must be random. A timestamp-derived serial collides
  for certificates issued within the same second by the same CA.
- `pkcs12.Decode` from the standard library expects exactly two bags and fails on
  chains; `software.sslmate.com/src/go-pkcs12`'s `DecodeChain` handles them.
