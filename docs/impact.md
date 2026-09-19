# Real-world impact

Detailed results behind the summary in the [README](../README.md#who-is-affected).
Unless noted, tests used certificates created in a live vault through CSR and
merge, whose PFX Key Vault serves reversed (root first, leaf last). Tested
2026-09-19.

## Secrets Store CSI Driver, Azure provider

Microsoft's [Azure Key Vault provider](https://github.com/Azure/secrets-store-csi-driver-provider-azure)
for the [Secrets Store CSI Driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver)
mounts Key Vault certificates as PEM files and can sync them into
`kubernetes.io/tls` secrets. Tested with its own conversion code (provider
v1.8.2, driver v1.6.1) on certificates from a live vault:

| PFX input | `constructPEMChain` | `tls.crt` order | nginx / Go TLS |
|---|---|---|---|
| Azure's reversed PFX | `true` *(default)* | leaf, Sub-Issuing, Issuing, Root | ✓ |
| Azure's reversed PFX | `false` | Root, Issuing, Sub-Issuing, leaf | ✗ `key values mismatch` |
| Leaf-first PFX, as imported | `true` *(default)* | leaf, Sub-Issuing, Issuing, Root | ✓ |

- Unaffected by default. The provider rebuilds the chain from each
  certificate's key-ID links instead of trusting the file order, so the result
  is correct both for CSR-created certificates, which Azure reverses, and for
  imported ones, which keep their order.
- It breaks only if `constructPEMChain` is turned off, or if an intermediate is
  missing from the middle of the chain, in which case it falls back to Azure's
  order. A chain without the root is still rebuilt correctly. (Both from reading
  the code, not tested.)

## azure-key-vault-to-kubernetes (akv2k8s)

[akv2k8s](https://github.com/SparebankenVest/azure-key-vault-to-kubernetes)
syncs Key Vault certificates into Kubernetes `kubernetes.io/tls` secrets. Tested
with its own conversion code (release `controller-1.8.4`, identical to
`master`) on certificates from a live vault:

| Certificate | `chainOrder` | `tls.crt` order | nginx / Go TLS |
|---|---|---|---|
| PFX, created via CSR | *(default)* | Root, Issuing, Sub-Issuing, leaf | ✗ `key values mismatch` |
| PFX, created via CSR | `ensureserverfirst` | leaf, Root, Issuing, Sub-Issuing | ✓ |
| PFX, imported | *(default)* | leaf, Sub-Issuing, Issuing, Root | ✓ |
| PFX, imported | `ensureserverfirst` | Root, leaf, Sub-Issuing, Issuing | ✗ `private key does not match public key` |
| PEM | *(ignored for PEM)* | leaf, Sub-Issuing, Issuing, Root | ✓ |

- With a PFX certificate and no `chainOrder`, nginx rejects the certificate and
  key akv2k8s writes, so ingress-nginx cannot serve the secret.
- `ensureserverfirst` moves the *last* certificate to the front, which is only
  correct for PFX files Key Vault reversed, i.e. certificates created via CSR.
  An imported certificate keeps its uploaded, normally leaf-first order, and
  `ensureserverfirst` moves its root to the front instead. With a mix of both,
  no single `chainOrder` setting works.
- **Recommended:** create the certificate with the PEM content-type. akv2k8s then
  writes a correctly ordered secret with no `chainOrder` setting, however the
  certificate entered Key Vault.

## Parsers and servers

Azure tags the key and the leaf with a matching `localKeyID`, so what breaks
depends on how a consumer pairs the key with its certificate. Tested against
Azure's actual reversed PFX:

| Parser | Leaf picked | CA certificates |
|---|---|---|
| [go-pkcs12](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12) 0.7.3 `DecodeChain` | ✗ **Root CA**, silently, paired with the leaf's key | — |
| Azure SDK for Go (azidentity 1.14, MSAL 1.8) | ✓ matched by public key | leaf moved first, rest in file order |
| OpenSSL 3.6, via Node.js 24 `tls` server | ✓ matched by key | sent on the wire in file order: `leaf, Root, Issuing, Sub-Issuing` |
| Python `cryptography` 48 | ✓ matched by key | returned in file order |
| Java 25 `KeyStore("PKCS12")` | ✓ paired with the key entry | rebuilt leaf-first by `getCertificateChain`; a Java TLS server sends `leaf, Sub-Issuing, Issuing, Root` |
| .NET 10 `X509CertificateLoader` | ✓ `LoadPkcs12` returns the certificate that has the key | `LoadPkcs12Collection` reverses file order, which on Azure's file happens to come out leaf-first; `SslStream` builds the path itself and sends `leaf, Sub-Issuing, Issuing` |

That gives two distinct consequences:

- **Wrong leaf**, for anything that treats the first certificate as the leaf.
  Most commonly this is a PFX converted to PEM with `openssl pkcs12`, which
  keeps file order, so the leaf ends up last. For nginx the conversion is
  unavoidable: it cannot load a PFX at all, only PEM. nginx takes the first certificate
  in `ssl_certificate` as its own, so it refuses to start: `SSL_CTX_use_PrivateKey
  ... key values mismatch` (tested with nginx 1.24). The message blames the key,
  although the key is correct. Caddy 2.11, which also reads only PEM, and any Go
  server using the standard library (`http.ListenAndServeTLS`) load through
  `tls.X509KeyPair`, which fails the same way: `tls: private key does not match
  public key`. go-pkcs12's `DecodeChain` picks the wrong leaf too.
- **Misordered chain on the wire**, for stacks that pass the CA certificates
  through unchanged (OpenSSL, Python `cryptography`). A server built on them
  sends the chain in an order TLS 1.2 forbids. OpenSSL and Node.js clients
  accepted it with only the root trusted, because they build the path from the
  certificates they receive rather than relying on their order. Strict TLS 1.2
  verifiers may not.

Java and .NET are unaffected on both counts: both select the leaf by key and
rebuild the chain before sending it.

## Likely origin

The evidence points to Windows' PKCS#12 export (CryptoAPI, which .NET uses on
Windows).

**Windows reproduces Azure's file.** Exporting a leaf-first chain on Windows
with .NET Framework 4.8 (`X509Certificate2Collection.Export`, which calls
CryptoAPI) produced a file matching Azure's in every property compared:

| Property | Azure | Windows export |
|---|---|---|
| Certificate order | Root, Issuing, Sub-Issuing, leaf | identical |
| MAC | SHA-1, 2000 iterations, 20-byte salt | identical |
| Encryption of key and certificates | 3DES, 2000 iterations | identical |
| Layout | key section, then certificates | identical |
| `localKeyID` on key and leaf | `01 00 00 00` | identical |
| Key attribute `Microsoft CSP Name` | Microsoft Enhanced RSA and AES Cryptographic Provider | identical |
| File size | 5140 bytes | identical |

**The provider attribute is Windows-specific.** `Microsoft CSP Name` names a
Windows CryptoAPI provider. .NET 10 on Linux reproduces the reversed order and
the encryption parameters, but not this attribute, and it places the key after
the certificates.

**It predicts import correctly.** Windows also reverses on load: it read Azure's
root-first file back leaf-first. Loading and then exporting reverses twice,
which matches Key Vault keeping the order of an imported PFX.

The key's GUID `friendlyName` matched too, but only because Windows reused the
name from the input file, so it is not counted as evidence. Key Vault's service
code is not public, so this remains an inference, although a well-supported one.
