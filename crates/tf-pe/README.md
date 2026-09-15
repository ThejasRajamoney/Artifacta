# Artifacta PE Analysis v2

`tf-pe` performs offline static parsing. It never loads the image, resolves an
import, contacts a network service, or makes a malware or safety verdict. A
valid signature proves only that signed bytes and the signer key agree; it does
not prove that a file is safe.

## Worker containment

On Windows the host creates a Job Object after process creation and before it
writes the request to worker stdin. The worker blocks while reading that one
request, so attacker-controlled parsing cannot begin before assignment. Both
process and job memory are limited to `WorkerLimits.memory_bytes` (512 MiB by
default), and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` remains enabled. Failure to
configure or assign the job aborts request delivery and terminates the child.
The worker has no network code.

## Evidence contract

Every record has the request artifact ID and emitted provenance ID. Records are
canonicalized in this strict order; repeated records retain file or table order.

| Kind | Class | Content |
| --- | --- | --- |
| `pe.header` | observed | PE/COFF and optional-header fields |
| `pe.rich_header` | observed | presence, decoded bounded entries, XOR key, checksum context |
| `pe.section` | observed | section geometry, flags, and entropy |
| `pe.import` | observed | normal imports in descriptor/thunk order |
| `pe.imphash` | observed | deterministic pefile-compatible MD5 over canonical imports |
| `pe.delay_import` | observed | bounded delay-load descriptors and thunks |
| `pe.export` | observed | exports and forwarders |
| `pe.resource` | observed | bounded resource leaves |
| `pe.manifest` | observed | bounded embedded RT_MANIFEST text and encoding |
| `pe.version_info` | observed | bounded VS_VERSION_INFO fixed and string metadata tree |
| `pe.debug` | observed | debug entries and bounded CodeView details |
| `pe.tls_callback` | observed | callback VA and image-relative RVA |
| `pe.relocation` | observed | relocation block/entry, type, and target RVA |
| `pe.load_config` | observed | load-config fields plus ASLR, DEP, CFG, and applicable x86 SafeSEH state |
| `pe.runtime_function` | observed | x64 or ARM64 exception/runtime-function entries |
| `pe.clr` | observed | CLR and metadata-root fields |
| `pe.overlay` | observed | post-section offset, size, SHA-256, and certificate-table inclusion note |
| `pe.authenticode` | observed | WIN_CERTIFICATE and bounded CMS/certificate/signer structure |
| `pe.authenticode.verification` | observed | image digest comparison, CMS/timestamp crypto results, chain build, and limitations |
| `pe.authenticode.trust` | unknown | offline publisher trust and revocation classification with explicit limitations |
| `pe.string` | observed | bounded ASCII/UTF-16LE strings |
| `pe.indicator` | inferred | deterministic indicators tied to source strings |

Optional absence is evidence where it affects interpretation (`pe.rich_header`,
`pe.imphash`, `pe.load_config`, `pe.clr`, `pe.overlay`, and Authenticode). A
field with `status: unknown` was not established; it must not be interpreted as
false or invalid.

## Authenticode verification

For SHA-1, SHA-256, SHA-384, and SHA-512 `SpcIndirectDataContent` digests, the
worker calculates the PE image digest while excluding the optional-header
checksum, security-directory entry, and certificate table. It compares the
calculated bytes with the signed digest when that structure is parseable.

On Windows, `CryptVerifyMessageSignature` verifies each bounded CMS signer
against its embedded signer certificate. RFC3161 nested CMS timestamp tokens
are structurally identified and their CMS signature is verified. Classic CMS
countersignature attributes are identified but their cryptographic validity is
left unknown because this implementation does not safely reconstruct the exact
counter-signature input. Embedded issuer/subject links are emitted as bounded
chains.

For a cryptographically valid signer, `CertGetCertificateChain` may classify a
chain against local Windows roots. It is called only with cache-only URL and
revocation flags, disabled AuthRoot auto-update, zero URL timeout, and the CMS
certificate store. Network retrieval is disabled. Cached revocation can establish a revoked result, but a
missing or stale cache remains `unknown`; an offline non-revoked result is not a
claim of current online revocation status. Unsupported algorithms, malformed
timestamp values, unavailable platform APIs, and inconclusive chain states are
explicitly `unknown`.

## Bounds

Request limits are additionally constrained by fixed caps: 96 sections; 4,096
normal and 4,096 delay-import descriptors; 65,536 normal imports, delay imports,
exports, relocations, and runtime functions; 16,384 resource leaves at depth 3;
1 MiB each for manifest, VERSIONINFO, and CodeView payloads; 256 VERSIONINFO
nodes; 1,024 debug entries; 4,096 TLS callbacks; 4,096 Rich entries; 64
WIN_CERTIFICATE entries; 16 MiB per PKCS#7 value; 128 embedded certificates; 64
signers and timestamps; 20,000 strings with at most 1,024 retained characters;
and 10,000 indicators. Reads, arithmetic, DER lengths, and RVA mappings are
checked before access or allocation. IPC record, line, total-byte, wall-time,
stderr, and process-memory limits remain independently enforced.

## Limitations

- Classic CMS countersignature cryptography is unknown; RFC3161 token CMS
  signatures are verified, but timestamp policy and full time-validity semantics
  are not asserted.
- Subject-key-identifier CMS signers are not matched by the Rust structural
  chain builder; Windows CryptoAPI may still verify them.
- Local-root trust is machine-specific and offline. Revocation is conclusive
  only when the local cache reports revocation; otherwise it can remain unknown.
- The local-root chain classification is not a complete WinVerifyTrust
  Authenticode policy or EKU verdict; those policy semantics remain unknown.
- Resource parsing recognizes manifest and VERSIONINFO payloads but is not a
  general resource-schema decoder.
- Rich headers are undocumented Microsoft metadata. Decoding and checksum
  context are observations, not proof of compiler identity or authenticity.
- Overlay data includes a certificate table when that table follows section
  data, and the evidence explicitly states this convention.
- UTF-16LE string extraction outside typed resources intentionally recognizes
  printable ASCII-range code units rather than arbitrary Unicode text.
