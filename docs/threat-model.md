# Artifacta Threat Model

Artifacta is a local-first Windows static-analysis application. It accepts attacker-controlled PE
files and YARA rule packs, stores immutable local copies, runs bounded analyzers, persists evidence,
and exports investigator-selected reports. Inputs may be malformed, adversarial, large within
accepted bounds, or crafted to exploit parser, native-library, WebView, database, or report-reader
defects.

This document describes implemented controls, not a claim that opening an artifact is risk-free.
The operating system, installed Artifacta executable and dependencies, current Windows account,
and correctly administered application directory are assumed trusted. Another process already
running as the same user, an administrator, a compromised OS, and physical/offline attacks are
outside the containment boundary.

## Assets and adversaries

Protected assets include artifact and YARA contents, original acquisition paths, analyst notes,
case history, evidence and findings, report destinations, the integrity of stored objects and the
database, credentials available to the desktop user, and the rest of the local machine. An
attacker may control every byte and file name of an imported artifact or rule pack and may try to
cause code execution, resource exhaustion, path traversal, evidence confusion, unintended egress,
or disclosure through the renderer or an exported report.

Artifacta does not execute or load an artifact as code. Static evidence can still contain hostile
text, URLs, DLL/API names, certificate fields, and rule-authored metadata. Those values remain
untrusted data wherever displayed or exported.

## Trust boundaries

### Desktop host

The Rust/Tauri host is the trusted coordinator. It has the current user's filesystem and database
access, receives local paths from native file dialogs, copies artifacts into the store, constructs
bounded worker requests, validates worker transcripts, applies deterministic rules, and exposes
explicit IPC commands to the renderer. A host compromise is outside worker containment and exposes
all data and authority available to the application user.

Artifact and YARA source paths are data, not command lines. Worker executables are selected with
`current_exe`; artifact and pack paths are serialized through bounded stdin requests. Production
source policy tests reject direct `CreateProcess`, `ShellExecute`, and `LoadLibrary` call sites and
reject artifact-path expressions passed to Rust process constructors or arguments.

### PE and YARA workers

Disposable workers are trusted only during startup. After request delivery they are treated as
potentially compromised parser processes. They receive immutable stored-object paths, expected
hashes, bounded limits, and YARA pack paths when applicable. They return bounded NDJSON over pipes;
the host independently enforces line, byte, record, wall-time, identity, provenance, and transcript
contracts before accepting evidence.

The workers do not receive database handles, renderer handles, case-service objects, report paths,
or original acquisition paths. PE and YARA have parity for Job Object limits, isolated CWD setup,
DLL policy, restricted-token setup, timeout/output handling, and containment tests.

### Renderer and WebView

The renderer is less trusted than the host because it processes attacker-derived display values in
a browser engine. Host projections omit artifact store paths and original acquisition paths. The
renderer can invoke only registered Tauri commands, and the reviewed `main` capability snapshot is
limited to `core:app:default`, `core:event:default`, and `core:window:default` for the `main` Windows
window. No renderer filesystem, shell, HTTP, or updater plugin permission is configured.

The production CSP permits application content and Tauri IPC only for connections:
`connect-src ipc: http://ipc.localhost`. Objects, frames, base-URI changes, and form submission are
disabled. Images may use packaged, asset-protocol, and data sources. Inline styles remain allowed;
inline scripts are not. Capability and CSP snapshots are regression-tested. These controls reduce
but do not eliminate WebView/XSS risk; host command validation remains the authority boundary.

### Database

`traceforge.db` is a local SQLite database under Tauri's application-local-data directory. It
contains case metadata, original acquisition paths, analysis state, evidence, findings, notes,
YARA metadata, and exported report records. SQLite foreign keys are enabled, `trusted_schema` is
disabled, WAL mode is required, synchronous mode is `FULL`, schema versions are checked before
migration, and database invariants are verified at open.

The database and its WAL/SHM files are not encrypted, authenticated, or protected from another
process with the user's filesystem rights. Local tampering or rollback can cause startup failure,
loss, or misleading state. Artifact hashes and relational validation detect specific integrity
failures but are not a cryptographic signature over the complete case database. Backups must treat
the database, WAL, SHM, artifact objects, YARA packs, and notes as one sensitive set.

### Reports

Reports are generated locally as deterministic JSON or static self-contained HTML. Report input
validates case/run/artifact/provenance/evidence relationships. Store paths, original acquisition
paths, and provenance parameters are omitted or redacted; HTML escapes attacker-controlled text,
contains no script, and contains no HTTP(S) references. Report writes use local staging, reject
parent traversal and reparse-point destinations, avoid overwrite by default, hash final bytes, and
coordinate database persistence with file rollback.

For the supported JSON report and manifest schemas, verification checks exact report bytes, rejects
non-contract JSON, and recomputes both the canonical snapshot and every sorted manifest record
digest. The canonical snapshot is compact typed JSON after removing `generated_at` and the complete
self-referential `integrity` object, matching report generation. Static HTML can be checked for exact
bytes and its exact embedded snapshot reference, but it cannot be losslessly reconstructed into the
canonical JSON records; that result is explicitly `unsupported`, not `verified`. These hashes detect
covered changes only. Even when an expected external manifest hash is supplied, verification does
not establish authorship, authenticity, intent, or safety.

An exported report intentionally contains artifact names, hashes, evidence, matched strings,
certificate and rule metadata, analyst-authored context, and findings. It is a portable disclosure
boundary after export. Artifact-derived URLs are inert text in Artifacta's static HTML but may be
made interactive by another viewer or downstream tooling. Recipients and destination ACLs are the
user's responsibility. Artifact bytes are not embedded.

### Updates and installation

The runtime has no updater plugin or update command, and `createUpdaterArtifacts` is false. No
automatic application-update trust channel currently exists. The canonical repository is
`https://github.com/ThejasRajamoney/Artifacta`, the bundle publisher is `Artifacta`, and private security
reports use GitHub Private Vulnerability Reporting. Installers are Authenticode-signed only when a
trusted certificate is configured; otherwise release metadata explicitly marks them unsigned and
publishes SHA-256 checksums. Checksums provide integrity verification but do not establish publisher
identity or replace Authenticode trust. The NSIS bundle blocks version downgrades and includes the
project license.

The NSIS configuration uses the WebView2 `downloadBootstrapper` mode. On systems without the
required runtime, installer/bootstrapper activity may retrieve Microsoft WebView2 components; that
installer-time vendor traffic is distinct from analyzer/runtime egress and must be considered in
offline deployment planning. Artifacta does not validate or control a downstream WebView2
bootstrapper's network behavior.

The Tauri identifier `org.traceforge.desktop` is deliberately retained from the legacy TraceForge
name so existing application-local data and cases remain available after the Artifacta rename.
Changing it would create a new storage identity and can orphan existing cases. Retention also means
that any prior application using the same identifier shares this local-data namespace; installer
identity, publisher, ACLs, and migration provenance must therefore be reviewed before release.

## Artifact and rule storage

Artifact intake accepts regular non-empty files up to 256 MiB. The host copies bytes through a
uniquely named staging file while calculating SHA-256, SHA-1, and MD5, syncs the staged copy, then
persists it without clobbering at `artifacts/objects/<sha256-prefix>/<sha256>`. Existing objects are
accepted only after size and SHA-256 verification. Stored files are marked read-only, paths are
derived from the expected SHA-256, and object resolution/deletion rejects symbolic links and
Windows reparse points. Workers hash before and after analysis to detect substitution during
parsing.

Original source paths and timestamps are retained in database artifact-location records for
forensic context. They are sensitive and are deliberately absent from normal renderer projections
and reports. Read-only is not an ACL boundary: the current user or an administrator can make an
object writable, replace data, or tamper with metadata. Re-verification detects covered changes but
does not prevent them.

Imported YARA source is bounded, staged, hashed, validated in a disposable YARA worker, and stored
under a hash-derived `yara-packs` path. Includes and modules are disabled. Rule source paths stay in
host/worker requests and are excluded from renderer projections and reports. Shared content-addressed
objects are retained until no case references remain; failed deletion is reported as deferred
rather than claimed successful.

## Windows worker containment

Before spawning either worker, the host creates a random per-run working directory beneath
`%LOCALAPPDATA%\Artifacta\worker-scratch`. The Artifacta and worker-scratch roots must be ordinary
directories, not reparse points, and the child receives the per-run directory as its CWD. Cleanup
uses only Artifacta's explicit walker: it recurses through ordinary directories, removes a junction
or symbolic link as a link, and never traverses it. Cleanup is best effort because Windows can
retain open handles and abrupt host termination bypasses destructors.

After process creation and before request bytes are written, the host assigns the worker to an
unnamed Job Object configured with:

- `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` and `ActiveProcessLimit = 1`, preventing child processes;
- per-process and per-job memory limits from the bounded request;
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, terminating a live worker when host ownership ends.

The host stages `worker.exe` and all path-based request inputs in a temporary directory under a
stable AppContainer profile. A trusted broker does not read request stdin. It configures the Job
first, then creates the actual worker with `CreateProcessW` and `STARTUPINFOEXW` attributes for the
Job, the three standard handles, and zero-capability AppContainer security capabilities. Failure
aborts without an unrestricted worker fallback.

At worker entry, before reading stdin, Artifacta removes the CWD from legacy DLL search and calls
`SetDefaultDllDirectories` with only `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` and
`LOAD_LIBRARY_SEARCH_SYSTEM32`. This protects delay-loaded/runtime libraries after worker entry;
Windows necessarily resolves executable startup imports before this code runs.

The actual worker starts with `TokenIsAppContainer = 1`, and all worker-created threads inherit that
process token. No thread token fallback or post-creation process-token replacement exists. The host
clones each request and replaces artifact and YARA pack paths with staged profile-storage paths
before encoding it.

## Egress policy

Artifacta's production application source contains no network-client calls, manifests declare no
direct network-client dependency, renderer capabilities grant no HTTP or shell plugin, and the CSP
does not permit Internet connection targets. Automated source/direct-dependency policy tests guard
those properties. This is an application policy, not proof that every transitive platform library
is incapable of networking and not an OS network boundary. Build/dev tools and cross-platform
Tauri dependency resolution can include network-capable components; the policy tests deliberately
scope themselves to production call sites, direct runtime dependencies, and reviewed capabilities.

PE parsing and YARA-X compilation/scanning contain no intended network operations. Authenticode
chain construction uses cache-only URL/revocation flags and disables AuthRoot auto-update. YARA
includes and modules are disabled. `network_access = false` provenance records this design intent;
it is not enforcement.

Zero-capability AppContainer tokens deny worker network access without persistent Firewall policy.
Windows tests first prove unrestricted TCP and UDP controls can deliver a nonce, then launch the
same canary through the production AppContainer creation routine and prove neither receiver gets a
nonce. The tests query `TokenIsAppContainer` and a zero `TokenCapabilities` count before waiting.

## Automated invariants

Windows containment tests execute TCP and UDP network canaries and query the actual child token.
Structural tests require the documented security-capability, Job-list, and handle-list creation
attributes and prohibit undocumented process-token mutation and thread-token fallbacks.

Desktop security-policy tests enforce the reviewed renderer capability/CSP snapshot, absence of
runtime updater configuration, absence of direct application network-client dependencies and
production client call sites, and absence of artifact-path expressions in process/library-loading
calls. These are deterministic source/configuration invariants. They do not inspect compiled native
code, prove the behavior of every transitive dependency, or provide OS egress denial.

## Residual risks

- A worker exploit can modify accessible profile storage and read system resources allowed to its
  AppContainer identity; staging and AppContainer ACLs are not secure erasure.
- DLL hardening occurs after startup imports; executable-directory ACL and release integrity remain
  essential.
- Job limits do not impose CPU-rate, file-I/O, handle-count, or filesystem quotas.
- Same-user processes can tamper with unencrypted database/store/report data and may race path
  checks; reparse checks and hashes detect covered states but do not replace handle-relative
  filesystem isolation.
- Stale scratch/staging files can remain after open handles, crashes, or power loss. Cleanup never
  claims secure erasure, particularly on SSDs and journaled filesystems.
- Renderer CSP/capabilities reduce impact but WebView, Tauri IPC, dependency, and host-command bugs
  can still expose trusted host authority.
- Reports can disclose sensitive evidence after export and downstream viewers may activate inert
  URLs or interpret data differently.
- Local database/store rollback can present old but internally consistent state; there is no signed
  audit log, hardware-backed key, or remote transparency service.
- There is no runtime update trust channel yet. Installer/bootstrapper and future release-signing
  compromise remain supply-chain risks.
