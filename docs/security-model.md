# Security Model

## Local-First Architecture

Artifacta is a local-first application. All data -- artifacts, cases, evidence,
findings, notes, and reports -- is stored on your local filesystem. There is no
cloud backend, no remote database, and no account system.

## No Network During Analysis

Artifacta's production application contains no network client calls. The CSP does
not permit Internet connection targets. Renderer capabilities grant no HTTP or
shell plugin. During analysis, no data leaves your machine.

This application policy is enforced by automated source and dependency tests. PE and YARA workers
also run in zero-capability Windows AppContainers, which deny worker network access at the OS token
boundary. The trusted desktop host is not an AppContainer process.

## Worker Sandboxing

Artifacta uses disposable workers for PE parsing and YARA scanning. Workers are
treated as potentially compromised after request delivery. Containment includes:

### Job Objects

The trusted broker creates each worker in an unnamed Windows Job Object with:

- **Single-process limit** -- `ActiveProcessLimit = 1` prevents child processes
- **Memory limits** -- Per-process and per-job memory limits from the bounded request
- **Kill-on-close** -- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates workers when
  the host ownership ends

### AppContainer Tokens

Workers are created with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and stable profiles named
`Artifacta.tf-pe.worker` and `Artifacta.tf-yara.worker`:

- `TokenIsAppContainer = 1` applies to the process and every worker thread
- The capability list is empty
- The worker receives no ordinary-user token replacement or thread impersonation fallback
- TCP and UDP behavior tests verify that a local receiver gets no sandbox nonce

### DLL Restrictions

At worker entry, before reading any input:

- The CWD is removed from the legacy DLL search path
- `SetDefaultDllDirectories` is called with only `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`
  and `LOAD_LIBRARY_SEARCH_SYSTEM32`

This protects against DLL hijacking through the working directory.

### Worker Isolation

Before broker launch, the host copies the executable and every path-based request input into a
temporary directory under the relevant AppContainer profile folder. Workers receive:

- Read-only staged artifact paths (not original acquisition paths)
- Expected hashes for input verification
- Bounded limits (memory, time, output size)
- YARA pack paths when applicable

Workers do **not** receive:

- Database handles
- Renderer handles
- Case service objects
- Report paths
- Original acquisition paths

## OS-Enforced Worker Network Denial

The broker uses documented `CreateProcessW`/`STARTUPINFOEXW` attributes to create the worker as a
zero-capability AppContainer from its first instruction. There is no unrestricted worker fallback.
Behavior tests use the production creation routine for TCP and UDP controls, query the child token
before waiting, and verify that sandbox receivers obtain no nonce.

## Code Signing Status

Artifacta releases are currently **unsigned**. The release tooling explicitly
marks the installer as `UNSIGNED` and does not simulate signing.

Unsigned status means:

- No cryptographic proof of publisher identity
- Windows SmartScreen may warn on execution
- Supply-chain integrity depends on checksum verification and distribution trust

## Automated Security Tests

The test suite enforces:

- Renderer capability and CSP snapshot
- Absence of runtime updater configuration
- Absence of direct application network-client dependencies
- Absence of production network client call sites
- Absence of artifact-path expressions in process/library-loading calls
- Worker containment (AppContainer token/capabilities, TCP and UDP denial, Job limits, DLL hardening)

These are deterministic source/configuration invariants. They do not inspect
compiled native code or prove the behavior of every transitive dependency.

## How to Report Vulnerabilities

See [SECURITY.md](../SECURITY.md) for vulnerability reporting procedures.

Do not open public issues for vulnerabilities that could lead to code execution,
sandbox escape, evidence disclosure, or other security impacts. Use GitHub
Private Vulnerability Reporting for confidential disclosure.
