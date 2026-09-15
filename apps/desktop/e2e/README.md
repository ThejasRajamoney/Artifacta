# Real Windows desktop E2E

These scripts launch the built `artifacta-desktop.exe`, enable a loopback-only
WebView2 CDP port for that child process, connect with `playwright-core`, and
drive the real Tauri renderer and IPC host. They do not use Vite, jsdom, mocked
IPC, test-only commands, CSP exceptions, or additional Tauri capabilities.

## Run

Build the release application first, close any running Artifacta instance, and
run from the workspace root:

```powershell
npm run e2e:probe
npm run e2e
npm run e2e:corpus
```

`ARTIFACTA_E2E_BINARY` can select another built executable. The default is
`target/release/artifacta-desktop.exe`. `ARTIFACTA_E2E_FIXTURE` can select the
fixture used by the connection probe. The corpus runner writes machine-readable
results to `target/qualification/corpus-results.json`; `ARTIFACTA_CORPUS_RESULTS`
can select another destination.

The harness asks Windows for an available random local port, fixes that port for
the process lifetime, and passes it through
`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`. `WEBVIEW2_USER_DATA_FOLDER` points to a
unique temporary browser profile. Additional fixtures enter through separate
exact `--analyze <path>` launches and the production single-instance forwarding
path, allowing real multi-file intake without exposing paths to the renderer.

## Isolation and limitations

- WebView2 state is isolated in a temporary profile. Tauri's
  `app_local_data_dir()` has no existing override, so the production case store
  cannot be redirected without changing application code. E2E cases receive a
  unique prefix and are deleted through the existing UI in teardown. Do not run
  this suite concurrently with normal Artifacta use.
- The native open and save dialogs are owned by Windows, not the WebView2 DOM,
  and are absent from CDP's target tree. Playwright over CDP cannot select files
  or destinations in them. Intake is still fully covered through the existing
  `--analyze` UI flow. The four report export actions are asserted in the real
  UI, but export completion is intentionally not claimed because the existing
  UI has no non-native destination control or other dialog bypass.
- CDP attachment has lower fidelity than Playwright's native protocol, per the
  Playwright documentation. The suite limits itself to DOM roles, labels, text,
  and ordinary input actions that work reliably in the real WebView2.
- The debug port exists only in the E2E child environment and binds to
  `127.0.0.1`; production configuration and permissions are unchanged.
