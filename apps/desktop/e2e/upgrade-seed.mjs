import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fixture, launchArtifacta } from "./harness.mjs";

const outputPath = path.resolve(process.env.ARTIFACTA_LIFECYCLE_OUTPUT);
const label = process.env.ARTIFACTA_LIFECYCLE_LABEL || "upgrade";
const app = await launchArtifacta(fixture("43_process_injection.exe"));

async function invoke(command, args = {}) {
  return app.page.evaluate(
    ({ requestedCommand, requestedArgs }) =>
      globalThis.__TAURI_INTERNALS__.invoke(requestedCommand, requestedArgs),
    { requestedCommand: command, requestedArgs: args },
  );
}

try {
  await app.page
    .getByRole("button", { name: "Analyze 1 authorized file" })
    .click();
  await app.page
    .getByRole("heading", { level: 1, name: "43_process_injection.exe" })
    .waitFor({ timeout: 120_000 });
  const cases = await invoke("list_cases");
  const seededCase = cases.find((item) => item.title === "43_process_injection.exe");
  assert.ok(seededCase, "historical application should persist the seeded case");
  const analysis = await invoke("get_case_analysis", { caseId: seededCase.id });
  assert.equal(analysis.run.status, "complete");
  assert.ok(analysis.evidence.length > 0);
  assert.ok(analysis.findings.length > 0);

  let note = null;
  let bookmark = null;
  const findingId = analysis.findings[0]?.id;
  if (findingId) {
    try {
      note = await invoke("create_note", {
        caseId: seededCase.id,
        entityId: null,
        findingId,
        body: `${label} lifecycle note`,
      });
    } catch {}
    try {
      bookmark = await invoke("create_bookmark", {
        caseId: seededCase.id,
        target: { targetType: "finding", targetId: findingId },
        label: `${label} lifecycle bookmark`,
      });
    } catch {}
  }
  let yaraPacks = [];
  try {
    yaraPacks = await invoke("list_yara_packs");
  } catch {}

  const result = {
    label,
    binary: app.binary,
    caseId: seededCase.id,
    artifactSha256: analysis.artifact.sha256,
    evidenceCount: analysis.evidence.length,
    findingCount: analysis.findings.length,
    note,
    bookmark,
    yaraPackCount: yaraPacks.length,
  };
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result));
} finally {
  await app.stop();
}
