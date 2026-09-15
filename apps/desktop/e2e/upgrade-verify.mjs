import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fixture, launchArtifacta } from "./harness.mjs";

const seed = JSON.parse(
  await readFile(path.resolve(process.env.ARTIFACTA_LIFECYCLE_SEED), "utf8"),
);
const app = await launchArtifacta(fixture("12_pe64_minimal.exe"));

async function invoke(command, args = {}) {
  return app.page.evaluate(
    ({ requestedCommand, requestedArgs }) =>
      globalThis.__TAURI_INTERNALS__.invoke(requestedCommand, requestedArgs),
    { requestedCommand: command, requestedArgs: args },
  );
}

try {
  const analysis = await invoke("get_case_analysis", { caseId: seed.caseId });
  assert.ok(analysis, "seeded historical case should survive upgrade");
  assert.equal(analysis.artifact.sha256, seed.artifactSha256);
  assert.ok(analysis.evidence.length >= seed.evidenceCount);
  assert.ok(analysis.findings.length >= seed.findingCount);
  if (seed.note) {
    const notes = await invoke("list_notes", { caseId: seed.caseId });
    assert.ok(notes.some((item) => item.id === seed.note.id && item.body === seed.note.body));
  }
  if (seed.bookmark) {
    const bookmarks = await invoke("list_bookmarks", { caseId: seed.caseId });
    assert.ok(bookmarks.some((item) => item.id === seed.bookmark.id));
  }
  const yaraPacks = await invoke("list_yara_packs");
  assert.ok(yaraPacks.length >= seed.yaraPackCount);
  console.log(
    JSON.stringify({
      label: seed.label,
      casePreserved: true,
      evidenceCount: analysis.evidence.length,
      findingCount: analysis.findings.length,
      notePreserved: seed.note ? true : "not supported by source version",
      bookmarkPreserved: seed.bookmark ? true : "not supported by source version",
      yaraPackCount: yaraPacks.length,
    }),
  );
} finally {
  await app.stop();
}
