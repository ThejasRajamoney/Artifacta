import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fixtureDirectory, launchArtifacta, workspaceRoot } from "./harness.mjs";

const expectedParserFailures = new Set([
  "07_malformed_pe.exe",
  "15_truncated_header.exe",
  "16_corrupt_directory.exe",
  "37_tls_callbacks.exe",
  "38_load_config.exe",
  "39_relocations.exe",
  "62_directory_oob.exe",
  "63_enormous_counts.exe",
]);
const outputPath = path.resolve(
  process.env.ARTIFACTA_CORPUS_RESULTS ||
    path.join(workspaceRoot, "target", "qualification", "corpus-results.json"),
);
const terminalStatuses = new Set([
  "complete",
  "partial",
  "failed",
  "cancelled",
  "timed_out",
  "resource_limit",
]);
const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function evidenceHas(analysis, kind, needle) {
  const normalized = needle.toLowerCase();
  return analysis.evidence
    .filter((item) => item.kind === kind)
    .some((item) => JSON.stringify(item.value).toLowerCase().includes(normalized));
}

function evidenceCounts(analysis) {
  return analysis.evidence.reduce((counts, item) => {
    counts[item.kind] = (counts[item.kind] || 0) + 1;
    return counts;
  }, {});
}

async function invoke(page, command, args = {}) {
  return page.evaluate(
    ({ command: requestedCommand, args: requestedArgs }) =>
      globalThis.__TAURI_INTERNALS__.invoke(requestedCommand, requestedArgs),
    { command, args },
  );
}

async function navigate(page, name) {
  await page
    .getByRole("navigation", { name: "Primary navigation" })
    .getByRole("button", { name: new RegExp(name, "i") })
    .click();
}

async function clearIntake(page) {
  const action = page.getByRole("button", { name: "Clear intake results" });
  if ((await action.count()) > 0 && (await action.isVisible())) await action.click();
}

async function materializeFixtures(entries, scratch) {
  const fixtures = new Map();
  for (const entry of entries) {
    const storedPath = path.join(fixtureDirectory, entry.file);
    const stored = await readFile(storedPath);
    const bytes = entry.file.endsWith(".hex")
      ? Buffer.from(stored.toString("ascii").trim(), "hex")
      : stored;
    assert.equal(bytes.length, entry.size, `${entry.file} size`);
    assert.equal(sha256(bytes), entry.sha256, `${entry.file} SHA-256`);
    if (entry.file.endsWith(".hex")) {
      // Keep synthetic PE bytes out of antivirus executable-path handling.
      const decodedPath = path.join(scratch, `${entry.file.slice(0, -4)}.bin`);
      await writeFile(decodedPath, bytes);
      fixtures.set(entry.file, { bytes, path: decodedPath });
    } else {
      fixtures.set(entry.file, { bytes, path: storedPath });
    }
  }
  return fixtures;
}

function assertPrimarySemantics(analyses, fixtures) {
  const one = analyses.get("01_signed_selfsigned_valid.exe");
  assert.equal(evidenceHas(one, "pe.authenticode", '"present":true'), true);
  assert.equal(
    evidenceHas(one, "pe.authenticode.verification", '"status":"valid"'),
    true,
  );
  assert.equal(
    one.evidence
      .filter((item) => item.kind === "pe.authenticode.trust")
      .every((item) => item.value.state !== "trusted"),
    true,
  );

  const two = analyses.get("02_normal_unsigned.exe");
  assert.equal(evidenceHas(two, "pe.authenticode", '"present":false'), true);

  const three = analyses.get("03_dotnet_managed.exe.hex");
  assert.equal(evidenceHas(three, "pe.clr", '"present":true'), true);
  assert.equal(evidenceHas(three, "pe.import", "_corexemain"), true);

  const four = analyses.get("04_qt_app.exe");
  for (const value of ["qt5core", "qt5network", "qt5widgets", "createprocessw"])
    assert.equal(evidenceHas(four, "pe.import", value), true, `fixture 04 ${value}`);
  assert.equal(evidenceHas(four, "pe.indicator", "url"), true);

  const five = analyses.get("05_packed_benign.exe");
  assert.equal(
    five.evidence.some(
      (item) =>
        item.kind === "pe.section" &&
        item.value.name === ".packed" &&
        item.value.entropy > 7.5,
    ),
    true,
  );
  assert.equal(JSON.stringify(five.findings).toLowerCase().includes("malware verdict"), false);

  const six = analyses.get("06_malware_like_INERT.exe");
  for (const value of [
    "writeprocessmemory",
    "createremotethread",
    "createservice",
    "winhttp",
    "isdebuggerpresent",
  ])
    assert.equal(evidenceHas(six, "pe.import", value), true, `fixture 06 ${value}`);
  assert.ok(six.findings.length >= 3, "fixture 06 should produce multiple findings");

  const seven = analyses.get("07_malformed_pe.exe");
  assert.notEqual(seven.run.status, "complete");
  assert.ok(seven.run.errorCode, "fixture 07 should persist a worker error code");

  const eight = analyses.get("08_ctf_reversing.exe");
  for (const value of ["correct", "wrong", "flag"])
    assert.equal(evidenceHas(eight, "pe.string", value), true, `fixture 08 ${value}`);
  assert.equal(
    fixtures
      .get("08_ctf_reversing.exe")
      .bytes.includes(Buffer.from("TRIVARNA{traceforge_static_re_fixture}")),
    false,
  );

  const nine = analyses.get("09_compare_app_v1.exe");
  const ten = analyses.get("10_compare_app_v2.exe");
  assert.equal(evidenceHas(nine, "pe.string", "version=1.0"), true);
  assert.equal(evidenceHas(ten, "pe.string", "version=2.0"), true);
  assert.equal(evidenceHas(ten, "pe.import", "winhttpsendrequest"), true);
  assert.equal(evidenceHas(ten, "pe.string", "powershell.exe"), true);
}

const manifest = JSON.parse(await readFile(path.join(fixtureDirectory, "manifest.json"), "utf8"));
assert.equal(manifest.length, 68, "release corpus must contain exactly 68 fixtures");
const scratch = await mkdtemp(path.join(os.tmpdir(), "artifacta-corpus-e2e-"));
const fixtures = await materializeFixtures(manifest, scratch);
const app = await launchArtifacta(fixtures.get(manifest[0].file).path);
const createdCaseIds = [];
const analyses = new Map();
const report = {
  schemaVersion: 1,
  generatedAtUtc: new Date().toISOString(),
  binary: app.binary,
  binarySha256: sha256(await readFile(app.binary)),
  browser: app.cdp.version.Browser,
  appStatus: await invoke(app.page, "app_status"),
  fixtureCount: manifest.length,
  expectedParserFailures: [...expectedParserFailures],
  results: [],
  comparison09To10: null,
  cleanupErrors: [],
  error: null,
};

try {
  for (const [index, entry] of manifest.entries()) {
    if (index > 0) {
      await navigate(app.page, "New Analysis");
      await clearIntake(app.page);
      await app.forwardAnalyze(fixtures.get(entry.file).path);
    }

    const before = await invoke(app.page, "list_cases");
    const beforeIds = new Set(before.map((item) => item.id));
    const action = app.page.getByRole("button", {
      name: "Analyze 1 authorized file",
    });
    const clear = app.page.getByRole("button", { name: "Clear intake results" });
    await action.waitFor({ state: "visible" });
    await action.click();
    await delay(100);

    const deadline = Date.now() + 120_000;
    let created = [];
    let analysis = null;
    let rejectedAtIntake = false;
    while (Date.now() < deadline) {
      const after = await invoke(app.page, "list_cases");
      created = after.filter((item) => !beforeIds.has(item.id));
      assert.ok(created.length <= 1, `${entry.file} created multiple cases`);
      if (created.length === 1) {
        analysis = await invoke(app.page, "get_case_analysis", {
          caseId: created[0].id,
        });
        if (analysis?.run && terminalStatuses.has(analysis.run.status)) break;
      }
      if (created.length === 0 && (await clear.count()) > 0 && (await clear.isVisible())) {
        rejectedAtIntake = true;
        break;
      }
      await delay(100);
    }
    const expectedFailure = expectedParserFailures.has(entry.file);
    if (rejectedAtIntake) {
      assert.equal(expectedFailure, true, `${entry.file} was unexpectedly rejected at intake`);
      const resultRow = app.page
        .getByRole("list", { name: "Intake results" })
        .getByRole("listitem")
        .filter({ hasText: entry.file });
      report.results.push({
        file: entry.file,
        category: entry.category,
        expected: entry.expected,
        expectedSha256: entry.sha256,
        caseId: null,
        artifactId: null,
        artifactKind: null,
        persistedSha256: null,
        persistedSize: null,
        runId: null,
        runStatus: "rejected_at_intake",
        errorCode: await resultRow.innerText(),
        evidenceCount: 0,
        evidenceKinds: {},
        findingCount: 0,
        findingRuleIds: [],
        quickCheckBand: null,
        graphEntities: 0,
        graphEdges: 0,
        chronologyEvents: 0,
        provenanceCount: 0,
      });
      console.log(`[${index + 1}/${manifest.length}] ${entry.file}: rejected safely`);
      continue;
    }
    assert.equal(created.length, 1, `${entry.file} should persist exactly one case`);
    const caseId = created[0].id;
    createdCaseIds.push(caseId);
    assert.ok(analysis?.run, `${entry.file} should reach a terminal analysis run`);
    if (analysis.run.status === "complete") {
      await app.page
        .getByRole("heading", { level: 1, name: analysis.artifact.originalName })
        .waitFor({ state: "visible", timeout: 120_000 });
    } else {
      await clear.waitFor({ state: "visible", timeout: 120_000 });
    }
    analysis = await invoke(app.page, "get_case_analysis", { caseId });
    analyses.set(entry.file, analysis);

    assert.equal(analysis.artifact.sha256, entry.sha256, `${entry.file} persisted SHA-256`);
    assert.equal(analysis.artifact.sizeBytes, entry.size, `${entry.file} persisted size`);
    assert.ok(analysis.run, `${entry.file} should retain a terminal run`);
    report.results.push({
      file: entry.file,
      category: entry.category,
      expected: entry.expected,
      expectedSha256: entry.sha256,
      caseId,
      artifactId: analysis.artifact.id,
      artifactKind: analysis.artifact.kind,
      persistedSha256: analysis.artifact.sha256,
      persistedSize: analysis.artifact.sizeBytes,
      runId: analysis.run.id,
      runStatus: analysis.run.status,
      errorCode: analysis.run.errorCode,
      evidenceCount: analysis.evidence.length,
      evidenceKinds: evidenceCounts(analysis),
      findingCount: analysis.findings.length,
      findingRuleIds: analysis.findings.map((finding) => finding.ruleId),
      quickCheckBand: analysis.quickCheck.band,
      graphEntities: analysis.graph?.entities.length ?? 0,
      graphEdges: analysis.graph?.edges.length ?? 0,
      chronologyEvents: analysis.chronology?.events.length ?? 0,
      provenanceCount: analysis.provenances.length,
    });
    assert.equal(
      analysis.run.status === "complete",
      !expectedFailure,
      `${entry.file} terminal run status (${analysis.run.errorCode ?? "no error code"})`,
    );
    if (!expectedFailure) {
      assert.ok(analysis.provenances.length > 0, `${entry.file} provenance`);
      assert.ok(analysis.graph, `${entry.file} graph projection`);
      assert.ok(analysis.chronology, `${entry.file} chronology projection`);
      assert.ok(analysis.quickCheck, `${entry.file} Quick Check`);
    }
    console.log(
      `[${index + 1}/${manifest.length}] ${entry.file}: ${analysis.run.status} ` +
        `(${analysis.evidence.length} evidence, ${analysis.findings.length} findings)`,
    );
    if (entry.file !== "09_compare_app_v1.exe" && entry.file !== "10_compare_app_v2.exe") {
      await invoke(app.page, "delete_case", { caseId });
      createdCaseIds.pop();
    }
  }

  assertPrimarySemantics(analyses, fixtures);
  const leftCaseId = analyses.get("09_compare_app_v1.exe").case.id;
  const rightCaseId = analyses.get("10_compare_app_v2.exe").case.id;
  const comparison = await invoke(app.page, "compare_cases", { leftCaseId, rightCaseId });
  const comparisonText = JSON.stringify(comparison).toLowerCase();
  assert.equal(comparisonText.includes("winhttpsendrequest"), true);
  assert.equal(comparisonText.includes("powershell.exe"), true);
  report.comparison09To10 = {
    leftCaseId,
    rightCaseId,
    includesWinHttpSendRequest: true,
    includesPowershell: true,
  };
} catch (error) {
  report.error = error instanceof Error ? error.stack || error.message : String(error);
  throw error;
} finally {
  for (const caseId of createdCaseIds.reverse()) {
    try {
      await invoke(app.page, "delete_case", { caseId });
    } catch (error) {
      report.cleanupErrors.push({ caseId, error: String(error) });
    }
  }
  report.completedFixtureCount = report.results.length;
  report.passed = report.error === null && report.cleanupErrors.length === 0;
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  await app.stop();
  await rm(scratch, { force: true, recursive: true, maxRetries: 3 });
}

console.log(
  JSON.stringify({
    passed: report.passed,
    fixtureCount: report.results.length,
    outputPath,
    binarySha256: report.binarySha256,
  }),
);
