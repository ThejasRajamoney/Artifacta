import assert from "node:assert/strict";
import { test } from "node:test";
import { fixture, launchArtifacta } from "./harness.mjs";

const runPrefix = `E2E ${new Date().toISOString().replaceAll(/[:.]/g, "-")}`;

async function visible(locator, message) {
  await locator.waitFor({ state: "visible" });
  assert.equal(await locator.isVisible(), true, message);
}

async function navigate(page, name) {
  await page
    .getByRole("navigation", { name: "Primary navigation" })
    .getByRole("button", { name: new RegExp(name, "i") })
    .click();
}

async function analyzeAuthorized(page, count) {
  const action = page.getByRole("button", {
    name: `Analyze ${count} authorized file${count === 1 ? "" : "s"}`,
  });
  await visible(action, `${count} startup intake offers should reach the UI`);
  await action.click();
}

async function waitForAnalysis(app, originalName) {
  const { page } = app;
  const heading = page.getByRole("heading", { level: 1, name: originalName });
  try {
    await heading.waitFor({ state: "visible", timeout: 120_000 });
  } catch (error) {
    const body = await page
      .locator("body")
      .innerText()
      .catch((failure) => `unavailable: ${failure.message}`);
    throw new Error(
      `${error.message}\nProcess exit code: ${app.child.exitCode}\n` +
        `URL: ${page.url()}\nRenderer body:\n${body}\n` +
        `Page events:\n${app.pageEvents.join("\n")}\n` +
        `Artifacta output:\n${app.output.join("")}`,
    );
  }
  assert.equal(
    await heading.isVisible(),
    true,
    `${originalName} should open as a completed real analysis`,
  );
  await visible(page.getByText(/^complete$/i).first());
}

async function currentCaseSuffix(page) {
  const identity = await page.getByText(/^Case .+ \/ artifact .+$/).innerText();
  const match = /^Case (.+) \/ artifact/i.exec(identity);
  assert.ok(match, `Could not parse case identity from ${identity}`);
  return match[1];
}

async function caseRow(page, identifyingText) {
  await navigate(page, "Cases");
  await visible(page.getByRole("heading", { level: 1, name: "Cases" }));
  const row = page
    .getByRole("article")
    .filter({ hasText: identifyingText })
    .first();
  await visible(row, `Case row containing ${identifyingText} should exist`);
  return row;
}

async function renameCase(page, identifyingText, title) {
  const row = await caseRow(page, identifyingText);
  await row.getByRole("button", { name: "Rename" }).click();
  await page.getByRole("textbox", { name: "New case title" }).fill(title);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await visible(page.getByRole("article").filter({ hasText: title }).first());
  return title;
}

async function openCase(page, title) {
  await navigate(page, "Cases");
  const action = page.getByRole("button", { name: `Open ${title}`, exact: true });
  await visible(action);
  await action.click();
  await visible(page.getByRole("heading", { level: 1, name: title }));
}

async function cleanupCases(page, titles) {
  for (const title of [...titles].reverse()) {
    const rows = page.getByRole("article").filter({ hasText: title });
    await navigate(page, "Cases");
    if ((await rows.count()) === 0) continue;
    const row = rows.first();
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    const dialog = page.getByRole("dialog", {
      name: "Delete case and cleanup data?",
    });
    await visible(dialog);
    await dialog
      .getByRole("button", { name: "Permanently delete case" })
      .click();
    await row.waitFor({ state: "detached" });
  }
}

test("real Tauri WebView2 investigation workflows", { timeout: 300_000 }, async (t) => {
  const app = await launchArtifacta(fixture("02_normal_unsigned.exe"));
  const { page } = app;
  const createdTitles = [];
  try {
    await t.test("exact --analyze intake and clean analysis views", async () => {
      await analyzeAuthorized(page, 1);
      await waitForAnalysis(app, "02_normal_unsigned.exe");

      await visible(page.getByText(/Quick Check \/ policy/));
      await visible(page.getByRole("heading", { name: "Evidence families" }));
      const findingsTab = page.getByRole("tab", { name: /^Findings/ });
      assert.match(await findingsTab.innerText(), /\d+/);
      await findingsTab.click();
      await visible(page.getByText(/Confidence is a deterministic rule-strength score/));

      const evidenceTab = page.getByRole("tab", { name: /^Evidence/ });
      assert.match(await evidenceTab.innerText(), /[1-9]\d*/);
      await evidenceTab.click();
      await visible(page.getByRole("region", { name: "Evidence filters" }));

      await page.getByRole("tab", { name: "Graph" }).click();
      await visible(
        page.getByRole("img", {
          name: /Interactive persisted relationship graph/,
        }),
      );
      await visible(page.getByText(/Accessible entity and relationship list/));

      await page.getByRole("tab", { name: "Chronology" }).click();
      await visible(page.getByText(/Timestamps are persisted artifact/));
      assert.ok(
        (await page.getByRole("tabpanel").getByRole("heading", { level: 2 }).count()) >
          0,
        "Clean fixture should have a persisted chronology event",
      );

      for (const label of [
        "Export JSON",
        "Export HTML",
        "Export JSON + integrity manifest",
        "Export HTML + integrity manifest",
      ]) {
        await visible(page.getByRole("button", { name: label, exact: true }));
      }

      const suffix = await currentCaseSuffix(page);
      const title = `${runPrefix} clean`;
      createdTitles.push(await renameCase(page, suffix, title));
    });

    await t.test("suspicious capability, evidence, graph, notes, bookmarks, and reanalysis", async () => {
      await navigate(page, "New Analysis");
      await app.forwardAnalyze(fixture("43_process_injection.exe"));
      await analyzeAuthorized(page, 1);
      await waitForAnalysis(app, "43_process_injection.exe");
      await visible(page.getByText(/process[- ]injection/i).first());

      const suffix = await currentCaseSuffix(page);
      const title = `${runPrefix} suspicious`;
      createdTitles.push(await renameCase(page, suffix, title));
      await openCase(page, title);

      await page.getByRole("tab", { name: /^Findings/ }).click();
      const processFinding = page
        .getByRole("heading", { level: 2, name: /process[- ]injection/i })
        .first();
      await visible(processFinding);
      const findingCard = page
        .getByRole("article")
        .filter({ has: processFinding })
        .first();
      const evidenceAction = findingCard
        .getByRole("button")
        .filter({ hasText: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/i })
        .first();
      await visible(evidenceAction);
      await evidenceAction.click();
      const evidenceDialog = page.getByRole("dialog");
      await visible(evidenceDialog);
      await visible(
        evidenceDialog
          .getByText(/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/i)
          .first(),
      );
      await visible(evidenceDialog.getByText("Input SHA-256", { exact: true }));
      await evidenceDialog
        .getByRole("button", { name: "Close evidence inspector" })
        .click();

      const actions = page.getByLabel(/Actions for .*process[- ]injection/i).first();
      await actions.getByRole("button", { name: "Bookmark" }).click();
      const bookmarks = page.getByText(/^Bookmarks \/ 1$/);
      await visible(bookmarks);
      await bookmarks.click();
      await page.getByRole("button", { name: "Rename", exact: true }).click();
      await page.getByRole("textbox", { name: "Bookmark label" }).fill("E2E injection finding");
      await page.getByRole("button", { name: "Save", exact: true }).click();
      await visible(page.getByText("E2E injection finding", { exact: true }));

      await actions.getByRole("button", { name: "Add linked note" }).click();
      const note = `${runPrefix} analyst note`;
      await page.getByRole("textbox", { name: "Note", exact: true }).fill(note);
      await page.getByRole("button", { name: "Add note" }).click();
      await visible(page.getByText(note, { exact: true }));

      await page.getByRole("tab", { name: "Graph" }).click();
      await visible(
        page.getByRole("img", {
          name: /Interactive persisted relationship graph/,
        }),
      );
      await page.getByText(/Accessible entity and relationship list/).click();
      await visible(page.getByText(/VirtualAllocEx/i).first());

      await page.getByRole("button", { name: "Reanalyze" }).click();
      await visible(page.getByText(/^complete$/i).first());
      assert.ok(
        (await page.getByRole("combobox", { name: "Analysis run history" }).getByRole("option").count()) >=
          2,
        "Reanalysis should preserve at least two runs",
      );
    });

    await t.test("malformed and valid files remain isolated in one batch", async () => {
      await navigate(page, "New Analysis");
      await app.forwardAnalyze(fixture("07_malformed_pe.exe"));
      await app.forwardAnalyze(fixture("17_msvc_like.exe"));
      await analyzeAuthorized(page, 2);
      await visible(page.getByRole("alert").filter({ hasText: /1 file failed independently/ }));
      await visible(page.getByText("07_malformed_pe.exe", { exact: true }));
      await visible(page.getByText("17_msvc_like.exe", { exact: true }));

      const title = `${runPrefix} post-malformed-good`;
      createdTitles.push(await renameCase(page, "17_msvc_like.exe", title));
      await openCase(page, title);
      await visible(page.getByText(/^complete$/i).first());
    });

    await t.test("good multi-file batch and deterministic 09/10 comparison", async () => {
      await navigate(page, "New Analysis");
      await app.forwardAnalyze(fixture("09_compare_app_v1.exe"));
      await app.forwardAnalyze(fixture("10_compare_app_v2.exe"));
      await analyzeAuthorized(page, 2);
      await waitForAnalysis(app, "09_compare_app_v1.exe");

      const leftTitle = `${runPrefix} compare-09`;
      const rightTitle = `${runPrefix} compare-10`;
      const leftSuffix = await currentCaseSuffix(page);
      createdTitles.push(await renameCase(page, leftSuffix, leftTitle));
      createdTitles.push(await renameCase(page, "10_compare_app_v2.exe", rightTitle));

      await navigate(page, "Compare");
      const selects = page.getByRole("combobox");
      await selects.nth(0).selectOption({ label: `${leftTitle} [complete]` });
      await selects.nth(1).selectOption({ label: `${rightTitle} [complete]` });
      await page.getByRole("button", { name: "Compare cases" }).click();
      await visible(page.getByText(leftTitle, { exact: true }));
      await visible(page.getByText(rightTitle, { exact: true }));
      await visible(page.getByText(/CreateProcessW|WinHttpSendRequest|powershell\.exe/i).first());
      await visible(page.getByRole("heading", { level: 2, name: "findings" }));
    });

    await t.test("case archive state is persisted", async () => {
      const title = `${runPrefix} suspicious`;
      const row = await caseRow(page, title);
      await row.getByRole("button", { name: "Archive" }).click();
      await visible(row.getByText("archived", { exact: true }));
    });
  } finally {
    await cleanupCases(page, createdTitles).catch((error) => {
      console.error(`E2E case cleanup failed: ${String(error)}`);
    });
    await app.stop();
  }
});
