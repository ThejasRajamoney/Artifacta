import { fixture, launchArtifacta } from "./harness.mjs";

const startupFixture = fixture(
  process.env.ARTIFACTA_E2E_FIXTURE || "12_pe64_minimal.exe",
);
const app = await launchArtifacta(startupFixture);
try {
  const inspectedCase = process.env.ARTIFACTA_E2E_INSPECT_CASE
    ? await app.page.evaluate(
        (caseId) => globalThis.__TAURI_INTERNALS__.invoke("get_case_analysis", { caseId }),
        process.env.ARTIFACTA_E2E_INSPECT_CASE,
      )
    : null;
  const deletedCases = [];
  for (const caseId of (process.env.ARTIFACTA_E2E_DELETE_CASE || "")
    .split(",")
    .filter(Boolean)) {
    try {
      deletedCases.push(
        await app.page.evaluate(
          (requestedCaseId) =>
            globalThis.__TAURI_INTERNALS__.invoke("delete_case", {
              caseId: requestedCaseId,
            }),
          caseId,
        ),
      );
    } catch (error) {
      deletedCases.push({ caseId, error: String(error) });
    }
  }
  const targets = await (await fetch(`${app.cdp.endpoint}/json/list`)).json();
  const analyze = app.page.getByRole("button", {
    name: "Analyze 1 authorized file",
  });
  if (!process.env.ARTIFACTA_E2E_DELETE_CASE && !process.env.ARTIFACTA_E2E_INSPECT_CASE)
    await analyze.waitFor();
  if (process.env.ARTIFACTA_E2E_ANALYZE === "1") {
    await analyze.click();
    await app.page
      .getByText(/^complete$/i)
      .first()
      .waitFor({ timeout: 30_000 })
      .catch(() => {});
  }
  console.log(
    JSON.stringify(
      {
        binary: app.binary,
        browser: app.cdp.version.Browser,
        cdpEndpoint: app.cdp.endpoint,
        pageTitle: await app.page.title(),
        pageUrl: app.page.url(),
        processExitCode: app.child.exitCode,
        rendererText: await app.page.locator("body").innerText(),
        pageEvents: app.pageEvents,
        artifactaOutput: app.output.join(""),
        inspectedCase,
        deletedCases,
        startupAction:
          process.env.ARTIFACTA_E2E_ANALYZE === "1"
            ? "clicked"
            : (await analyze.count()) > 0
              ? await analyze.innerText()
              : null,
        targets: targets.map(({ id, title, type, url }) => ({
          id,
          title,
          type,
          url,
        })),
      },
      null,
      2,
    ),
  );
} finally {
  await app.stop();
}
