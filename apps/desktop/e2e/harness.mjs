import { spawn } from "node:child_process";
import { access, mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const e2eDirectory = path.dirname(fileURLToPath(import.meta.url));
export const workspaceRoot = path.resolve(e2eDirectory, "../../..");
export const fixtureDirectory = path.join(workspaceRoot, "testfiles");
export const defaultBinary = path.join(
  workspaceRoot,
  "target",
  "release",
  "artifacta-desktop.exe",
);

const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function randomLocalPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => {
        if (error) reject(error);
        else if (port) resolve(port);
        else reject(new Error("Windows did not allocate a local CDP port"));
      });
    });
  });
}

async function waitForCdp(port, child, timeout = 30_000) {
  const endpoint = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `Artifacta exited with code ${child.exitCode} before WebView2 exposed CDP. ` +
          "Ensure no other Artifacta instance is running.",
      );
    }
    try {
      const response = await fetch(`${endpoint}/json/version`, {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok) return { endpoint, version: await response.json() };
      lastError = new Error(`CDP returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(200);
  }
  throw new Error(
    `WebView2 did not expose CDP at ${endpoint}: ${String(lastError)}`,
  );
}

async function waitForTauriPage(browser, timeout = 15_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const page = browser
      .contexts()
      .flatMap((context) => context.pages())
      .find((candidate) => candidate.url().startsWith("http://tauri.localhost"));
    if (page) return page;
    await delay(100);
  }
  throw new Error("CDP connected, but the Tauri WebView target was absent");
}

function waitForExit(child, timeout) {
  if (child.exitCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Process ${child.pid} did not exit within ${timeout} ms`));
    }, timeout);
    const onExit = (code) => {
      cleanup();
      resolve(code);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    function cleanup() {
      clearTimeout(timer);
      child.off("exit", onExit);
      child.off("error", onError);
    }
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

export function fixture(name) {
  return path.join(fixtureDirectory, name);
}

export async function launchArtifacta(startupFixture) {
  if (process.platform !== "win32") {
    throw new Error("The real desktop E2E suite requires Windows");
  }
  const binary = path.resolve(process.env.ARTIFACTA_E2E_BINARY || defaultBinary);
  await Promise.all([access(binary), access(startupFixture)]);
  const port = await randomLocalPort();
  const profile = await mkdtemp(path.join(os.tmpdir(), "artifacta-webview2-e2e-"));
  const output = [];
  const pageEvents = [];
  const child = spawn(binary, ["--analyze", startupFixture], {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS:
        `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
      WEBVIEW2_USER_DATA_FOLDER: profile,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: false,
  });
  child.stdout.on("data", (chunk) => output.push(chunk.toString()));
  child.stderr.on("data", (chunk) => output.push(chunk.toString()));

  let browser;
  try {
    const cdp = await waitForCdp(port, child);
    browser = await chromium.connectOverCDP(cdp.endpoint, {
      isLocal: true,
      noDefaults: true,
      timeout: 15_000,
    });
    const page = await waitForTauriPage(browser);
    page.setDefaultTimeout(15_000);
    page.on("console", (message) =>
      pageEvents.push(`console:${message.type()}:${message.text()}`),
    );
    page.on("pageerror", (error) => pageEvents.push(`pageerror:${error.message}`));
    page.on("crash", () => pageEvents.push("page:crash"));
    await page
      .getByRole("button", { name: "Analyze 1 authorized file" })
      .waitFor();
    return {
      binary,
      browser,
      cdp,
      child,
      output,
      pageEvents,
      page,
      port,
      profile,
      async forwardAnalyze(nextFixture) {
        await access(nextFixture);
        const forwarder = spawn(binary, ["--analyze", nextFixture], {
          cwd: workspaceRoot,
          env: process.env,
          stdio: "ignore",
          windowsHide: false,
        });
        const code = await waitForExit(forwarder, 15_000);
        if (code !== 0) {
          throw new Error(`Forwarded --analyze process exited with code ${code}`);
        }
      },
      async stop() {
        await browser.close().catch(() => {});
        if (child.exitCode === null) {
          child.kill();
          await waitForExit(child, 5_000).catch(() => child.kill("SIGKILL"));
        }
        await rm(profile, { force: true, recursive: true, maxRetries: 3 }).catch(
          () => {},
        );
      },
    };
  } catch (error) {
    await browser?.close().catch(() => {});
    if (child.exitCode === null) child.kill();
    await rm(profile, { force: true, recursive: true, maxRetries: 3 }).catch(
      () => {},
    );
    const diagnostics = output.join("").trim();
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}` +
        (diagnostics ? `\nArtifacta output:\n${diagnostics}` : ""),
    );
  }
}
