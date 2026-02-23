const { app, BrowserWindow, ipcMain, dialog, shell, systemPreferences } = require("electron");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const crypto = require("node:crypto");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const { spawn } = require("node:child_process");

let nativeHelperPromise = null;
const transferWriters = new Map();
const APP_PROTOCOL = "valden";
let mainWindow = null;
let pendingActivationPayload = null;

async function hashFileStreaming(filePath) {
  return await new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function normalizeTransferID(input) {
  return String(input || "").trim();
}

async function closeTransferWriter(transferID) {
  const writer = transferWriters.get(transferID);
  if (!writer) {
    return;
  }
  transferWriters.delete(transferID);
  try {
    await writer.handle.sync();
  } catch (_err) {
    // ignore flush errors during cleanup
  }
  try {
    await writer.handle.close();
  } catch (_err) {
    // ignore close errors during cleanup
  }
}

async function closeAllTransferWriters() {
  const ids = Array.from(transferWriters.keys());
  for (const id of ids) {
    await closeTransferWriter(id);
  }
}

function toBufferChunk(chunk) {
  if (Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (chunk instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(chunk));
  }
  if (ArrayBuffer.isView(chunk)) {
    return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  throw new Error("unsupported chunk payload");
}

function parseActivationPayloadFromURL(rawURL) {
  const urlText = String(rawURL || "").trim();
  if (!urlText) {
    return null;
  }

  try {
    const parsed = new URL(urlText);
    if (parsed.protocol !== `${APP_PROTOCOL}:`) {
      return null;
    }

    const action = String(parsed.hostname || parsed.pathname || "")
      .replace(/^\/+/, "")
      .toLowerCase();
    if (action !== "activate") {
      return null;
    }

    const hashParams = new URLSearchParams(String(parsed.hash || "").replace(/^#/, ""));
    const token = String(parsed.searchParams.get("token") || hashParams.get("token") || "").trim();
    if (!token) {
      return null;
    }

    const api = String(parsed.searchParams.get("api") || hashParams.get("api") || "").trim();
    return {
      token,
      api,
      receivedAt: new Date().toISOString(),
      source: urlText
    };
  } catch (_err) {
    return null;
  }
}

function parseActivationPayloadFromArgv(argv) {
  if (!Array.isArray(argv)) {
    return null;
  }
  for (const item of argv) {
    const payload = parseActivationPayloadFromURL(item);
    if (payload) {
      return payload;
    }
  }
  return null;
}

function getLatestInstallerURL(platform, arch) {
  const base = "https://valden.space/downloads";
  if (platform === "win32") {
    return `${base}/VALDEN-latest-x64.exe`;
  }
  if (platform === "darwin") {
    return arch === "arm64" ? `${base}/VALDEN-latest-arm64.dmg` : `${base}/VALDEN-latest-x64.dmg`;
  }
  return "";
}

async function downloadFileWithRedirect(url, destinationPath, redirectsLeft = 5) {
  if (redirectsLeft < 0) {
    throw new Error("too many redirects while downloading update");
  }

  const parsed = new URL(url);
  const transport = parsed.protocol === "https:" ? https : http;

  await fsp.mkdir(path.dirname(destinationPath), { recursive: true });

  await new Promise((resolve, reject) => {
    const request = transport.get(parsed, (response) => {
      const status = Number(response.statusCode || 0);

      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        const redirected = new URL(response.headers.location, parsed).toString();
        downloadFileWithRedirect(redirected, destinationPath, redirectsLeft - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (status !== 200) {
        response.resume();
        reject(new Error(`update download failed: HTTP ${status}`));
        return;
      }

      const file = fs.createWriteStream(destinationPath);
      response.pipe(file);

      file.on("finish", () => {
        file.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });

      file.on("error", (error) => {
        file.destroy();
        reject(error);
      });
    });

    request.on("error", reject);
    request.setTimeout(120000, () => {
      request.destroy(new Error("update download timeout"));
    });
  }).catch(async (error) => {
    try {
      await fsp.rm(destinationPath, { force: true });
    } catch (_err) {
      // ignore cleanup failures
    }
    throw error;
  });
}

function focusMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.focus();
}

function deliverActivationPayload(payload) {
  if (!payload) {
    return;
  }
  pendingActivationPayload = payload;
  if (!mainWindow || mainWindow.isDestroyed()) {
    return;
  }
  mainWindow.webContents.send("valden:activation-payload", payload);
}

function ensureSingleInstalledAppOnMac() {
  if (process.platform !== "darwin" || !app.isPackaged) {
    return false;
  }

  try {
    if (app.isInApplicationsFolder()) {
      return false;
    }

    const moved = app.moveToApplicationsFolder({
      conflictHandler: (conflictType) => {
        // Keep a single VALDEN.app in /Applications by allowing default replacement behavior.
        if (conflictType === "exists" || conflictType === "existsAndRunning") {
          return true;
        }
        return true;
      }
    });

    if (moved) {
      return true;
    }
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("[install] failed to move app to /Applications", error);
  }

  return false;
}

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 920,
    minWidth: 1160,
    minHeight: 760,
    title: "VALDEN",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      sandbox: false,
      nodeIntegration: false,
      devTools: true
    }
  });

  mainWindow = win;
  win.on("closed", () => {
    if (mainWindow === win) {
      mainWindow = null;
    }
  });

  win.loadFile(path.join(__dirname, "renderer", "index.html"));
  return win;
}

function getPermissionsStatus() {
  if (process.platform !== "darwin") {
    return {
      platform: process.platform,
      accessibilityTrusted: false,
      screen: "unsupported"
    };
  }

  let accessibilityTrusted = false;
  let screen = "unknown";

  try {
    accessibilityTrusted = systemPreferences.isTrustedAccessibilityClient(false);
  } catch (_err) {
    accessibilityTrusted = false;
  }

  try {
    screen = systemPreferences.getMediaAccessStatus("screen");
  } catch (_err) {
    screen = "unknown";
  }

  return {
    platform: process.platform,
    accessibilityTrusted,
    screen
  };
}

function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      ...options,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });

    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });

    child.on("error", (err) => {
      reject(err);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} exited with code ${code}: ${stderr || stdout}`));
      }
    });
  });
}

function getNativeSourcePath() {
  return path.join(__dirname, "native", "macos_input.swift");
}

function getNativeBuildDir() {
  return path.join(app.getPath("userData"), "bin");
}

function getNativeHelperPath() {
  return path.join(getNativeBuildDir(), "valden-input");
}

async function ensureNativeHelper() {
  if (process.platform !== "darwin") {
    throw new Error("native input helper is supported only on macOS");
  }

  const buildDir = getNativeBuildDir();
  const buildSourcePath = path.join(buildDir, "macos_input.swift");
  const helperPath = getNativeHelperPath();

  await fsp.mkdir(buildDir, { recursive: true });

  const sourceText = await fsp.readFile(getNativeSourcePath(), "utf8");
  let shouldWriteSource = true;
  try {
    const current = await fsp.readFile(buildSourcePath, "utf8");
    shouldWriteSource = current !== sourceText;
  } catch (_err) {
    shouldWriteSource = true;
  }

  if (shouldWriteSource) {
    await fsp.writeFile(buildSourcePath, sourceText, "utf8");
  }

  let shouldCompile = shouldWriteSource;
  if (!shouldCompile) {
    try {
      const st = await fsp.stat(helperPath);
      shouldCompile = st.size === 0;
    } catch (_err) {
      shouldCompile = true;
    }
  }

  if (shouldCompile) {
    await runProcess("/usr/bin/swiftc", [buildSourcePath, "-O", "-o", helperPath]);
    await fsp.chmod(helperPath, 0o755);
  }

  return helperPath;
}

async function getNativeHelperReady() {
  if (!nativeHelperPromise) {
    nativeHelperPromise = ensureNativeHelper().catch((err) => {
      nativeHelperPromise = null;
      throw err;
    });
  }
  return nativeHelperPromise;
}

function numberOr(defaultValue, input) {
  const value = Number(input);
  if (!Number.isFinite(value)) {
    return defaultValue;
  }
  return value;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function mapInputEventToArgs(inputEvent) {
  const action = String(inputEvent?.action || "").trim();
  switch (action) {
    case "mouse_move": {
      const xNorm = clamp(numberOr(0.5, inputEvent.xNorm), 0, 1);
      const yNorm = clamp(numberOr(0.5, inputEvent.yNorm), 0, 1);
      return ["move-norm", `${xNorm}`, `${yNorm}`];
    }

    case "mouse_down":
    case "mouse_up":
    case "mouse_click": {
      const button = String(inputEvent.button || "left").toLowerCase();
      return [action.replace("mouse_", "mouse-"), button];
    }

    case "mouse_scroll": {
      const dx = Math.round(numberOr(0, inputEvent.dx));
      const dy = Math.round(numberOr(0, inputEvent.dy));
      return ["mouse-scroll", `${dx}`, `${dy}`];
    }

    case "key_down":
    case "key_up": {
      const key = String(inputEvent.key || "").trim().toLowerCase();
      if (!key) {
        throw new Error("key is required");
      }
      return [action.replace("_", "-"), key];
    }

    case "text_input": {
      const text = String(inputEvent.text || "");
      if (!text) {
        throw new Error("text is required");
      }
      return ["text", text.slice(0, 2000)];
    }

    default:
      throw new Error(`unsupported input action: ${action}`);
  }
}

async function runNativeInput(inputEvent) {
  const helperPath = await getNativeHelperReady();
  const args = mapInputEventToArgs(inputEvent);
  await runProcess(helperPath, args);
}

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv) => {
    const payload = parseActivationPayloadFromArgv(argv);
    if (payload) {
      deliverActivationPayload(payload);
    }
    focusMainWindow();
  });
}

app.on("open-url", (event, rawURL) => {
  event.preventDefault();
  const payload = parseActivationPayloadFromURL(rawURL);
  if (payload) {
    deliverActivationPayload(payload);
    focusMainWindow();
  }
});

app.whenReady().then(() => {
  if (ensureSingleInstalledAppOnMac()) {
    return;
  }

  if (app.isPackaged) {
    app.setAsDefaultProtocolClient(APP_PROTOCOL);
  } else if (process.argv[1]) {
    app.setAsDefaultProtocolClient(APP_PROTOCOL, process.execPath, [path.resolve(process.argv[1])]);
  }

  createMainWindow();

  const startupPayload = parseActivationPayloadFromArgv(process.argv);
  if (startupPayload) {
    deliverActivationPayload(startupPayload);
    focusMainWindow();
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", async () => {
  await closeAllTransferWriters();
});

ipcMain.handle("valden:save-json", async (_event, { defaultName, content }) => {
  const { canceled, filePath } = await dialog.showSaveDialog({
    defaultPath: defaultName,
    filters: [{ name: "JSON", extensions: ["json"] }]
  });

  if (canceled || !filePath) {
    return { canceled: true };
  }

  await fsp.writeFile(filePath, content, "utf8");
  return { canceled: false, filePath };
});

ipcMain.handle("valden:get-meta", () => {
  return {
    version: app.getVersion(),
    platform: process.platform,
    arch: process.arch
  };
});

ipcMain.handle("valden:self-update", async () => {
  const platform = process.platform;
  const arch = process.arch;
  const installerURL = getLatestInstallerURL(platform, arch);
  if (!installerURL) {
    return { ok: false, error: `Автообновление не поддерживается для ${platform}/${arch}` };
  }

  if (platform === "win32") {
    const tempDir = path.join(app.getPath("temp"), "VALDEN");
    const installerPath = path.join(tempDir, `VALDEN-Setup-latest-${Date.now()}.exe`);

    try {
      await downloadFileWithRedirect(installerURL, installerPath);
      const child = spawn(installerPath, [], {
        detached: true,
        stdio: "ignore",
        windowsHide: false
      });
      child.unref();
      setTimeout(() => {
        app.quit();
      }, 300);
      return {
        ok: true,
        mode: "installer-started",
        installerPath,
        url: installerURL
      };
    } catch (error) {
      try {
        await shell.openExternal(installerURL);
      } catch (_openErr) {
        // ignore fallback failure
      }
      return {
        ok: false,
        error: `Не удалось запустить автообновление: ${error.message}`,
        url: installerURL
      };
    }
  }

  await shell.openExternal(installerURL);
  return {
    ok: true,
    mode: "external-opened",
    url: installerURL
  };
});

ipcMain.handle("valden:consume-pending-activation", () => {
  const payload = pendingActivationPayload;
  pendingActivationPayload = null;
  return payload;
});

ipcMain.handle("valden:open-external", async (_event, url) => {
  await shell.openExternal(url);
  return { ok: true };
});

ipcMain.handle("valden:open-path", async (_event, filePath) => {
  const target = String(filePath || "").trim();
  if (!target) {
    return { ok: false, error: "path is required" };
  }
  const openErr = await shell.openPath(target);
  if (openErr) {
    return { ok: false, error: openErr };
  }
  return { ok: true };
});

ipcMain.handle("valden:file-hash", async (_event, filePath) => {
  const target = String(filePath || "").trim();
  if (!target) {
    return { ok: false, error: "file_path is required" };
  }
  try {
    const stat = await fsp.stat(target);
    if (!stat.isFile()) {
      return { ok: false, error: "path is not a file" };
    }
    const sha256 = await hashFileStreaming(target);
    return { ok: true, sha256, size: stat.size };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle("valden:file-select-destination", async (_event, payload) => {
  const transferID = normalizeTransferID(payload?.transferId);
  const suggestedName = String(payload?.suggestedName || "valden-transfer.bin").replace(/[\\/]/g, "_");
  const expectedSizeRaw = Number(payload?.expectedSize);
  const expectedSize = Number.isFinite(expectedSizeRaw) && expectedSizeRaw >= 0 ? expectedSizeRaw : null;

  if (!transferID) {
    return { ok: false, error: "transfer_id is required" };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save incoming file",
    defaultPath: suggestedName
  });

  if (canceled || !filePath) {
    return { ok: true, canceled: true };
  }

  try {
    await closeTransferWriter(transferID);

    let resumeOffset = 0;
    let fileExists = false;
    try {
      const stat = await fsp.stat(filePath);
      fileExists = stat.isFile();
      if (fileExists) {
        resumeOffset = stat.size;
      }
    } catch (_err) {
      fileExists = false;
      resumeOffset = 0;
    }

    const handle = await fsp.open(filePath, fileExists ? "r+" : "w+");
    if (!fileExists) {
      await handle.truncate(0);
    }

    if (expectedSize !== null && resumeOffset > expectedSize) {
      await handle.truncate(0);
      resumeOffset = 0;
    }

    transferWriters.set(transferID, {
      transferID,
      filePath,
      handle,
      bytesWritten: resumeOffset,
      expectedSize
    });

    return {
      ok: true,
      canceled: false,
      transferId: transferID,
      filePath,
      resumeOffset,
      expectedSize
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle("valden:file-get-resume-offset", async (_event, payload) => {
  const transferID = normalizeTransferID(payload?.transferId);
  if (!transferID) {
    return { ok: false, error: "transfer_id is required" };
  }
  const writer = transferWriters.get(transferID);
  if (!writer) {
    return { ok: true, resumeOffset: 0 };
  }
  return { ok: true, resumeOffset: writer.bytesWritten, filePath: writer.filePath };
});

ipcMain.handle("valden:file-write-chunk", async (_event, payload) => {
  const transferID = normalizeTransferID(payload?.transferId);
  const offset = Number(payload?.offset);
  if (!transferID) {
    return { ok: false, error: "transfer_id is required" };
  }
  if (!Number.isFinite(offset) || offset < 0) {
    return { ok: false, error: "offset is required" };
  }

  const writer = transferWriters.get(transferID);
  if (!writer) {
    return { ok: false, error: "transfer writer not found" };
  }
  if (offset !== writer.bytesWritten) {
    return {
      ok: false,
      error: "unexpected offset",
      expectedOffset: writer.bytesWritten
    };
  }

  try {
    const chunk = toBufferChunk(payload?.chunk);
    if (chunk.length === 0) {
      return { ok: true, bytesWritten: writer.bytesWritten };
    }
    await writer.handle.write(chunk, 0, chunk.length, offset);
    writer.bytesWritten += chunk.length;
    return {
      ok: true,
      bytesWritten: writer.bytesWritten
    };
  } catch (err) {
    return { ok: false, error: err.message, expectedOffset: writer.bytesWritten };
  }
});

ipcMain.handle("valden:file-finalize", async (_event, payload) => {
  const transferID = normalizeTransferID(payload?.transferId);
  if (!transferID) {
    return { ok: false, error: "transfer_id is required" };
  }

  const writer = transferWriters.get(transferID);
  if (!writer) {
    return { ok: false, error: "transfer writer not found" };
  }

  const { filePath, expectedSize } = writer;
  try {
    await writer.handle.sync();
    await writer.handle.close();
    transferWriters.delete(transferID);

    const stat = await fsp.stat(filePath);
    const sha256 = await hashFileStreaming(filePath);

    if (expectedSize !== null && stat.size !== expectedSize) {
      return {
        ok: false,
        error: "size mismatch",
        filePath,
        size: stat.size,
        expectedSize,
        sha256
      };
    }

    return {
      ok: true,
      filePath,
      size: stat.size,
      expectedSize,
      sha256
    };
  } catch (err) {
    await closeTransferWriter(transferID);
    return { ok: false, error: err.message, filePath };
  }
});

ipcMain.handle("valden:file-abort", async (_event, payload) => {
  const transferID = normalizeTransferID(payload?.transferId);
  if (!transferID) {
    return { ok: false, error: "transfer_id is required" };
  }
  try {
    await closeTransferWriter(transferID);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle("valden:get-permissions-status", () => {
  return getPermissionsStatus();
});

ipcMain.handle("valden:prompt-accessibility", () => {
  if (process.platform !== "darwin") {
    return { ok: false, reason: "unsupported-platform" };
  }

  const trusted = systemPreferences.isTrustedAccessibilityClient(true);
  return {
    ok: trusted,
    trusted
  };
});

ipcMain.handle("valden:open-permissions-settings", async (_event, kind) => {
  if (process.platform !== "darwin") {
    return { ok: false, reason: "unsupported-platform" };
  }

  const map = {
    accessibility: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
    screen: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
  };
  const target = map[kind] || map.accessibility;
  await shell.openExternal(target);
  return { ok: true };
});

ipcMain.handle("valden:inject-input", async (_event, inputEvent) => {
  if (process.platform !== "darwin") {
    return { ok: false, error: "unsupported-platform" };
  }

  const perms = getPermissionsStatus();
  if (!perms.accessibilityTrusted) {
    return { ok: false, error: "accessibility-not-granted" };
  }

  try {
    await runNativeInput(inputEvent);
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: err.message
    };
  }
});
