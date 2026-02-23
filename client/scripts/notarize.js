const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { notarize } = require("@electron/notarize");

function isTruthy(value) {
  if (!value) {
    return false;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

function normalizePemFromEnv(rawValue) {
  if (!rawValue) {
    return null;
  }

  const value = String(rawValue).trim();
  if (!value) {
    return null;
  }

  if (value.includes("BEGIN PRIVATE KEY")) {
    return value.endsWith("\n") ? value : `${value}\n`;
  }

  try {
    const decoded = Buffer.from(value, "base64").toString("utf8").trim();
    if (decoded.includes("BEGIN PRIVATE KEY")) {
      return decoded.endsWith("\n") ? decoded : `${decoded}\n`;
    }
  } catch (error) {
    // ignore invalid base64 payloads
  }

  return null;
}

function resolveApiKeyFile() {
  const explicitPath = process.env.APPLE_API_KEY_PATH || process.env.APPLE_API_KEY_FILE;
  if (explicitPath && fs.existsSync(explicitPath)) {
    return { keyPath: explicitPath, cleanup: null };
  }

  const apiKeyValue = process.env.APPLE_API_KEY;
  if (apiKeyValue && fs.existsSync(apiKeyValue)) {
    return { keyPath: apiKeyValue, cleanup: null };
  }

  const pem =
    normalizePemFromEnv(process.env.APPLE_API_KEY) || normalizePemFromEnv(process.env.APPLE_API_KEY_B64);
  if (!pem) {
    return null;
  }

  const keyId = process.env.APPLE_API_KEY_ID || crypto.randomBytes(6).toString("hex");
  const keyPath = path.join(os.tmpdir(), `AuthKey_${keyId}.p8`);
  fs.writeFileSync(keyPath, pem, { mode: 0o600 });

  return {
    keyPath,
    cleanup: () => {
      try {
        fs.rmSync(keyPath, { force: true });
      } catch (error) {
        // ignore cleanup errors
      }
    }
  };
}

async function notarizeWithAppleID(appPath) {
  const appleId = process.env.APPLE_ID;
  const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
  const teamId = process.env.APPLE_TEAM_ID;
  if (!appleId || !appleIdPassword || !teamId) {
    return false;
  }

  await notarize({
    tool: "notarytool",
    appPath,
    appleId,
    appleIdPassword,
    teamId
  });
  return true;
}

async function notarizeWithAPIKey(appPath) {
  const appleApiKeyId = process.env.APPLE_API_KEY_ID;
  const appleApiIssuer = process.env.APPLE_API_ISSUER;
  if (!appleApiKeyId || !appleApiIssuer) {
    return false;
  }

  const resolved = resolveApiKeyFile();
  if (!resolved) {
    return false;
  }

  try {
    await notarize({
      tool: "notarytool",
      appPath,
      appleApiKey: resolved.keyPath,
      appleApiKeyId,
      appleApiIssuer
    });
    return true;
  } finally {
    if (resolved.cleanup) {
      resolved.cleanup();
    }
  }
}

exports.default = async function notarizing(context) {
  const { electronPlatformName, appOutDir, packager } = context;
  if (electronPlatformName !== "darwin") {
    return;
  }

  const requireNotarization = isTruthy(process.env.REQUIRE_NOTARIZATION);
  const appName = packager.appInfo.productFilename;
  const appPath = path.join(appOutDir, `${appName}.app`);

  if (!fs.existsSync(appPath)) {
    throw new Error(`[notarize] app bundle not found at ${appPath}`);
  }

  try {
    const usedAPIKey = await notarizeWithAPIKey(appPath);
    if (usedAPIKey) {
      // eslint-disable-next-line no-console
      console.log(`[notarize] completed via API key for ${appPath}`);
      return;
    }

    const usedAppleID = await notarizeWithAppleID(appPath);
    if (usedAppleID) {
      // eslint-disable-next-line no-console
      console.log(`[notarize] completed via Apple ID for ${appPath}`);
      return;
    }

    const message =
      "[notarize] missing credentials. Set APPLE_API_KEY(_PATH|_FILE|_B64)+APPLE_API_KEY_ID+APPLE_API_ISSUER or APPLE_ID+APPLE_APP_SPECIFIC_PASSWORD+APPLE_TEAM_ID.";
    if (requireNotarization) {
      throw new Error(message);
    }

    // eslint-disable-next-line no-console
    console.log(`${message} Skipping because REQUIRE_NOTARIZATION is not enabled.`);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("[notarize] failed", error);
    throw error;
  }
};
