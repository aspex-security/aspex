#!/usr/bin/env node
// Postinstall: download the correct prebuilt binary for this platform from GitHub Releases.

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { createGunzip } = require("zlib");
const { pipeline } = require("stream");

const VERSION = require("./package.json").version;
const REPO = "aspex-security/aspex";
const BIN_DIR = path.join(__dirname, "bin");
const BIN_NAME = process.platform === "win32" ? "onyx-mcp-scan.exe" : "onyx-mcp-scan";
const BIN_PATH = path.join(BIN_DIR, BIN_NAME);

function platformTarget() {
  const p = process.platform;
  const a = process.arch;
  const map = {
    "darwin-arm64": "darwin_arm64",
    "darwin-x64": "darwin_amd64",
    "linux-x64": "linux_amd64",
    "linux-arm64": "linux_arm64",
    "win32-x64": "windows_amd64",
  };
  const key = `${p}-${a}`;
  const target = map[key];
  if (!target) throw new Error(`Unsupported platform: ${key}`);
  return target;
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const follow = (u) => {
      https.get(u, { headers: { "User-Agent": "onyx-mcp-scan-installer" } }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Download failed: HTTP ${res.statusCode} for ${u}`));
        }
        const out = fs.createWriteStream(dest);
        pipeline(res, out, (err) => (err ? reject(err) : resolve()));
      }).on("error", reject);
    };
    follow(url);
  });
}

async function install() {
  const target = platformTarget();
  const ext = process.platform === "win32" ? ".zip" : ".tar.gz";
  const assetName = `onyx-mcp-scan_${target}${ext}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });

  const archivePath = path.join(BIN_DIR, assetName);
  console.log(`Downloading onyx-mcp-scan v${VERSION} for ${target}...`);

  try {
    await downloadFile(url, archivePath);
  } catch (e) {
    console.error(`Failed to download binary: ${e.message}`);
    console.error(`You can manually download from: https://github.com/${REPO}/releases`);
    process.exit(1);
  }

  // Extract.
  if (process.platform === "win32") {
    execSync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${BIN_DIR}' -Force"`, { stdio: "inherit" });
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${BIN_DIR}" --strip-components=0`, { stdio: "inherit" });
  }

  fs.unlinkSync(archivePath);

  const extracted = path.join(BIN_DIR, process.platform === "win32" ? "onyx-mcp-scan.exe" : "onyx-mcp-scan");
  if (extracted !== BIN_PATH) {
    fs.renameSync(extracted, BIN_PATH);
  }

  if (process.platform !== "win32") {
    fs.chmodSync(BIN_PATH, 0o755);
  }

  console.log("onyx-mcp-scan installed successfully.");
}

install().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
