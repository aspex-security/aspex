#!/usr/bin/env node
// Postinstall: download the correct prebuilt binary for this platform from GitHub Releases.

const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { pipeline } = require("stream");

const VERSION = require("./package.json").version;
const REPO = "aspex-security/aspex";
const BIN_DIR = path.join(__dirname, "bin");
const BIN_NAME = process.platform === "win32" ? "aspex-scan.exe" : "aspex-scan";
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

const ALLOWED_REDIRECT_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "codeload.github.com"]);
const MAX_REDIRECTS = 5;

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const follow = (u, depth) => {
      if (depth > MAX_REDIRECTS) {
        return reject(new Error(`Too many redirects (max ${MAX_REDIRECTS})`));
      }
      let parsed;
      try { parsed = new URL(u); } catch (_) {
        return reject(new Error(`Invalid redirect URL: ${u}`));
      }
      if (!ALLOWED_REDIRECT_HOSTS.has(parsed.hostname)) {
        return reject(new Error(`Redirect to untrusted host blocked: ${parsed.hostname}`));
      }
      https.get(u, { headers: { "User-Agent": "aspex-scan-installer" } }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          return follow(res.headers.location, depth + 1);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Download failed: HTTP ${res.statusCode} for ${u}`));
        }
        const out = fs.createWriteStream(dest);
        pipeline(res, out, (err) => (err ? reject(err) : resolve()));
      }).on("error", reject);
    };
    follow(url, 0);
  });
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const follow = (u, depth) => {
      if (depth > MAX_REDIRECTS) return reject(new Error(`Too many redirects`));
      let parsed;
      try { parsed = new URL(u); } catch (_) { return reject(new Error(`Invalid URL: ${u}`)); }
      if (!ALLOWED_REDIRECT_HOSTS.has(parsed.hostname)) {
        return reject(new Error(`Redirect to untrusted host blocked: ${parsed.hostname}`));
      }
      https.get(u, { headers: { "User-Agent": "aspex-scan-installer" } }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) return follow(res.headers.location, depth + 1);
        if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      }).on("error", reject);
    };
    follow(url, 0);
  });
}

async function verifyChecksum(filePath, assetName, version) {
  const checksumUrl = `https://github.com/${REPO}/releases/download/v${version}/checksums.txt`;
  let checksumText;
  try {
    checksumText = await fetchText(checksumUrl);
  } catch (e) {
    throw new Error(`Failed to fetch checksums.txt: ${e.message}`);
  }
  const expected = checksumText.split("\n")
    .map((l) => l.trim().split(/\s+/))
    .find(([, name]) => name === assetName);
  if (!expected) throw new Error(`No checksum entry found for ${assetName}`);
  const actual = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  if (actual !== expected[0]) {
    throw new Error(`Checksum mismatch for ${assetName}: expected ${expected[0]}, got ${actual}`);
  }
}

async function install() {
  const target = platformTarget();
  const ext = process.platform === "win32" ? ".zip" : ".tar.gz";
  const assetName = `aspex-scan_${target}${ext}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });

  const archivePath = path.join(BIN_DIR, assetName);
  console.log(`Downloading aspex-scan v${VERSION} for ${target}...`);

  try {
    await downloadFile(url, archivePath);
  } catch (e) {
    console.error(`Failed to download binary: ${e.message}`);
    console.error(`You can manually download from: https://github.com/${REPO}/releases`);
    process.exit(1);
  }

  try {
    await verifyChecksum(archivePath, assetName, VERSION);
  } catch (e) {
    fs.unlinkSync(archivePath);
    console.error(`Checksum verification failed: ${e.message}`);
    process.exit(1);
  }

  if (process.platform === "win32") {
    execSync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${BIN_DIR}' -Force"`, { stdio: "inherit" });
  } else {
    execSync(`tar -xzf "${archivePath}" -C "${BIN_DIR}" --strip-components=0 --no-absolute-names`, { stdio: "inherit" });
  }

  fs.unlinkSync(archivePath);

  // The binary extracted from the archive is named aspex-scan (or aspex-scan.exe on Windows).
  const extracted = path.join(BIN_DIR, BIN_NAME);
  // Guard against Zip Slip: ensure the resolved path is still within BIN_DIR.
  const resolvedExtracted = path.resolve(extracted);
  const resolvedBinDir = path.resolve(BIN_DIR);
  if (!resolvedExtracted.startsWith(resolvedBinDir + path.sep) && resolvedExtracted !== resolvedBinDir) {
    throw new Error(`Extracted binary path escapes BIN_DIR: ${resolvedExtracted}`);
  }
  if (resolvedExtracted !== path.resolve(BIN_PATH)) {
    fs.renameSync(extracted, BIN_PATH);
  }

  if (process.platform !== "win32") {
    fs.chmodSync(BIN_PATH, 0o755);
  }

  console.log("aspex-scan installed successfully.");
}

install().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
