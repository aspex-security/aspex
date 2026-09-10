#!/usr/bin/env node
// Postinstall: download the Aspex release archive for this platform from GitHub
// Releases, verify it against checksums.txt, and unpack the five binaries into
// vendor/. The bin/*.js shims exec them. Nothing else is fetched, ever.

"use strict";

const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { pipeline } = require("stream");

const REPO = "aspex-security/aspex";
// ASPEX_VERSION lets a checkout test the installer against a real release
// without editing package.json (which CI sets from the git tag).
const VERSION = process.env.ASPEX_VERSION || require("./package.json").version;
const VENDOR = path.join(__dirname, "vendor");
const BINARIES = ["aspex", "aspex-scan", "aspex-trace", "aspex-attack", "aspex-doctor"];

const ALLOWED_HOSTS = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);
const MAX_REDIRECTS = 5;

function platformTarget() {
  const key = `${process.platform}-${process.arch}`;
  const map = {
    "darwin-arm64": "darwin_arm64",
    "darwin-x64": "darwin_amd64",
    "linux-x64": "linux_amd64",
    "linux-arm64": "linux_arm64",
    "win32-x64": "windows_amd64",
  };
  const target = map[key];
  if (!target) {
    throw new Error(`Unsupported platform ${key}. Prebuilt binaries: https://github.com/${REPO}/releases`);
  }
  return target;
}

function get(url, onResponse, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > MAX_REDIRECTS) return reject(new Error("Too many redirects"));
    let parsed;
    try {
      parsed = new URL(url);
    } catch (_) {
      return reject(new Error(`Invalid URL: ${url}`));
    }
    if (parsed.protocol !== "https:" || !ALLOWED_HOSTS.has(parsed.hostname)) {
      return reject(new Error(`Refusing to fetch from untrusted host: ${parsed.hostname}`));
    }
    https
      .get(url, { headers: { "User-Agent": `aspex-npm-installer/${VERSION}` } }, (res) => {
        if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.resume();
          return get(new URL(res.headers.location, url).toString(), onResponse, depth + 1).then(resolve, reject);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        onResponse(res).then(resolve, reject);
      })
      .on("error", reject);
  });
}

function downloadTo(url, dest) {
  return get(url, (res) => new Promise((resolve, reject) => {
    pipeline(res, fs.createWriteStream(dest), (err) => (err ? reject(err) : resolve()));
  }));
}

function fetchText(url) {
  return get(url, (res) => new Promise((resolve, reject) => {
    const chunks = [];
    res.on("data", (c) => chunks.push(c));
    res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    res.on("error", reject);
  }));
}

async function verifyChecksum(filePath, assetName) {
  const text = await fetchText(`https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt`);
  const line = text.split("\n").map((l) => l.trim().split(/\s+/)).find(([, name]) => name === assetName);
  if (!line) throw new Error(`No checksum entry for ${assetName}`);
  const actual = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  if (actual !== line[0]) {
    throw new Error(`Checksum mismatch for ${assetName}: expected ${line[0]}, got ${actual}`);
  }
}

function extract(archivePath) {
  if (process.platform === "win32") {
    execFileSync("powershell", ["-NoProfile", "-Command",
      `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${VENDOR}' -Force`], { stdio: "inherit" });
  } else {
    execFileSync("tar", ["-xzf", archivePath, "-C", VENDOR], { stdio: "inherit" });
  }
}

function binaryPath(name) {
  return path.join(VENDOR, process.platform === "win32" ? `${name}.exe` : name);
}

async function install() {
  const target = platformTarget();
  const assetName = `aspex_${target}${process.platform === "win32" ? ".zip" : ".tar.gz"}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  fs.rmSync(VENDOR, { recursive: true, force: true });
  fs.mkdirSync(VENDOR, { recursive: true });
  const archivePath = path.join(VENDOR, assetName);

  console.log(`aspex: downloading v${VERSION} for ${target}`);
  await downloadTo(url, archivePath);
  await verifyChecksum(archivePath, assetName);
  extract(archivePath);
  fs.unlinkSync(archivePath);

  const vendorReal = fs.realpathSync(VENDOR);
  for (const name of BINARIES) {
    const p = binaryPath(name);
    if (!fs.existsSync(p)) throw new Error(`Archive did not contain ${path.basename(p)}`);
    // Zip-slip guard: every binary must resolve inside vendor/.
    if (!fs.realpathSync(p).startsWith(vendorReal + path.sep)) {
      throw new Error(`Refusing to use binary outside vendor/: ${p}`);
    }
    if (process.platform !== "win32") fs.chmodSync(p, 0o755);
  }
  console.log("aspex: installed. Run `aspex` to see what your agents did this month.");
}

install().catch((err) => {
  console.error(`aspex: install failed: ${err.message}`);
  console.error(`Download manually from https://github.com/${REPO}/releases or use Homebrew: brew install aspex-security/tap/aspex`);
  process.exit(1);
});
