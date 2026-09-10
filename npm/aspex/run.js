"use strict";
// Shared launcher for the bin/*.js shims: exec the vendored binary with the
// caller's stdio (so the TUI and colors work) and propagate its exit code.

const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");

module.exports = function run(name) {
  const bin = path.join(__dirname, "vendor", process.platform === "win32" ? `${name}.exe` : name);
  if (!fs.existsSync(bin)) {
    console.error(`aspex: ${name} is not installed. Reinstall the package (npm i -g aspex) to fetch the binaries.`);
    process.exit(1);
  }
  const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) {
    console.error(`aspex: failed to start ${name}: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
};
