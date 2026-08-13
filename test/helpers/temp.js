const fs = require("fs");
const os = require("os");
const path = require("path");

const tempDirs = new Set();

function makeTempDir(prefixPath) {
  const prefix = path.basename(String(prefixPath));
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.add(tempDir);
  return tempDir;
}

function cleanupTempDirs() {
  for (const tempDir of tempDirs) {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort process-exit cleanup must not hide the original test result.
    }
  }
  tempDirs.clear();
}

process.once("exit", cleanupTempDirs);

module.exports = { cleanupTempDirs, makeTempDir };
