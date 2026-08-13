const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { buildRemediationPlan } = require("../src/remediation");

const cli = path.join(__dirname, "..", "bin", "herewegoagain-incident-scanner.js");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "hwg-safety-contract-"));
const monitorMarker = ["gh-token", "monitor"].join("-");

try {
  fs.writeFileSync(path.join(root, `${monitorMarker}.service`), "historical fixture\n");
  fs.writeFileSync(path.join(root, "cat.py"), "print('ordinary file')\n");
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ name: "fixture", scripts: { postinstall: "PRIVATE_BUILD_VALUE=do-not-disclose node build.js" } })
  );

  const report = scanTarget(root);
  const basenameFinding = report.findings.find((item) => item.path.endsWith("cat.py") && item.type === "payload-file");
  assert(basenameFinding, "generic basename should remain visible for review");
  assert.strictEqual(basenameFinding.severity, "medium");
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, true);
  assert(report.safeRemovalGuidance.instructionDestination.includes("docs/recovery-playbook.md"));

  const lifecycleFinding = report.findings.find((item) => item.type === "lifecycle-script");
  assert(lifecycleFinding, "lifecycle script presence should be disclosed");
  assert(!lifecycleFinding.message.includes("PRIVATE_BUILD_VALUE"), "lifecycle body must not be disclosed");
  assert(lifecycleFinding.message.includes("body withheld"));

  const plan = buildRemediationPlan(report);
  assert.strictEqual(plan.hasDeadManSwitch, true);
  assert(!plan.items.some((item) => item.id === "monitor-kitty-persistence"), "cat.py alone must not trigger persistence/dead-man guidance");

  const human = childProcess.spawnSync(process.execPath, [cli, root], { encoding: "utf8" });
  assert.strictEqual(human.status, 4);
  assert(human.stdout.includes("Safe removal guidance:"));
  assert(human.stdout.includes("docs/recovery-playbook.md"));
  assert(human.stdout.indexOf("Do not revoke or rotate") < human.stdout.indexOf("Instructions:"));
  assert(!human.stdout.includes("PRIVATE_BUILD_VALUE"));

  const retainedPath = path.join(root, "must-not-exist.json");
  const reportAttempt = childProcess.spawnSync(process.execPath, [cli, root, "--report", retainedPath], { encoding: "utf8" });
  assert.strictEqual(reportAttempt.status, 1);
  assert(reportAttempt.stderr.includes("no-retention policy"));
  assert.strictEqual(fs.existsSync(retainedPath), false);

  const largeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hwg-large-lock-"));
  try {
    fs.writeFileSync(path.join(largeRoot, "package-lock.json"), Buffer.alloc(10 * 1024 * 1024 + 1));
    const incomplete = scanTarget(largeRoot);
    assert.strictEqual(incomplete.coverage.complete, false);
    assert.strictEqual(incomplete.coverage.status, "incomplete");
    assert.strictEqual(incomplete.risk, "review-needed");
    assert(incomplete.findings.some((item) => item.type === "large-lockfile-skipped"));
  } finally {
    fs.rmSync(largeRoot, { recursive: true, force: true });
  }

  const missing = scanTarget(path.join(root, "missing-target"));
  assert.strictEqual(missing.coverage.complete, false);
  assert.strictEqual(missing.risk, "review-needed");
  assert(missing.findings.some((item) => item.type === "target-unreadable"));
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

console.log("safety contract tests passed");
