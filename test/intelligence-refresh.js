const assert = require("assert");
const childProcess = require("child_process"); // push-guard: ignore -- test-only CLI harness
const fs = require("fs");
const path = require("path");
const { loadAdvisoryData, scanTarget } = require("../src/scanner");
const { buildRemediationPlan } = require("../src/remediation");
const { makeTempDir } = require("./helpers/temp");

const repoRoot = path.join(__dirname, "..");
const cli = path.join(repoRoot, "bin", "herewegoagain-incident-scanner.js");
const tokenMonitorMarker = ["gh-token", "monitor"].join("-");
const chainDrop = JSON.parse(fs.readFileSync(path.join(repoRoot, "data", "campaigns", "august-2026-chaindrop.json"), "utf8"));
const copycats = JSON.parse(fs.readFileSync(path.join(repoRoot, "data", "campaigns", "may-2026-teampcp-copycats.json"), "utf8"));
const legacyNpm = JSON.parse(fs.readFileSync(path.join(repoRoot, "data", "packages", "npm.json"), "utf8"));
const advisory = loadAdvisoryData();

function pairCount(packages) {
  return Object.values(packages).reduce((sum, versions) => sum + versions.length, 0);
}

assert.strictEqual(Object.keys(chainDrop.packages).length, 444);
assert.strictEqual(pairCount(chainDrop.packages), 2236);
assert.strictEqual(chainDrop.excludedSingleSourcePairs, 101);
assert.strictEqual(chainDrop.status, "historical-confirmed");
assert.strictEqual(chainDrop.currentActivity, "unverified");
assert.strictEqual(chainDrop.lastVerified, "2026-08-12");
assert(chainDrop.confidence.includes("corroborated by at least two"));
assert(chainDrop.deadManPolicy.includes("not evidence"));
assert(chainDrop.sources.length >= 4);
assert.strictEqual(advisory.lastUpdated, "2026-08-12");
for (const source of [...chainDrop.sources, ...copycats.sources]) {
  assert(advisory.sources.includes(source), `canonical source catalog is missing ${source}`);
}
for (const monitor of [`${tokenMonitorMarker}.service`, `${tokenMonitorMarker}.sh`, `com.user.${tokenMonitorMarker}.plist`]) {
  const metadata = advisory.indicators.indicatorMetadata[monitor];
  assert.strictEqual(metadata.lastVerified, "2026-08-12");
  assert(metadata.currentActivity.includes("local installation or activation"));
}

for (const [name, versions] of Object.entries(chainDrop.packages)) {
  assert.strictEqual(new Set(versions).size, versions.length, `${name} contains duplicate versions`);
  for (const version of versions) {
    assert(!(legacyNpm[name] || []).includes(version), `${name}@${version} overlaps the legacy catalog`);
  }
}

assert.deepStrictEqual(Object.keys(copycats.packages).sort(), [
  "@deadcode09284814/axios-util",
  "axois-utils",
  "chalk-tempalte",
  "color-style-utils"
]);
assert(Object.values(copycats.packages).every((versions) => versions.length === 1 && versions[0] === "*"));

const root = makeTempDir("hwg-intel-refresh-");
try {
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
    name: "refresh-fixture",
    dependencies: {
      "@hubsync/web-sdk-react": "6.3.19",
      "@servicetitan/tokens": "12.9.7",
      "@deadcode09284814/axios-util": "1.0.0"
    }
  }));
  const report = scanTarget(root);
  const exact = report.findings.filter((finding) => finding.type === "known-bad-requested-version");
  const allVersion = report.findings.find((finding) => finding.type === "known-bad-requested-version" && finding.message.includes("@deadcode09284814/axios-util"));
  assert(exact.some((finding) => finding.message.includes("@hubsync/web-sdk-react") && finding.evidence?.status === "historical-confirmed"));
  assert(exact.some((finding) => finding.message.includes("@servicetitan/tokens") && finding.evidence?.currentActivity === "unverified"));
  assert(allVersion && allVersion.evidence?.campaign === "May 2026 TeamPCP copycat npm packages");
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false, "package-only findings must never be sequence-sensitive");
  assert.strictEqual(buildRemediationPlan(report).hasDeadManSwitch, false);
  const cliResult = childProcess.spawnSync(process.execPath, [cli, root, "--json"], { encoding: "utf8" }); // push-guard: ignore -- test-only CLI harness
  assert.strictEqual(cliResult.status, 2, "package-only findings use exposure exit 2, never sequence-sensitive exit 4");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

const safeRoot = makeTempDir("hwg-intel-refresh-safe-");
try {
  fs.writeFileSync(path.join(safeRoot, "package.json"), JSON.stringify({
    name: "safe-refresh-fixture",
    dependencies: {
      "@hubsync/web-sdk-react": "6.3.6",
      "@servicetitan/tokens": "12.9.8"
    }
  }));
  const report = scanTarget(safeRoot);
  assert(!report.findings.some((finding) => finding.type === "known-bad-requested-version"));
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false);
} finally {
  fs.rmSync(safeRoot, { recursive: true, force: true });
}

const reviewRoot = makeTempDir("hwg-intel-refresh-review-");
try {
  fs.writeFileSync(path.join(reviewRoot, "package.json"), JSON.stringify({
    name: "review-refresh-fixture",
    notes: `${tokenMonitorMarker}.service Math_Symbol.js Bun/1.3.13 eth.llamarpc.com`
  }));
  const report = scanTarget(reviewRoot);
  const historicalSignals = report.findings.filter((finding) =>
    ["payload-reference", "workflow-indicator", "network-indicator", "campaign-indicator"].includes(finding.type)
  );
  assert(historicalSignals.length >= 4);
  assert(historicalSignals.every((finding) => finding.severity === "medium"), "generic and copied historical indicators must stay review-only");
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false, "copied monitor text must not be sequence-sensitive");
  assert.strictEqual(buildRemediationPlan(report).hasDeadManSwitch, false);
} finally {
  fs.rmSync(reviewRoot, { recursive: true, force: true });
}

for (const relative of ["README.md", "docs/recovery-playbook.md", "docs/sources.md", "docs/advisory.md", "data/remediation.json"]) {
  const text = fs.readFileSync(path.join(repoRoot, relative), "utf8");
  assert(!text.includes("actions-warden"), `${relative} retains a promotional tool reference`);
}
const chainDropDocs = fs.readFileSync(path.join(repoRoot, "docs", "sources.md"), "utf8").split("## August 2026 keyv / cacheable (ChainDrop)")[1];
assert(chainDropDocs && !/Credits:|Moshe|partnership|endorsement|guarantee/i.test(chainDropDocs));

console.log("intelligence refresh tests passed");
