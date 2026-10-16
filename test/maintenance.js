const assert = require("assert");
const childProcess = require("child_process"); // push-guard: ignore -- test-only subprocess harness
const fs = require("fs");
const os = require("os");
const path = require("path");

const repoRoot = path.join(__dirname, "..");
const tempHelper = path.join(__dirname, "helpers", "temp.js");

const dependencyFields = [
  "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
  "bundledDependencies", "bundleDependencies", "overrides", "resolutions", "workspaces",
];
const manifestGitRule = "workflow.npm_v12_git_dependency";

function assertMetadataExceptionSafe(manifest, policy) {
  const allowed = policy.split(/\r?\n/).some((line) => {
    const [file, ...rules] = line.split("#", 1)[0].trim().split(/\s+/);
    return file === "package.json" && rules.join(",").split(",").includes(manifestGitRule);
  });
  if (!allowed) return;
  for (const field of dependencyFields) {
    assert(!Object.hasOwn(manifest, field),
      `Remove or re-scope the package.json Git-source exception before adding ${field}`);
  }
}

const metadataPolicy = `package.json ${manifestGitRule}`;
for (const field of dependencyFields) {
  const candidate = { [field]: { fixture: "git+https://example.invalid/repository.git" } };
  assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /Remove or re-scope/);
  assert.doesNotThrow(() => assertMetadataExceptionSafe(candidate, ""));
}
assertMetadataExceptionSafe(
  JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8")),
  fs.readFileSync(path.join(repoRoot, ".push-guard-allow"), "utf8")
);

const failureScript = [
  'const fs = require("fs");',
  `const { makeTempDir } = require(${JSON.stringify(tempHelper)});`,
  'fs.writeSync(1, `${makeTempDir("hwg-failure-cleanup-")}\\n`);',
  'throw new Error("intentional cleanup test");'
].join("\n");
const failedChild = childProcess.spawnSync(process.execPath, ["-e", failureScript], { // push-guard: ignore -- cleanup failure test
  encoding: "utf8"
});
assert.notStrictEqual(failedChild.status, 0, "cleanup fixture must exercise a failing process");
const failedTempDir = failedChild.stdout.trim().split(/\r?\n/)[0];
assert(failedTempDir.startsWith(os.tmpdir()), "fixtures must be created under the system temp directory");
assert.strictEqual(fs.existsSync(failedTempDir), false, "exit cleanup must remove failed-test fixtures");

const advisory = JSON.parse(fs.readFileSync(path.join(repoRoot, "data", "advisory.json"), "utf8"));
const sourceDocs = fs.readFileSync(path.join(repoRoot, "docs", "sources.md"), "utf8");
assert(Array.isArray(advisory.sources) && advisory.sources.length > 0, "advisory sources must be populated");
assert.strictEqual(new Set(advisory.sources).size, advisory.sources.length, "advisory sources must be unique");
for (const source of advisory.sources) {
  assert(sourceDocs.includes(source), `docs/sources.md is missing canonical source: ${source}`);
}

console.log("maintenance tests passed");
