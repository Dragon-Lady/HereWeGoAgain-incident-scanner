const assert = require("assert");
const childProcess = require("child_process"); // push-guard: ignore -- test-only subprocess harness
const fs = require("fs");
const os = require("os");
const path = require("path");

const repoRoot = path.join(__dirname, "..");
const tempHelper = path.join(__dirname, "helpers", "temp.js");

const manifestGitRule = "workflow.npm_v12_git_dependency";
// Re-review all package hits before refreshing this baseline; remove the exception
// if any hit is an executable Git fetch or a dependency rather than project metadata.
const reviewedManifestDigest = "936c48bf0eb86ef16e5df735a2131f1e81c0209b8e8ea17106846cdb4d2d5322";

function assertMetadataExceptionSafe(manifest, policy) {
  const allowed = policy.split(/\r?\n/).some((line) => {
    const [file, ...rules] = line.split("#", 1)[0].trim().split(/\s+/);
    return file === "package.json" && rules.join(",").split(",").includes(manifestGitRule);
  });
  if (!allowed) return;
  const digest = require("crypto").createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
  assert.strictEqual(digest, reviewedManifestDigest,
    "Manifest changed: remove or re-review the package.json Git-source exception");
}

const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
const metadataPolicy = `package.json ${manifestGitRule}`;
assertMetadataExceptionSafe(manifest, fs.readFileSync(path.join(repoRoot, ".push-guard-allow"), "utf8"));
assert.doesNotThrow(() => assertMetadataExceptionSafe(structuredClone(manifest), metadataPolicy));

function assertManifestChangeRejected(mutate) {
  const candidate = structuredClone(manifest);
  mutate(candidate);
  assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /Manifest changed/);
  assert.doesNotThrow(() => assertMetadataExceptionSafe(candidate, ""));
}

for (const field of [
  "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
  "bundledDependencies", "bundleDependencies", "overrides", "resolutions", "workspaces",
]) {
  assertManifestChangeRejected((candidate) => { candidate[field] = { fixture: "example/project" }; });
}
for (const name of Object.keys(manifest.scripts)) {
  assertManifestChangeRejected((candidate) => { delete candidate.scripts[name]; });
  assertManifestChangeRejected((candidate) => { candidate.scripts[name] += " && echo changed"; });
}
assertManifestChangeRejected((candidate) => { delete candidate.scripts; });
for (const scripts of [null, [], {}, "node example.js"]) {
  assertManifestChangeRejected((candidate) => { candidate.scripts = scripts; });
}
for (const source of [
  "git+https://example.invalid/repository.git", "git://example.invalid/repository.git",
  "git+http://example.invalid/repository.git", "git+ssh://git@example.invalid/repository.git",
  "git+file:///example/repository.git", "GIT+SSH://git@example.invalid/repository.git",
  "github:example/project", "gitlab:example/project", "bitbucket:example/project",
  "git@github.com:example/project.git", "HTTPS://GITHUB.COM/example/project.git",
  "gist:101a11beef", "git@gitlab.com:example/project.git",
  "https://gitlab.com/example/project.git", "https://bitbucket.org/example/project.git",
  "example/project",
]) {
  for (const script of ["preinstall", "install", "postinstall", "prepare", "prepublishOnly", "custom"]) {
    assertManifestChangeRejected((candidate) => { candidate.scripts[script] = "npm install " + source; });
  }
  for (const field of ["config", "repository", "bugs", "homepage"]) {
    assertManifestChangeRejected((candidate) => { candidate[field] = { extra: source }; });
  }
}
assertManifestChangeRejected((candidate) => { candidate.version = "0.0.0"; });
assertManifestChangeRejected((candidate) => { candidate.homepage = "https://example.invalid/updated"; });

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
