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
const reviewedScripts = {
  scan: "node bin/herewegoagain-incident-scanner.js",
  smoke: "node bin/herewegoagain-incident-scanner.js --help",
  test: [
    "node --check bin/herewegoagain-incident-scanner.js", "node --check src/scanner.js",
    "node --check src/remediation.js", "node test/smoke.js", "node test/remediation.js",
    "node test/safety-contract.js", "node test/maintenance.js", "node test/intelligence-refresh.js",
    "node --check src/tensorlake.js", "node test/tensorlake.js",
  ].join(" && "),
  "package:check": "npm pack --dry-run --ignore-scripts",
};

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
  // Script changes require re-review instead of guessing which commands fetch Git.
  if (Object.hasOwn(manifest, "scripts")) {
    assert(manifest.scripts && typeof manifest.scripts === "object" && !Array.isArray(manifest.scripts),
      "Remove or re-scope the package.json Git-source exception before changing scripts");
    for (const [name, command] of Object.entries(manifest.scripts)) {
      assert(Object.hasOwn(reviewedScripts, name) && command === reviewedScripts[name],
        `Remove or re-scope the package.json Git-source exception before changing script ${name}`);
    }
  }
  // Only these three descriptive URL fields were reviewed for the exception.
  const remaining = { ...manifest };
  if (typeof remaining.homepage === "string") delete remaining.homepage;
  for (const field of ["repository", "bugs"]) {
    if (remaining[field] && typeof remaining[field] === "object" && !Array.isArray(remaining[field])) {
      remaining[field] = { ...remaining[field] };
      if (typeof remaining[field].url === "string") delete remaining[field].url;
    }
  }
  assert(!/(?:git(?:\+[a-z][a-z0-9.-]*)?|github|gitlab|bitbucket):|github\.com[:/]/i.test(JSON.stringify(remaining)),
    "Remove or re-scope the package.json Git-source exception before adding Git sources outside project metadata");
}

const metadataPolicy = `package.json ${manifestGitRule}`;
for (const field of dependencyFields) {
  const candidate = { [field]: { fixture: "git+https://example.invalid/repository.git" } };
  assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /Remove or re-scope/);
  assert.doesNotThrow(() => assertMetadataExceptionSafe(candidate, ""));
}
const projectMetadata = {
  homepage: "https://github.com/example/project#readme",
  repository: { type: "git", url: "git+https://github.com/example/project.git" },
  bugs: { url: "https://github.com/example/project/issues" },
};
assert.doesNotThrow(() => assertMetadataExceptionSafe(projectMetadata, metadataPolicy));
assert.doesNotThrow(() => assertMetadataExceptionSafe({ scripts: reviewedScripts }, metadataPolicy));
for (const [name, command] of Object.entries(reviewedScripts)) {
  const candidate = { scripts: { ...reviewedScripts, [name]: `${command} && echo changed` } };
  assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /changing script/);
  assert.doesNotThrow(() => assertMetadataExceptionSafe(candidate, ""));
}
for (const scripts of [null, [], "node example.js"]) {
  assert.throws(() => assertMetadataExceptionSafe({ scripts }, metadataPolicy), /changing scripts/);
}
for (const script of ["preinstall", "install", "postinstall", "prepare", "prepublishOnly", "custom"]) {
  for (const source of [
    "git+https://example.invalid/repository.git", "git://example.invalid/repository.git",
    "git+http://example.invalid/repository.git", "git+ssh://git@example.invalid/repository.git",
    "git+file:///example/repository.git", "GIT+SSH://git@example.invalid/repository.git",
    "github:example/project", "gitlab:example/project", "bitbucket:example/project",
    "git@github.com:example/project.git", "HTTPS://GITHUB.COM/example/project.git",
    "gist:101a11beef", "git@gitlab.com:example/project.git",
    "https://gitlab.com/example/project.git", "example/project",
  ]) {
    const candidate = { ...projectMetadata, scripts: { [script]: `npm install ${source}` } };
    assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /changing script/);
    assert.doesNotThrow(() => assertMetadataExceptionSafe(candidate, ""));
  }
}
for (const field of ["config", "repository", "bugs", "homepage"]) {
  const candidate = { ...projectMetadata, [field]: { extra: "github:example/project" } };
  assert.throws(() => assertMetadataExceptionSafe(candidate, metadataPolicy), /outside project metadata/);
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
