"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { scanTarget, loadAdvisoryData } = require("../src/scanner");
const { buildRemediationPlan } = require("../src/remediation");
const { makeTempDir } = require("./helpers/temp");

const library = "@wppconnect-team/wppconnect";
const server = "@wppconnect/server";
const campaign = "November 2026 WPPConnect credential and WhatsApp-session theft";
function inspect(base, value) {
  const root = makeTempDir("hwg-wppconnect-");
  const file = path.join(root, base);
  const text = typeof value === "string" ? value : JSON.stringify(value);
  fs.writeFileSync(file, text);
  try {
    const report = scanTarget(root);
    assert.equal(fs.readFileSync(file, "utf8"), text, "inspection changes no input");
    assert.deepEqual(fs.readdirSync(root), [base], "inspection retains no report or other data");
    return report;
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const hits = report => report.findings.filter(item => item.evidence?.campaign === campaign);

test("WPPConnect snapshot contains only two corroborated pairs with dated sources", () => {
  const advisory = loadAdvisoryData();
  assert.deepEqual(advisory.packages[library], ["2.4.1"]);
  assert.deepEqual(advisory.packages[server], ["2.10.82"]);
  for (const name of [library, server]) {
    const report = inspect("package.json", { name, version: advisory.packages[name][0] });
    const evidence = hits(report)[0].evidence;
    assert.equal(evidence.sources.length, 2);
    assert.equal(evidence.lastVerified, "2026-11-17");
    assert.equal(evidence.executionTrigger, "import-or-start");
    assert.match(evidence.currentActivity, /not assessed/);
  }
});

test("manifest pins and scoped npm aliases carry exact identities", () => {
  for (const [name, version] of [[library, "2.4.1"], [server, "2.10.82"]]) {
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      assert.equal(hits(inspect("package.json", { [section]: { [name]: version } })).length, 1);
      assert.equal(hits(inspect("package.json", { [section]: { alias: `npm:${name}@${version}` } })).length, 1);
    }
  }
});

test("package-lock and npm-shrinkwrap entries are scoped across versions and aliases", () => {
  for (const base of ["package-lock.json", "npm-shrinkwrap.json"]) {
    for (const [name, version] of [[library, "2.4.1"], [server, "2.10.82"]]) {
      for (const data of [
        { lockfileVersion: 3, packages: { [`node_modules/${name}`]: { version } } },
        { lockfileVersion: 2, packages: { [`node_modules/outer/node_modules/${name}`]: { version } } },
        { lockfileVersion: 1, dependencies: { outer: { dependencies: { [name]: { version } } } } },
        { lockfileVersion: 3, packages: { "node_modules/alias": { name, version } } },
        { lockfileVersion: 1, dependencies: { alias: { version: `npm:${name}@${version}` } } }
      ]) assert.equal(hits(inspect(base, data)).length, 1, `${base} ${JSON.stringify(data)}`);
    }
  }
});

test("Yarn classic and Berry and pnpm old/new keys identify resolved versions", () => {
  for (const [name, version] of [[library, "2.4.1"], [server, "2.10.82"]]) {
    for (const text of [
      `"${name}@^${version}":\n  version "${version}"\n`,
      `"${name}@npm:^${version}":\n  version: ${version}\n`,
      `"alias@npm:${name}@^${version}":\n  version "${version}"\n`,
      `"alias@npm:${name}@^${version}":\n  version: ${version}\n`,
      `"@local/alias@npm:${name}@^${version}":\n  version "${version}"\n`,
      `"@local/alias@npm:${name}@^${version}":\n  version: ${version}\n`,
      `"alias@npm:${name}@^${version}", "${name}@~${version}":\n  version "${version}"\n`,
      `"${name}@npm:^${version}, alias@npm:${name}@~${version}":\n  version: ${version}\n`
    ]) assert.equal(hits(inspect("yarn.lock", text)).length, 1);
    for (const text of [
      `packages:\n  '${name}@${version}': {}\n`,
      `packages:\n  /${name}/${version}:\n    resolution: {}\n`,
      `snapshots:\n  '${name}@${version}(peer@1.0.0)': {}\n`
    ]) assert.equal(hits(inspect("pnpm-lock.yaml", text)).length, 1);
  }
});

test("Yarn npm alias labels do not impersonate their unrelated targets", () => {
  for (const [name, version] of [[library, "2.4.1"], [server, "2.10.82"]]) {
    for (const target of ["unrelated-server", "@unrelated/server"]) {
      for (const resolved of [`version "${version}"`, `version: ${version}`]) {
        const report = inspect("yarn.lock", `"${name}@npm:${target}@${version}":\n  ${resolved}\n`);
        assert.equal(hits(report).length, 0, `${name} aliases ${target}`);
        assert.notEqual(report.risk, "likely-exposed");
      }
    }
  }
});

test("adjacent versions, unresolved ranges, descriptions and unrelated versions are not exact hits", () => {
  for (const [name, version, safe] of [[library, "2.4.1", "2.4.0"], [server, "2.10.82", "2.10.81"]]) {
    for (const value of [safe, `${version}0`, `^${version}`, `~${version}`, `>=${version}`, `npm:${name}@^${version}`]) {
      assert.equal(hits(inspect("package.json", { dependencies: { [name]: value } })).length, 0);
    }
    for (const base of ["package.json", "package-lock.json"]) {
      assert.equal(hits(inspect(base, { description: `${name}@${version}` })).length, 0);
      assert.equal(hits(inspect(base, { packages: { [`node_modules/${name}`]: { version: safe }, "node_modules/other": { version } } })).length, 0);
    }
    assert.equal(hits(inspect("yarn.lock", `"${name}@^${version}":\n  version "${safe}"\n"other@1":\n  version "${version}"\n`)).length, 0);
    assert.equal(hits(inspect("yarn.lock", `"@local/alias@npm:${name}@^${version}":\n  version "${safe}"\n"other@1":\n  version "${version}"\n`)).length, 0);
    assert.equal(hits(inspect("pnpm-lock.yaml", `# ${name}@${version}:\npackages:\n  '${name}@${safe}': {}\n`)).length, 0);
  }
});

test("malformed dependency metadata remains incomplete", () => {
  for (const base of ["package.json", "package-lock.json"]) {
    const report = inspect(base, `{"dependencies":{"${library}":`);
    assert.equal(report.coverage.complete, false);
    assert.equal(hits(report).length, 0);
  }
});

test("import-time response is referral-only without inferring a wiper", () => {
  const report = inspect("package.json", { dependencies: { [library]: "2.4.1" } });
  assert.equal(report.risk, "likely-exposed");
  assert.equal(report.safeRemovalGuidance.sequenceSensitive, false);
  assert.match(report.safeRemovalGuidance.firstAction, /--ignore-scripts does not prevent/);
  assert.match(report.safeRemovalGuidance.firstAction, /does not prove execution or theft/);
  const plan = buildRemediationPlan(report);
  assert.equal(plan.hasDeadManSwitch, false);
  const item = plan.items.find(item => item.id === "wppconnect-import-response");
  assert(item);
  assert.match(item.warning.join(" "), /import or server startup/);
  assert.match(report.safeRemovalGuidance.retention, /does not save/);
});

test("separately detected wiper guidance takes precedence over WPPConnect response", () => {
  const report = inspect("package.json", { dependencies: {
    [library]: "2.4.1", "event-bus-lite-testmetest": "0.0.1"
  } });
  assert.equal(report.safeRemovalGuidance.sequenceSensitive, true);
  assert.match(report.guidance.join(" "), /before revoking or rotating/);
  assert.equal(buildRemediationPlan(report).hasDeadManSwitch, true);
});
