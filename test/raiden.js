"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { scanTarget } = require("../src/scanner");
const { makeTempDir } = require("./helpers/temp");

const name = "raiden-baileys";
const upstream = "@whiskeysockets/baileys";

function check(file, metadata, expected) {
  const root = makeTempDir("hwg-raiden-");
  const raw = typeof metadata === "string" ? metadata : JSON.stringify(metadata);
  fs.writeFileSync(path.join(root, file), raw);
  const report = scanTarget(root);
  const hits = report.findings.filter(item => item.type === "raiden-baileys-package");
  assert.equal(hits.length, expected ? 1 : 0, file + " " + raw);
  if (expected) {
    assert.match(hits[0].evidence.source, /MAL-2026-19108/);
    assert.equal(report.safeRemovalGuidance.sequenceSensitive, false);
    assert.equal(report.risk, "likely-exposed");
  }
  assert.equal(fs.readFileSync(path.join(root, file), "utf8"), raw);
  assert.deepEqual(fs.readdirSync(root), [file]);
  return report;
}

test("manifest package identity, ranges and npm aliases", () => {
  check("package.json", { name, version: "0.0.0-stage" }, true);
  for (const key of ["dependencies","devDependencies","peerDependencies","optionalDependencies"]) {
    check("package.json", { [key]: { [name]: "^2.1.0" } }, true);
    check("package.json", { [key]: { adapter: "npm:" + name } }, true);
    check("package.json", { [key]: { adapter: "npm:" + name + "@latest" } }, true);
  }
  for (const spec of ["npm:" + upstream + "@2.1.6", "file:../vendor", "workspace:*", "owner/project"]) {
    check("package.json", { dependencies: { [name]: spec } }, false);
  }
  check("package.json", { description: name, dependencies: { [upstream]: "2.1.6", "raiden-baileys-extra": "2.1.6", "@other/raiden-baileys": "2.1.6" } }, false);
});

test("npm lockfiles resolve nested entries and alias targets", () => {
  for (const file of ["package-lock.json","npm-shrinkwrap.json"]) {
    check(file, { packages: { ["node_modules/outer/node_modules/" + name]: { version: "2.2.4" } } }, true);
    check(file, { packages: { "node_modules/alias": { name, version: "0.0.0-stage" } } }, true);
    check(file, { dependencies: { outer: { dependencies: { alias: { version: "npm:" + name + "@2.1.6" } } } } }, true);
    check(file, { packages: { ["node_modules/" + name]: { name: upstream, version: "2.1.6" } }, description: name }, false);
    check(file, { packages: { ["node_modules/" + name]: { link: true, resolved: "../local" } } }, false);
  }
  assert.equal(check("package-lock.json", '{"packages":', false).coverage.complete, false);
});

test("Yarn and pnpm match resolved identities only", () => {
  check("yarn.lock", '"adapter@npm:raiden-baileys@^2":\n  version "2.1.6"\n', true);
  check("yarn.lock", '"raiden-baileys@npm:^2":\n  version: 2.2.4\n', true);
  check("yarn.lock", '"raiden-baileys@npm:@whiskeysockets/baileys@2":\n  version: 2.1.6\n', false);
  check("yarn.lock", '"raiden-baileys@workspace:.":\n  version: 0.0.0\n', false);
  check("yarn.lock", '"raiden-baileys@vendor/local-copy":\n  version "2.1.6"\n', false);
  check("pnpm-lock.yaml", "packages:\n  /raiden-baileys/2.1.6:\n    resolution: {}\n", true);
  check("pnpm-lock.yaml", "snapshots:\n  'raiden-baileys@0.0.0-stage(peer@2.0.0)': {}\n", true);
  check("pnpm-lock.yaml", "importers:\n  raiden-baileys@2.1.6: {}\npackages:\n  raiden-baileys-extra@2.1.6: {}\n", false);
});
