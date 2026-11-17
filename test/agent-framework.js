"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {test} = require("node:test");
const {makeTempDir} = require("./helpers/temp");
const {scanTarget} = require("../src/scanner");

function check(base, contents) {
  const root = makeTempDir("hwg-af-");
  const file = path.join(root, base);
  fs.mkdirSync(path.dirname(file), {recursive:true});
  fs.writeFileSync(file, contents);
  const report = scanTarget(root);
  assert.equal(fs.readFileSync(file, "utf8"), contents);
  return {report, hits: report.findings.filter(item => item.type.startsWith("agent-framework-"))};
}

for (const v of ["1.26.1", "1.26.2"]) {
  test(`matches exact PyPI release ${v} in supported records`, () => {
    const records = [
      ["requirements-dev.txt", `Agent_Framework[all]==${v} ; python_version >= '3.11'`],
      ["pyproject.toml", `[project]\ndependencies = ["agent-framework==${v}"]`],
      ["pyproject.toml", `[project.optional-dependencies]\nextra = ["agent-framework==${v}"]`],
      ["pyproject.toml", `[tool.poetry.dependencies]\n"Agent.Framework" = {version="==${v}"}`],
      ["uv.lock", `[[package]]\nname="Agent_Framework"\nversion="${v}"`],
      ["poetry.lock", `[[package]]\nversion="${v}"\nname="agent-framework"`],
      ["pylock.toml", `[[packages]]\nname="agent-framework"\nversion="${v}"`],
      ["Pipfile.lock", JSON.stringify({develop:{"agent-framework":{version:`==${v}`}}})],
      [`site-packages/agent_framework-${v}.dist-info/METADATA`, `Metadata-Version: 2.4\nName: agent-framework\nVersion: ${v}\n\nExample`],
    ];
    for (const [file,contents] of records) {
      const {report,hits} = check(file,contents);
      assert.deepEqual(hits.map(x=>[x.severity,x.evidence.version]), [["critical",v]], file);
      assert.equal(report.safeRemovalGuidance.sequenceSensitive,false);
      assert.match(report.safeRemovalGuidance.firstAction,/Do not start Python or pip/);
    }
  });
}
test("other releases, names, ranges, comments and adjacent records are clear", () => {
  const records = [
    ["requirements.txt","agent-framework==1.26.0\nAgent_Framework==1.26.10\nagent-framework==1.26.2.post1\nagent-framework==1.26.2+local\nagent-framework>=1.26.1\nagent-framework-core==1.26.2\n# agent-framework==1.26.2"],
    ["uv.lock",'[[package]]\nname="agent-framework"\nversion="1.26.0"\n[[package]]\nname="example"\nversion="1.26.1"'],
    ["METADATA","Name: other\nVersion: 1.26.2\n\nName: agent-framework\nVersion: 1.26.1"],
    ["pyproject.toml",'[project]\ndescription="agent-framework==1.26.2"'],
  ];
  for (const [file,contents] of records) assert.equal(check(file,contents).hits.length,0,file);
});
test("a matching wheel filename with different bytes is only a review finding", () => {
  for (const v of ["1.26.1","1.26.2"]) {
    const {hits} = check(`agent_framework-${v}-py3-none-any.whl`,"inert fixture");
    assert.deepEqual(hits.map(x=>[x.type,x.severity]),[["agent-framework-wheel-review","medium"]]);
  }
  assert.equal(check("agent_framework-1.26.0-py3-none-any.whl","inert fixture").hits.length,0);
});
test("each published digest must match the corresponding release", () => {
  const {wheelFinding} = require("../src/agent-framework");
  const a = "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110";
  const b = "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9";
  for (const [version,digest,other] of [["1.26.1",a,b],["1.26.2",b,a]]) {
    assert.equal(wheelFinding("fixture",version,digest).type,"agent-framework-wheel-hash");
    assert.equal(wheelFinding("fixture",version,other).severity,"medium");
  }
});
test("incident referral and separate persistence guidance retain their order", () => {
  const root = makeTempDir("hwg-af-mixed-");
  fs.writeFileSync(path.join(root,"requirements.txt"),"agent-framework==1.26.2");
  const {buildRemediationPlan} = require("../src/remediation");
  assert(buildRemediationPlan(scanTarget(root)).items.some(item => item.id === "agent-framework-startup-hook-response"));
  fs.writeFileSync(path.join(root,["gh-token","monitor.service"].join("-")),"inert");
  const mixed = scanTarget(root);
  assert.equal(mixed.safeRemovalGuidance.sequenceSensitive,true);
  assert.match(mixed.safeRemovalGuidance.firstAction,/do not revoke/i);
});
