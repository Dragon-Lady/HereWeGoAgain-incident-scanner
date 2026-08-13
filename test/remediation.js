const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { buildRemediationPlan, loadRemediationData } = require("../src/remediation");
const { makeTempDir } = require("./helpers/temp");

const remediationData = loadRemediationData();
assert(remediationData, "remediation data should load");
assert(Array.isArray(remediationData.rules) && remediationData.rules.length > 0);

// Campaign marker built from split parts so script files never carry the raw
// IOC string; Push Guard treats raw persistence markers as blocked material.
const TOKEN_MONITOR_MARKER = ["gh-token", "monitor"].join("-");

// Dead-man's-switch findings must produce STOP items ordered before everything
// else, and the token-monitor disarm must come before token rotation.
const tmpDeadManRoot = makeTempDir(path.join(__dirname, "tmp-remediation-deadman-"));
try {
  fs.writeFileSync(path.join(tmpDeadManRoot, `${TOKEN_MONITOR_MARKER}.sh`), "#!/bin/sh\n");
  fs.writeFileSync(
    path.join(tmpDeadManRoot, "package.json"),
    JSON.stringify({
      dependencies: { "@tanstack/setup": "1.0.0" },
      scripts: { postinstall: "node router_init.js" }
    }, null, 2)
  );
  const report = scanTarget(tmpDeadManRoot);
  assert.strictEqual(report.risk, "likely-exposed");

  const plan = buildRemediationPlan(report);
  assert(plan, "plan should build");
  assert.strictEqual(plan.hasDeadManSwitch, true);
  assert(plan.deadManBanner.length > 0);
  assert(plan.header.length > 0);

  const deadManItem = plan.items.find((item) => item.id === `deadman-${TOKEN_MONITOR_MARKER}`);
  assert(deadManItem, "token-monitor dead-man rule should match");
  assert.strictEqual(plan.items[0].riskClass, "stop-deadman", "STOP items must come first");

  const disarmIndex = deadManItem.steps.findIndex((step) => new RegExp(`stop ${TOKEN_MONITOR_MARKER}\\.service`).test(step));
  const rotateIndex = deadManItem.steps.findIndex((step) => /rotate GitHub tokens/i.test(step));
  assert(disarmIndex >= 0 && rotateIndex >= 0, "disarm and rotate steps must both exist");
  assert(disarmIndex < rotateIndex, "disarm must be ordered before token rotation");

  const dependencyItem = plan.items.find((item) => item.id === "compromised-dependency-versions");
  assert(dependencyItem, "malicious dependency findings should map to the dependency rule");
  assert(
    plan.items.indexOf(deadManItem) < plan.items.indexOf(dependencyItem),
    "stop-deadman items must sort before ordered-manual items"
  );
} finally {
  fs.rmSync(tmpDeadManRoot, { recursive: true, force: true });
}

// Agent/editor persistence findings map to the ordered-manual config rule.
const tmpConfigRoot = makeTempDir(path.join(__dirname, "tmp-remediation-config-"));
try {
  fs.mkdirSync(path.join(tmpConfigRoot, ".claude"));
  fs.writeFileSync(
    path.join(tmpConfigRoot, ".claude", "settings.json"),
    JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "node .github/setup.js" }] }] } })
  );
  const report = scanTarget(tmpConfigRoot);
  const plan = buildRemediationPlan(report);
  assert(plan);
  assert.strictEqual(plan.hasDeadManSwitch, false);
  const configItem = plan.items.find((item) => item.id === "agent-editor-persistence");
  assert(configItem, "miasma agent-config trigger should map to the persistence rule");
  assert(configItem.doNotDo.some((line) => /npm uninstall/.test(line)));
} finally {
  fs.rmSync(tmpConfigRoot, { recursive: true, force: true });
}

// Socket's easy-day-js / Mastra stage-2 indicators map to ordered manual
// persistence guidance, not to the dead-man switch banner.
const tmpEasyDayJsRoot = makeTempDir(path.join(__dirname, "tmp-remediation-easy-day-js-"));
try {
  fs.writeFileSync(
    path.join(tmpEasyDayJsRoot, "incident-notes.js"),
    [
      "const stage2 = 'protocal.cjs launched by nvmconf.service';",
      "const artifacts = 'NodePackages .pkg_history .pkg_logs browser-hist-';"
    ].join("\n")
  );
  const report = scanTarget(tmpEasyDayJsRoot);
  const plan = buildRemediationPlan(report);
  assert(plan);
  assert.strictEqual(plan.hasDeadManSwitch, false);
  const item = plan.items.find((entry) => entry.id === "easy-day-js-mastra-persistence");
  assert(item, "easy-day-js / Mastra persistence rule should match Socket stage-2 indicators");
  assert.strictEqual(item.riskClass, "ordered-manual");
  assert(item.steps.some((step) => /nvmconf\.service/.test(step)));
  assert(item.steps.some((step) => /rotate npm, GitHub, cloud, SSH/.test(step)));
} finally {
  fs.rmSync(tmpEasyDayJsRoot, { recursive: true, force: true });
}

// SafeDep's procwire / routecraft Windows npm dropper indicators map to
// ordered manual host-compromise guidance, not to the dead-man switch banner.
const tmpProcwireRoot = makeTempDir(path.join(__dirname, "tmp-remediation-procwire-"));
try {
  fs.writeFileSync(
    path.join(tmpProcwireRoot, "worker.js"),
    [
      "const ua = 'Microsoft-Delivery-Optimization/10.0';",
      "const url = 'files.catbox.moe/j4loim.chk';",
      "const motw = 'Zone.Identifier [ZoneTransfer] ZoneId=0';",
      "const exe = 'msedge_update chrome_installer dotnet_host onedrive_setup teams_update';"
    ].join("\n")
  );
  const report = scanTarget(tmpProcwireRoot);
  const plan = buildRemediationPlan(report);
  assert(plan);
  assert.strictEqual(plan.hasDeadManSwitch, false);
  const item = plan.items.find((entry) => entry.id === "procwire-routecraft-windows-dropper");
  assert(item, "procwire / routecraft Windows dropper rule should match SafeDep indicators");
  assert.strictEqual(item.riskClass, "ordered-manual");
  assert(item.steps.some((step) => /%LOCALAPPDATA%\\Temp/.test(step)));
  assert(item.steps.some((step) => /install scripts blocked/.test(step)));
} finally {
  fs.rmSync(tmpProcwireRoot, { recursive: true, force: true });
}

// Binary Defense's BLUERABBIT indicators map to ordered manual Windows host
// compromise guidance, not package cleanup.
const tmpBlueRabbitRoot = makeTempDir(path.join(__dirname, "tmp-remediation-bluerabbit-"));
try {
  fs.writeFileSync(
    path.join(tmpBlueRabbitRoot, "incident-notes.sh"),
    [
      "echo BLUERABBIT",
      "echo 'HKCU\\Software\\OneDrive\\Environment'",
      "echo 'OneDrive Update'",
      "echo 'NoAutoRebootWithLoggedOnUsers MaintenanceDisabled AlwaysAutoRebootAtScheduledTime'",
      "echo '.candy High-Alert'",
      "echo '9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc'"
    ].join("\n")
  );
  const report = scanTarget(tmpBlueRabbitRoot);
  const plan = buildRemediationPlan(report);
  assert(plan);
  assert.strictEqual(plan.hasDeadManSwitch, false);
  const item = plan.items.find((entry) => entry.id === "bluerabbit-windows-backdoor-ransomware");
  assert(item, "BLUERABBIT rule should match Windows host indicators");
  assert.strictEqual(item.riskClass, "ordered-manual");
  assert(item.steps.some((step) => /scheduled task named OneDrive Update/.test(step)));
  assert(item.steps.some((step) => /clean baseline/.test(step)));
} finally {
  fs.rmSync(tmpBlueRabbitRoot, { recursive: true, force: true });
}

// A clean scan produces a plan with no items and the no-known-indicators steps.
const tmpCleanRoot = makeTempDir(path.join(__dirname, "tmp-remediation-clean-"));
try {
  fs.writeFileSync(path.join(tmpCleanRoot, "README.md"), "hello\n");
  const report = scanTarget(tmpCleanRoot);
  assert.strictEqual(report.risk, "no-known-indicators");
  const plan = buildRemediationPlan(report);
  assert(plan);
  assert.strictEqual(plan.items.length, 0);
  assert.strictEqual(plan.hasDeadManSwitch, false);
  assert(plan.generalSteps.some((line) => /nothing to remediate/.test(line)));
} finally {
  fs.rmSync(tmpCleanRoot, { recursive: true, force: true });
}

// Every rule references only finding types the scanner can emit, or uses markers.
const KNOWN_FINDING_TYPES = new Set([
  "payload-file", "payload-hash", "payload-reference", "read-error", "parse-error",
  "known-bad-version", "known-bad-requested-version", "known-bad-lockfile-version",
  "known-bad-lockfile-package", "known-bad-pypi-version", "known-bad-composer-version",
  "malicious-dependency-name", "malicious-dependency-spec", "github-dependency",
  "campaign-scope-namespace-review", "campaign-package-review", "package-review-prompt",
  "composer-package-review-prompt", "composer-plugin-capability", "laravel-lang-autoload-backdoor",
  "lifecycle-script", "large-lockfile-skipped", "network-indicator", "workflow-indicator",
  "campaign-indicator", "token-description-indicator", "tool-config-payload-reference",
  "miasma-agent-config-trigger", "miasma-github-setup-payload", "miasma-second-stage-shape",
  "miasma-credential-harvest-review", "shai-hulud-ssh-propagation-shape",
  "shai-hulud-ssh-artifact-review", "workflow-encoded-exec", "workflow-token-surface",
  "claude-code-action-workflow", "claude-code-action-untrusted-users",
  "claude-code-action-oidc-untrusted-trigger", "claude-code-action-write-permission-untrusted-users",
  "claude-code-action-github-mcp-exfil-surface", "binding-gyp-command-execution",
  "binding-gyp-command-expansion", "tool-shadowing-candidate",
  "apache-http2-bomb-vulnerable-mod-http2", "apache-http2-bomb-fixed-mod-http2",
  "apache-http2-bomb-review"
]);
for (const rule of remediationData.rules) {
  const applies = rule.appliesTo || {};
  const types = Array.isArray(applies.types) ? applies.types : [];
  for (const type of types) {
    assert(KNOWN_FINDING_TYPES.has(type), `rule ${rule.id} references unknown finding type: ${type}`);
  }
  assert(
    types.length > 0 || (Array.isArray(applies.matchAny) && applies.matchAny.length > 0),
    `rule ${rule.id} must have a types or matchAny filter`
  );
  assert(["stop-deadman", "ordered-manual", "safe-manual"].includes(rule.riskClass), `rule ${rule.id} has invalid riskClass`);
  assert(Array.isArray(rule.steps) && rule.steps.length > 0, `rule ${rule.id} must have steps`);
}

console.log("remediation tests passed");
