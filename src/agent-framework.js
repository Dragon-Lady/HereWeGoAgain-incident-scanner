"use strict";

const name = "agent-framework";
const source = "https://github.com/microsoft/agent-framework/issues/10411#issuecomment-6961285339";
const hashes = new Map([
  ["1.26.1", "d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110"],
  ["1.26.2", "3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9"],
]);
const guidance = "Do not start Python or pip in a suspected environment. The reported startup hook can run before application imports. Preserve evidence and contact incident response. If Python ran after installation, contain the environment and review reachable credentials from a trusted device.";
function wheelVersion(base) {
  for (const version of hashes.keys()) {
    if (base === `agent_framework-${version}-py3-none-any.whl`) return version;
  }
  return null;
}
function finding(path, version, severity, type, message) {
  return {path, severity, type, message, evidence: {source, lastVerified: "2026-11-17", package: name, version, activation: "not-assessed"}};
}
function metadataFinding(path, version) {
  return finding(path, version, "critical", "agent-framework-exact-version",
    `Package metadata identifies agent-framework ${version}, a reported malicious PyPI release. Installation and execution are unverified. ${guidance}`);
}
function wheelFinding(path, version, digest) {
  if (digest === hashes.get(version)) {
    return finding(path, version, "critical", "agent-framework-wheel-hash",
      `Wheel bytes match the published SHA-256 for agent-framework ${version}. A cached wheel does not establish execution. ${guidance}`);
  }
  return finding(path, version, "medium", "agent-framework-wheel-review",
    `Wheel filename references agent-framework ${version}, but the bytes differ from the published malicious wheel. Verify the artifact offline.`);
}
module.exports = {name, guidance, wheelVersion, hasVersion: version => hashes.has(version), metadataFinding, wheelFinding};
