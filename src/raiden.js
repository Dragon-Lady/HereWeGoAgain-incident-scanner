"use strict";

const name = "raiden-baileys";
const packages = { [name]: ["*"] };
const evidence = {
  source: "https://osv.dev/vulnerability/MAL-2026-19108",
  lastVerified: "2026-11-24",
  activation: "not-assessed"
};

function manifestReferences(manifest) {
  if (manifest.name === name && typeof manifest.version === "string" && manifest.version) return true;
  for (const section of ["dependencies", "optionalDependencies", "devDependencies", "peerDependencies"]) {
    for (const [label, spec] of Object.entries(manifest[section] || {})) {
      if (typeof spec !== "string") continue;
      if (/^npm:raiden-baileys(?:@[^:/\\]*)?$/.test(spec)) return true;
      // Registry versions, tags and ranges. A local path, URL, Git shorthand
      // or alias to another package does not establish this registry identity.
      if (label === name && !/[:/\\#]/.test(spec) && !spec.startsWith(".")) return true;
    }
  }
  return false;
}

function finding(filePath) {
  return {
    severity: "critical",
    type: "raiden-baileys-package",
    path: filePath,
    message: "Package metadata identifies raiden-baileys. OpenSSF reports that this npm fork silently follows WhatsApp newsletters on connection. Review the resolved dependency and, if used, check account subscriptions from a trusted client. Local execution and account changes are unverified.",
    evidence
  };
}

module.exports = { manifestReferences, packages, finding };
