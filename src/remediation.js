const fs = require("fs");
const path = require("path");

const RISK_CLASS_ORDER = {
  "stop-deadman": 0,
  "ordered-manual": 1,
  "safe-manual": 2
};

const RISK_CLASS_LABELS = {
  "stop-deadman": "STOP - DO NOT REMOVE ANYTHING YET",
  "ordered-manual": "CAUTION - ORDER MATTERS",
  "safe-manual": "REVIEW - SAFE TO HANDLE"
};

function loadRemediationData() {
  const dataPath = path.join(__dirname, "..", "data", "remediation.json");
  try {
    return JSON.parse(fs.readFileSync(dataPath, "utf8"));
  } catch (error) {
    return null;
  }
}

function buildRemediationPlan(report, remediationData) {
  const data = remediationData || loadRemediationData();
  if (!data || !Array.isArray(data.rules)) return null;

  const items = [];
  for (const rule of data.rules) {
    const matchedFindings = report.findings.filter((item) => ruleMatchesFinding(rule, item));
    if (matchedFindings.length === 0) continue;
    items.push({
      id: rule.id,
      title: rule.title,
      riskClass: rule.riskClass,
      riskLabel: RISK_CLASS_LABELS[rule.riskClass] || rule.riskClass,
      warning: Array.isArray(rule.warning) ? rule.warning : [],
      steps: Array.isArray(rule.steps) ? rule.steps : [],
      doNotDo: Array.isArray(rule.doNotDo) ? rule.doNotDo : [],
      matchedFindings: matchedFindings.map((item) => ({
        severity: item.severity,
        type: item.type,
        path: item.path
      }))
    });
  }

  items.sort((left, right) => classRank(left.riskClass) - classRank(right.riskClass));

  return {
    header: Array.isArray(data.planHeader) ? data.planHeader : [],
    hasDeadManSwitch: items.some((item) => item.riskClass === "stop-deadman"),
    deadManBanner: Array.isArray(data.deadManBanner) ? data.deadManBanner : [],
    items,
    generalSteps: (data.generalStepsByRisk && data.generalStepsByRisk[report.risk]) || []
  };
}

function classRank(riskClass) {
  return Object.prototype.hasOwnProperty.call(RISK_CLASS_ORDER, riskClass)
    ? RISK_CLASS_ORDER[riskClass]
    : RISK_CLASS_ORDER["safe-manual"];
}

function ruleMatchesFinding(rule, finding) {
  const applies = rule.appliesTo || {};
  const hasTypeFilter = Array.isArray(applies.types) && applies.types.length > 0;
  const hasMarkerFilter = Array.isArray(applies.matchAny) && applies.matchAny.length > 0;

  if (hasTypeFilter && !applies.types.includes(finding.type)) return false;

  if (hasMarkerFilter) {
    const haystack = `${finding.message || ""}\n${finding.path || ""}`.toLowerCase();
    return applies.matchAny.some(
      (marker) => typeof marker === "string" && marker.length > 0 && haystack.includes(marker.toLowerCase())
    );
  }

  return hasTypeFilter;
}

module.exports = {
  loadRemediationData,
  buildRemediationPlan
};
