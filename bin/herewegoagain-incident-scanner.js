#!/usr/bin/env node
const { scanTarget } = require("../src/scanner");
const { buildRemediationPlan } = require("../src/remediation");

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }

  const report = scanTarget(args.target);
  const remediationPlan = buildRemediationPlan(report);
  if (remediationPlan?.hasDeadManSwitch) {
    report.safeRemovalGuidance.required = true;
    report.safeRemovalGuidance.sequenceSensitive = true;
  }
  if (args.remediationPlan) {
    report.remediationPlan = remediationPlan;
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printHuman(report);
    if (args.remediationPlan) {
      printRemediationPlan(report.remediationPlan);
    }
  }

  if (report.risk === "likely-exposed") return 2;
  if (report.safeRemovalGuidance.sequenceSensitive) return 4;
  return report.coverage.complete ? 0 : 3;
}

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    remediationPlan: false,
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--remediation-plan") {
      args.remediationPlan = true;
    } else if (arg === "--report" || arg.startsWith("--report=")) {
      throw new Error("--report is disabled by the no-retention policy; use --json for stdout-only output");
    } else if (!arg.startsWith("-")) {
      args.target = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`herewegoagain-incident-scanner

Read-only exposure scanner for Shai-Hulud: Here We Go Again npm/PyPI/Composer indicators.

Usage:
  node bin/herewegoagain-incident-scanner.js [target] [--json] [--remediation-plan]

Options:
  --json              print JSON report to stdout
  --remediation-plan  print a step-by-step advisory cleanup plan built from the
                      findings; dead-man's-switch warnings print first. The plan
                      is text only - this tool never executes remediation.

Exit codes:
  0  no known critical indicators found
  2  likely exposure indicators found
  3  scan coverage incomplete (without a critical finding)
  4  sequence-sensitive persistence requires incident-response review
`);
}

function printHuman(report) {
  console.log("Here We Go Again Incident Scanner");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.summary.filesScanned} files, ${report.summary.packageManifestsScanned} package manifests, ${report.summary.lockfilesScanned} lockfiles`);
  console.log(`Findings: ${report.summary.findings}`);
  console.log(`Coverage: ${report.coverage.status}`);
  console.log("");

  printPlainLanguageSummary(report);
  printSafeRemovalGuidance(report.safeRemovalGuidance);

  if (report.findings.length > 0) {
    console.log("Technical findings:");
    for (const item of report.findings) {
      console.log(`[${item.severity}] ${item.type}`);
      console.log(`  ${item.path}`);
      console.log(`  ${item.message}`);
    }
    console.log("");
  }

  console.log("Guidance:");
  for (const item of report.guidance) {
    console.log(`- ${item}`);
  }

}

function printSafeRemovalGuidance(guidance) {
  console.log("Safe removal guidance:");
  console.log(`- ${guidance.firstAction}`);
  console.log(`- Instructions: ${guidance.instructionDestination}`);
  console.log(`- ${guidance.retention}`);
  console.log("");
}

function printPlainLanguageSummary(report) {
  if (report.risk === "likely-exposed") {
    console.log("STOP");
    console.log("This project references known compromised Shai-Hulud: Here We Go Again indicators.");
    console.log("Do not run npm, pnpm, yarn, bun, pip, composer, build, test, or dev-server commands here until reviewed.");
    console.log("If execution is possible, follow the safe-removal guidance below before rotating credentials.");
    console.log("");
    return;
  }

  if (report.risk === "possible-exposure" || report.risk === "review-needed") {
    console.log("PAUSE");
    console.log("This project has suspicious, historical, or currentness-unverified review signals.");
    console.log("Review the findings before running package installs or builds. Exact known-bad versions are listed as critical findings.");
    console.log("");
    return;
  }

  console.log("No known compromised package, payload, or persistence indicators were found by this scanner within completed coverage.");
  console.log("This does not prove the host is clean; it only covers the indicators this tool knows about.");
  console.log("");
}

function printRemediationPlan(plan) {
  console.log("");
  console.log("==================================================================");
  console.log("REMEDIATION PLAN (advisory text only - nothing has been changed)");
  console.log("==================================================================");
  for (const line of plan.header) {
    console.log(line);
  }
  console.log("");

  if (plan.items.length === 0) {
    for (const line of plan.generalSteps) {
      console.log(`- ${line}`);
    }
    return;
  }

  if (plan.hasDeadManSwitch) {
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    for (const line of plan.deadManBanner) {
      console.log(`!! ${line}`);
    }
    console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    console.log("");
  }

  for (const item of plan.items) {
    console.log(`[${item.riskLabel}]`);
    console.log(item.title);
    if (item.evidence) {
      console.log(`  evidence status: ${item.evidence.status || "unverified"}`);
      console.log(`  evidence confidence: ${item.evidence.confidence || "unverified"}`);
      if (item.evidence.lastVerified) console.log(`  evidence last verified: ${item.evidence.lastVerified}`);
      if (item.evidence.source) console.log(`  evidence source: ${item.evidence.source}`);
      if (Array.isArray(item.evidence.sources)) {
        for (const source of item.evidence.sources) console.log(`  evidence source: ${source}`);
      }
    }
    for (const matched of item.matchedFindings) {
      console.log(`  found: [${matched.severity}] ${matched.type} ${matched.path}`);
    }
    for (const line of item.warning) {
      console.log(`  WARNING: ${line}`);
    }
    item.steps.forEach((step, index) => {
      console.log(`  ${index + 1}. ${step}`);
    });
    for (const line of item.doNotDo) {
      console.log(`  DO NOT: ${line}`);
    }
    console.log("");
  }

  console.log("After the items above:");
  for (const line of plan.generalSteps) {
    console.log(`- ${line}`);
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
