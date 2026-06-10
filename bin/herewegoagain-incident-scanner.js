#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { buildRemediationPlan } = require("../src/remediation");

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }

  const report = scanTarget(args.target);
  if (args.remediationPlan) {
    report.remediationPlan = buildRemediationPlan(report);
  }

  let writtenReportPath = "";
  if (args.reportPath) {
    writtenReportPath = path.resolve(args.reportPath);
    fs.writeFileSync(writtenReportPath, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printHuman(report, writtenReportPath);
    if (args.remediationPlan) {
      printRemediationPlan(report.remediationPlan);
    }
  }

  return report.risk === "likely-exposed" ? 2 : 0;
}

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    reportPath: "",
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
    } else if (arg === "--report") {
      args.reportPath = argv[index + 1] || "";
      if (!args.reportPath) throw new Error("--report requires a file path");
      index += 1;
    } else if (arg.startsWith("--report=")) {
      args.reportPath = arg.slice("--report=".length);
      if (!args.reportPath) throw new Error("--report requires a file path");
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

Read-only exposure scanner for Shai-Hulud: Here We Go Again npm/PyPI indicators.

Usage:
  node bin/herewegoagain-incident-scanner.js [target] [--json] [--report report.json] [--remediation-plan]

Options:
  --json              print JSON report to stdout
  --report <path>     write JSON report to a specific path
  --remediation-plan  print a step-by-step advisory cleanup plan built from the
                      findings; dead-man's-switch warnings print first. The plan
                      is text only - this tool never executes remediation.

Exit codes:
  0  no known critical indicators found
  2  likely exposure indicators found
`);
}

function printHuman(report, writtenReportPath) {
  console.log("Here We Go Again Incident Scanner");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.summary.filesScanned} files, ${report.summary.packageManifestsScanned} package manifests, ${report.summary.lockfilesScanned} lockfiles`);
  console.log(`Findings: ${report.summary.findings}`);
  console.log("");

  printPlainLanguageSummary(report);

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

  if (writtenReportPath) {
    console.log("");
    console.log(`JSON report written: ${writtenReportPath}`);
  }
}

function printPlainLanguageSummary(report) {
  if (report.risk === "likely-exposed") {
    console.log("STOP");
    console.log("This project references known compromised Shai-Hulud: Here We Go Again indicators.");
    console.log("Do not run npm, pnpm, yarn, bun, pip, composer, build, test, or dev-server commands here until reviewed.");
    console.log("If this package may have already executed, rotate secrets from a clean machine and check dev-tool persistence.");
    console.log("");
    return;
  }

  if (report.risk === "possible-exposure" || report.risk === "review-needed") {
    console.log("PAUSE");
    console.log("This project has suspicious or active-campaign-adjacent dependency signals.");
    console.log("Review the findings before running package installs or builds. Exact known-bad versions are listed as critical findings.");
    console.log("");
    return;
  }

  console.log("No known compromised package, payload, or persistence indicators were found by this scanner.");
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
