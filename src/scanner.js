const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;
const LOCKFILES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock"
]);
const PYTHON_DEPENDENCY_FILES = new Set(["requirements.txt", "pyproject.toml", "uv.lock", "Pipfile.lock"]);
const COMPOSER_DEPENDENCY_FILES = new Set(["composer.json", "composer.lock"]);
const APACHE_HTTPD_FILES = new Set(["httpd.conf", "apache2.conf", "ports.conf", "mods-enabled-http2.conf"]);
const PACKAGE_MANIFEST = "package.json";
const NODE_GYP_MANIFEST = "binding.gyp";
const TOOL_CONFIG_FILES = new Set(["settings.json", "settings.local.json", "tasks.json", "extensions.json"]);
const CURSOR_RULE_EXTENSIONS = new Set([".mdc"]);
const JAVASCRIPT_SOURCE_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);
const WEB_SOURCE_EXTENSIONS = new Set([".html", ".htm"]);
const NOTEBOOK_SOURCE_EXTENSIONS = new Set([".ipynb"]);
const PHP_SOURCE_EXTENSIONS = new Set([".php"]);
const SHELL_SOURCE_EXTENSIONS = new Set([".sh", ".bash", ".zsh"]);
const SHADOWABLE_TOOL_NAMES = new Set(["ssh", "git", "npm", "node", "python", "powershell", "gh", "claude", "codex", "composer", "pnpm", "yarn"]);
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);
const LANGFLOW_UPLOAD_FIXED = "1.9.1";
const LANGFLOW_WEBHOOK_AFFECTED_MAX = "1.8.4";
const LANGFLOW_WEBHOOK_FIXED = "1.9.1";
const LANGFLOW_PYTHON_REPL_FIXED = "1.9.4";
const LIVEWIRE_AFFECTED_MIN = "3.0.0";
const LIVEWIRE_FIXED = "3.6.4";

const DEFAULT_ADVISORY = {
  indicators: {
    maliciousOptionalDependencyName: "@tanstack/setup",
    maliciousOptionalDependencySpec: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    payloadFiles: ["router_init.js", "tanstack_runner.js", "router_runtime.js"],
    payloadFileHashes: {
      "router_init.js": [
        "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
        "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
      ],
      "router_runtime.js": [
        "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
      ],
      "tanstack_runner.js": [
        "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
      ]
    }
  },
  packages: {},
  pypiPackages: {},
  composerPackages: {}
};

function loadAdvisoryData() {
  const dataDir = path.join(__dirname, "..", "data");
  try {
    const raw = loadSplitAdvisoryData(dataDir);
    return normalizeAdvisory(raw);
  } catch (error) {
    const legacyPath = path.join(dataDir, "affected-packages.json");
    try {
      const raw = JSON.parse(fs.readFileSync(legacyPath, "utf8"));
      return normalizeAdvisory(raw);
    } catch (legacyError) {
      if (error.code === "ENOENT" || legacyError.code === "ENOENT") return DEFAULT_ADVISORY;
    }
    return DEFAULT_ADVISORY;
  }
}

function loadSplitAdvisoryData(dataDir) {
  const advisory = readJsonFile(path.join(dataDir, "advisory.json"));
  return {
    ...advisory,
    indicators: readJsonFile(path.join(dataDir, "indicators.json")),
    packages: readJsonFile(path.join(dataDir, "packages", "npm.json")),
    pypiPackages: readJsonFile(path.join(dataDir, "packages", "pypi.json")),
    composerPackages: readJsonFile(path.join(dataDir, "packages", "composer.json"))
  };
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function scanTarget(targetPath, options = {}) {
  const root = path.resolve(targetPath || ".");
  const advisory = options.advisory || loadAdvisoryData();
  const payloadFiles = new Set(advisory.indicators.payloadFiles || DEFAULT_ADVISORY.indicators.payloadFiles);
  const findings = [];
  const seen = { files: 0, manifests: 0, lockfiles: 0 };

  walk(root, (filePath, dirent) => {
    seen.files += 1;
    const base = dirent.name;

    if (payloadFiles.has(base)) {
      findings.push(finding("critical", "payload-file", filePath, `Known incident payload filename present: ${base}`));
      scanPayloadHash(filePath, base, advisory, findings);
    }

    if (base === PACKAGE_MANIFEST) {
      seen.manifests += 1;
      scanPackageJson(filePath, advisory, findings);
      return;
    }

    if (base === NODE_GYP_MANIFEST) {
      scanNodeGypManifest(filePath, advisory, findings);
      return;
    }

    if (LOCKFILES.has(base)) {
      seen.lockfiles += 1;
      scanTextFile(filePath, advisory, findings);
      return;
    }

    if (isPythonDependencyFile(base)) {
      scanPythonDependencyFile(filePath, advisory, findings);
      return;
    }

    if (COMPOSER_DEPENDENCY_FILES.has(base)) {
      scanComposerDependencyFile(filePath, advisory, findings);
      return;
    }

    if (isApacheHttpdFile(filePath, base)) {
      scanApacheHttpdFile(filePath, advisory, findings);
      return;
    }

    if (isToolConfigFile(filePath, base)) {
      scanToolConfigFile(filePath, advisory, findings);
      return;
    }

    if (isWorkflowFile(filePath, base)) {
      scanWorkflowFile(filePath, advisory, findings);
      return;
    }

    if (isShellSourceFile(filePath, base) || isShadowableToolFile(base)) {
      scanShellSourceFile(filePath, base, advisory, findings);
      return;
    }

    if (isJavaScriptSourceFile(filePath)) {
      scanJavaScriptSourceFile(filePath, advisory, findings);
      return;
    }

    if (isWebSourceFile(filePath)) {
      scanWebSourceFile(filePath, advisory, findings);
      return;
    }

    if (isNotebookSourceFile(filePath)) {
      scanNotebookSourceFile(filePath, advisory, findings);
      return;
    }

    if (isPhpSourceFile(filePath)) {
      scanPhpSourceFile(filePath, advisory, findings);
    }
  });

  const dedupedFindings = dedupeFindings(findings);
  const risk = riskLevel(dedupedFindings);
  return {
    tool: "herewegoagain-incident-scanner",
    scannedAt: new Date().toISOString(),
    target: root,
    risk,
    summary: {
      filesScanned: seen.files,
      packageManifestsScanned: seen.manifests,
      lockfilesScanned: seen.lockfiles,
      findings: dedupedFindings.length
    },
    findings: dedupedFindings,
    guidance: guidanceForRisk(risk)
  };
}

function walk(root, onFile) {
  let rootStat;
  try {
    rootStat = fs.statSync(root);
  } catch (error) {
    return;
  }

  if (rootStat.isFile()) {
    onFile(root, { name: path.basename(root) });
    return;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(fullPath);
      } else if (entry.isFile()) {
        onFile(fullPath, entry);
      }
    }
  }
}

function scanPayloadHash(filePath, fileName, advisory, findings) {
  const knownHashes = advisory.indicators.payloadFileHashes?.[fileName];
  if (!Array.isArray(knownHashes) || knownHashes.length === 0) return;

  let data;
  try {
    data = fs.readFileSync(filePath);
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not hash payload candidate: ${error.message}`));
    return;
  }

  const sha256 = crypto.createHash("sha256").update(data).digest("hex");
  if (knownHashes.includes(sha256)) {
    findings.push(finding("critical", "payload-hash", filePath, `${fileName} matches known malicious SHA-256 ${sha256}.`));
  }
}

function scanPackageJson(filePath, advisory, findings) {
  let rawText;
  let manifest;
  try {
    rawText = fs.readFileSync(filePath, "utf8");
    manifest = JSON.parse(rawText);
  } catch (error) {
    findings.push(finding("low", "parse-error", filePath, `Could not parse package.json: ${error.message}`));
    return;
  }

  scanManifestText(filePath, rawText, advisory, findings);

  if (manifest.name && manifest.version && versionIsListed(advisory.packages[manifest.name], manifest.version)) {
    findings.push(finding("critical", "known-bad-version", filePath, `${manifest.name}@${manifest.version} is listed as compromised.`));
  }

  const dependencySections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies"];
  for (const section of dependencySections) {
    const deps = manifest[section];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;

    for (const [name, spec] of Object.entries(deps)) {
      inspectDependencySpec(filePath, section, name, String(spec), advisory, findings);
    }
  }

  const scripts = manifest.scripts || {};
  for (const scriptName of LIFECYCLE_SCRIPTS) {
    if (typeof scripts[scriptName] === "string") {
      const scriptBody = scripts[scriptName];
      const severity = scriptName === "prepare" && /bun\s+run|router_|tanstack_/i.test(scriptBody) ? "high" : "medium";
      findings.push(finding(severity, "lifecycle-script", filePath, `Lifecycle script "${scriptName}" is present: ${scriptBody}`));
    }
  }
}

function scanManifestText(filePath, text, advisory, findings) {
  const indicators = advisory.indicators;

  for (const payload of indicators.payloadFiles) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "payload-reference", filePath, `Manifest references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Manifest");
}

function scanNodeGypManifest(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read binding.gyp: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "binding.gyp");

  const commandExpansions = text.match(/<!\([\s\S]*?\)/g) || [];
  for (const expansion of commandExpansions) {
    const suspicious =
      /\b(node|bun|curl|wget|powershell|pwsh|bash|sh|python|python3)\b/i.test(expansion) ||
      /\/tmp\/|%TEMP%|\.js\b|>\s*\/dev\/null|2>&1/i.test(expansion);
    findings.push(finding(
      suspicious ? "high" : "medium",
      suspicious ? "binding-gyp-command-execution" : "binding-gyp-command-expansion",
      filePath,
      `binding.gyp contains node-gyp command expansion ${expansion.slice(0, 180)}${expansion.length > 180 ? "..." : ""}`
    ));
  }
}

function normalizeAdvisory(raw) {
  const advisory = {
    indicators: {
      ...DEFAULT_ADVISORY.indicators,
      ...(raw && typeof raw.indicators === "object" ? raw.indicators : {})
    },
    packages: {},
    pypiPackages: {},
    composerPackages: {}
  };

  if (raw && raw.packages && typeof raw.packages === "object" && !Array.isArray(raw.packages)) {
    for (const [name, versions] of Object.entries(raw.packages)) {
      addAdvisoryPackage(advisory.packages, name, versions);
    }
  } else if (Array.isArray(raw)) {
    for (const item of raw) {
      if (!item || typeof item !== "object") continue;
      addAdvisoryPackage(advisory.packages, item.name || item.package || item.packageName, item.version || item.versions);
    }
  } else if (raw && typeof raw === "object") {
    for (const [name, versions] of Object.entries(raw)) {
      if (name === "indicators") continue;
      addAdvisoryPackage(advisory.packages, name, versions);
    }
  }

  if (raw && raw.pypiPackages && typeof raw.pypiPackages === "object" && !Array.isArray(raw.pypiPackages)) {
    for (const [name, versions] of Object.entries(raw.pypiPackages)) {
      addAdvisoryPackage(advisory.pypiPackages, normalizePythonPackageName(name), versions);
    }
  }

  if (raw && raw.composerPackages && typeof raw.composerPackages === "object" && !Array.isArray(raw.composerPackages)) {
    for (const [name, versions] of Object.entries(raw.composerPackages)) {
      addAdvisoryPackage(advisory.composerPackages, name.toLowerCase(), versions);
    }
  }

  return advisory;
}

function addAdvisoryPackage(packages, name, versions) {
  if (typeof name !== "string" || name.length === 0) return;
  const normalizedVersions = Array.isArray(versions) ? versions : [versions];
  const cleanVersions = normalizedVersions.filter((version) => typeof version === "string" && version.length > 0);
  if (cleanVersions.length > 0) packages[name] = cleanVersions;
}

function inspectDependencySpec(filePath, section, name, spec, advisory, findings) {
  const indicators = advisory.indicators;

  if (name === indicators.maliciousOptionalDependencyName) {
    findings.push(finding("critical", "malicious-dependency-name", filePath, `${section} contains ${name}.`));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency && name === dependency.name) {
      findings.push(finding("critical", "malicious-dependency-name", filePath, `${section} contains ${name}.`));
    }
  }

  if (
    indicators.maliciousOptionalDependencySpec &&
    spec.includes(indicators.maliciousOptionalDependencySpec)
  ) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, `${section}.${name} points to the known malicious GitHub commit.`));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency?.spec && spec.includes(dependency.spec)) {
      findings.push(finding("critical", "malicious-dependency-spec", filePath, `${section}.${name} points to a known malicious GitHub commit.`));
    }
  }

  if (/^github:/i.test(spec) || /github\.com[:/]/i.test(spec)) {
    const severity = section === "optionalDependencies" ? "high" : "medium";
    findings.push(finding(severity, "github-dependency", filePath, `${section}.${name} resolves from GitHub: ${spec}`));
  }

  if (matchesActiveNamespace(name, advisory)) {
    findings.push(finding("medium", "active-campaign-namespace", filePath, `${section}.${name} is in a namespace reported in the active campaign; verify the exact version.`));
  }

  if (matchesActivePackage(name, advisory)) {
    findings.push(finding("medium", "active-campaign-package", filePath, `${section}.${name} is a package reported in the active campaign; verify the exact version.`));
  }

  const reviewPrompt = packageReviewPrompt(name, advisory);
  if (reviewPrompt) {
    findings.push(finding("medium", "package-review-prompt", filePath, `${section}.${name}: ${reviewPrompt}`));
  }

  if (versionIsListed(advisory.packages[name], spec)) {
    findings.push(finding("critical", "known-bad-requested-version", filePath, `${section}.${name} requests compromised version ${spec}.`));
  }
}

function scanTextFile(filePath, advisory, findings) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    return;
  }
  if (stat.size > DEFAULT_MAX_FILE_BYTES) {
    findings.push(finding("low", "large-lockfile-skipped", filePath, `Skipped lockfile over ${DEFAULT_MAX_FILE_BYTES} bytes.`));
    return;
  }

  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read lockfile: ${error.message}`));
    return;
  }

  const indicators = advisory.indicators;
  for (const payload of indicators.payloadFiles) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "payload-reference", filePath, `Lockfile references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Lockfile");

  if (
    indicators.maliciousOptionalDependencyName &&
    text.includes(indicators.maliciousOptionalDependencyName)
  ) {
    findings.push(finding("critical", "malicious-dependency-name", filePath, `Lockfile references ${indicators.maliciousOptionalDependencyName}.`));
  }

  if (
    indicators.maliciousOptionalDependencySpec &&
    text.includes(indicators.maliciousOptionalDependencySpec)
  ) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, "Lockfile references the known malicious GitHub commit."));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency?.name && text.includes(dependency.name)) {
      findings.push(finding("critical", "malicious-dependency-name", filePath, `Lockfile references ${dependency.name}.`));
    }
    if (dependency?.spec && text.includes(dependency.spec)) {
      findings.push(finding("critical", "malicious-dependency-spec", filePath, "Lockfile references a known malicious GitHub commit."));
    }
  }

  for (const [pkg, versions] of Object.entries(advisory.packages)) {
    if (packageIsListedAllVersions(versions) && text.includes(pkg)) {
      findings.push(finding("critical", "known-bad-lockfile-package", filePath, `Lockfile references ${pkg}, which is listed as compromised for all observed versions.`));
      continue;
    }
    for (const version of versions) {
      if (version === "*") continue;
      if (lockfileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-lockfile-version", filePath, `Lockfile references ${pkg}@${version}.`));
      }
    }
  }

  for (const namespace of advisory.indicators.activeNamespaces || []) {
    if (typeof namespace === "string" && namespace.length > 0 && text.includes(namespace)) {
      findings.push(finding("medium", "active-campaign-namespace", filePath, `Lockfile references namespace reported in the active campaign: ${namespace}`));
    }
  }

  for (const pkg of advisory.indicators.activePackages || []) {
    if (typeof pkg === "string" && pkg.length > 0 && text.includes(pkg)) {
      findings.push(finding("medium", "active-campaign-package", filePath, `Lockfile references package reported in the active campaign: ${pkg}`));
    }
  }

  for (const [pkg, message] of Object.entries(advisory.indicators.packageReviewPrompts || {})) {
    if (typeof pkg === "string" && pkg.length > 0 && text.includes(pkg)) {
      findings.push(finding("medium", "package-review-prompt", filePath, `Lockfile references ${pkg}: ${message}`));
    }
  }
}

function scanPythonDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Python dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Python dependency file");
  scanLangflowDependencyText(filePath, text, findings, "Python dependency file");

  for (const [pkg, versions] of Object.entries(advisory.pypiPackages || {})) {
    for (const version of versions) {
      if (pythonFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-pypi-version", filePath, `Python dependency file references ${pkg}==${version}.`));
      }
    }
  }
}

function scanLangflowDependencyText(filePath, text, findings, sourceLabel) {
  for (const version of pythonPackageVersionsInText(text, "langflow")) {
    if (compareDottedVersions(version, LANGFLOW_PYTHON_REPL_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-10561-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-10561 PythonREPL unauthenticated RCE. Upgrade to langflow>=${LANGFLOW_PYTHON_REPL_FIXED}.`));
    }
    if (compareDottedVersions(version, LANGFLOW_WEBHOOK_AFFECTED_MAX) <= 0) {
      findings.push(finding("critical", "langflow-cve-2026-7664-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-7664 unauthenticated webhook/MCP flow execution. Upgrade to langflow>=${LANGFLOW_WEBHOOK_FIXED}.`));
    }
    if (compareDottedVersions(version, LANGFLOW_UPLOAD_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-55450-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-55450. Upgrade to langflow>=${LANGFLOW_UPLOAD_FIXED}.`));
    }
  }
}

function scanComposerDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Composer dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Composer dependency file");
  scanLaravelLangAutoloadBackdoor(filePath, text, advisory, findings);
  scanComposerPluginCapabilities(filePath, text, findings);
  scanLivewireComposerText(filePath, text, findings, "Composer dependency file");

  for (const [pkg, versions] of Object.entries(advisory.composerPackages || {})) {
    for (const version of versions) {
      if (composerFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-composer-version", filePath, `Composer dependency file references ${pkg}@${version}.`));
      }
    }
  }

  for (const [pkg, message] of Object.entries(advisory.indicators.composerReviewPrompts || {})) {
    if (typeof pkg === "string" && pkg.length > 0 && text.toLowerCase().includes(pkg.toLowerCase())) {
      findings.push(finding("medium", "composer-package-review-prompt", filePath, `Composer dependency file references ${pkg}: ${message}`));
    }
  }
}

function scanLivewireComposerText(filePath, text, findings, sourceLabel) {
  const versions = composerPackageVersionsInText(text, "livewire/livewire");
  for (const version of versions) {
    if (compareDottedVersions(version, LIVEWIRE_AFFECTED_MIN) >= 0 && compareDottedVersions(version, LIVEWIRE_FIXED) < 0) {
      findings.push(finding("critical", "livewire-cve-2025-54068-vulnerable-version", filePath, `${sourceLabel} references livewire/livewire ${version}, affected by CVE-2025-54068. Upgrade to livewire/livewire>=${LIVEWIRE_FIXED}.`));
    }
  }

  if (versions.length === 0 && composerConstraintNeedsLivewireReview(text)) {
    findings.push(finding("medium", "livewire-cve-2025-54068-version-range-review", filePath, `${sourceLabel} references a broad livewire/livewire v3 constraint. Verify the resolved lockfile is livewire/livewire>=${LIVEWIRE_FIXED}.`));
  }
}

function scanLaravelLangAutoloadBackdoor(filePath, text, advisory, findings) {
  const prompts = Object.keys(advisory.indicators.composerReviewPrompts || {});
  const laravelLangPackages = prompts.filter((pkg) => pkg.startsWith("laravel-lang/"));
  if (laravelLangPackages.length === 0) return;

  const lowerText = text.toLowerCase();
  const hasLaravelLangPackage = laravelLangPackages.some((pkg) => lowerText.includes(pkg.toLowerCase()));
  if (!hasLaravelLangPackage) return;

  const hasAutoloadFiles =
    /"autoload"\s*:/i.test(text) &&
    /"files"\s*:\s*\[[\s\S]{0,800}"src\/helpers\.php"/i.test(text);
  if (!hasAutoloadFiles) return;

  findings.push(finding(
    "critical",
    "laravel-lang-autoload-backdoor",
    filePath,
    "Composer dependency metadata for laravel-lang includes autoload.files -> src/helpers.php, matching Socket's reported RCE backdoor shape."
  ));
}

function scanComposerPluginCapabilities(filePath, text, findings) {
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    return;
  }

  const packages = [];
  if (Array.isArray(manifest.packages)) packages.push(...manifest.packages);
  if (Array.isArray(manifest["packages-dev"])) packages.push(...manifest["packages-dev"]);
  if (manifest && typeof manifest === "object" && !Array.isArray(manifest)) packages.push(manifest);

  for (const pkg of packages) {
    if (!pkg || typeof pkg !== "object") continue;
    const name = typeof pkg.name === "string" ? pkg.name : "(root composer package)";
    const version = typeof pkg.version === "string" ? `@${pkg.version}` : "";
    const requireBlock = pkg.require && typeof pkg.require === "object" ? pkg.require : {};
    const extra = pkg.extra && typeof pkg.extra === "object" ? pkg.extra : {};
    const pluginClass = extra.class || extra["plugin-class"];
    const hasPluginType = pkg.type === "composer-plugin";
    const hasPluginApi = Object.prototype.hasOwnProperty.call(requireBlock, "composer-plugin-api");
    const hasPluginEntry = typeof pluginClass === "string" || Array.isArray(pluginClass);

    if (hasPluginType || hasPluginApi || hasPluginEntry) {
      const capabilities = [];
      if (hasPluginType) capabilities.push("type=composer-plugin");
      if (hasPluginApi) capabilities.push("require=composer-plugin-api");
      if (hasPluginEntry) capabilities.push("extra.class/plugin-class");
      findings.push(finding(
        "high",
        "composer-plugin-capability",
        filePath,
        `Composer package ${name}${version} declares install/update-time plugin capability (${capabilities.join(", ")}); verify this is expected and matches upstream source.`
      ));
    }
  }
}

function scanApacheHttpdFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Apache httpd file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Apache httpd file");

  const modHttp2Version = extractModHttp2Version(text);
  if (modHttp2Version) {
    const vulnerable = compareDottedVersions(modHttp2Version, "2.0.41") < 0;
    findings.push(finding(
      vulnerable ? "high" : "medium",
      vulnerable ? "apache-http2-bomb-vulnerable-mod-http2" : "apache-http2-bomb-fixed-mod-http2",
      filePath,
      vulnerable
        ? `Apache mod_http2 ${modHttp2Version} is below the 2.0.41 fix for CVE-2026-49975 / HTTP/2 Bomb; upgrade mod_http2 or disable HTTP/2 until patched.`
        : `Apache mod_http2 ${modHttp2Version} is at or above the 2.0.41 fix floor for CVE-2026-49975 / HTTP/2 Bomb; verify the running module matches this file.`
    ));
    return;
  }

  if (/\bmod_http2\b/i.test(text) || /^\s*Protocols\s+.*\bh2\b/im.test(text) || /^\s*LoadModule\s+http2_module\b/im.test(text)) {
    findings.push(finding(
      "medium",
      "apache-http2-bomb-review",
      filePath,
      "Apache HTTP/2 appears enabled or mod_http2 is referenced; verify mod_http2 is 2.0.41 or newer, or disable HTTP/2 until patched for CVE-2026-49975."
    ));
  }
}

function extractModHttp2Version(text) {
  const patterns = [
    /\bmod_http2\b[^\n\r]{0,80}?\bv?(\d+\.\d+\.\d+)\b/i,
    /\bmod_h2\b[^\n\r]{0,80}?\bv?(\d+\.\d+\.\d+)\b/i,
    /\bhttp2_module\b[^\n\r]{0,80}?\bv?(\d+\.\d+\.\d+)\b/i
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1];
  }
  return "";
}

function compareDottedVersions(left, right) {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = leftParts[index] || 0;
    const rightPart = rightParts[index] || 0;
    if (leftPart < rightPart) return -1;
    if (leftPart > rightPart) return 1;
  }
  return 0;
}

function scanToolConfigFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read tool config file: ${error.message}`));
    return;
  }

  const indicators = advisory.indicators;
  for (const payload of indicators.payloadFiles || []) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "tool-config-payload-reference", filePath, `Tool config references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Tool config");
  scanMiasmaAgentConfigShape(filePath, text, findings);
}

function scanMiasmaAgentConfigShape(filePath, text, findings) {
  if (!/node\s+\.github\/setup\.js/i.test(text)) return;

  const normalized = filePath.replace(/\\/g, "/");
  const isAgentSessionHook =
    normalized.includes("/.claude/") ||
    normalized.includes("/.gemini/") ||
    /SessionStart/i.test(text);
  const isCursorRule =
    normalized.includes("/.cursor/rules/") ||
    /alwaysApply\s*:\s*true/i.test(text);
  const isVsCodeFolderOpen =
    normalized.includes("/.vscode/") ||
    /runOn"\s*:\s*"folderOpen/i.test(text) ||
    /runOn\s*:\s*folderOpen/i.test(text);

  if (isAgentSessionHook || isCursorRule || isVsCodeFolderOpen) {
    findings.push(finding(
      "critical",
      "miasma-agent-config-trigger",
      filePath,
      "Tool config auto-runs node .github/setup.js through an AI-agent or editor trigger; this matches the reported Miasma source-repo persistence pattern."
    ));
  }
}

function scanWorkflowFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read workflow file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "GitHub Actions workflow");
  scanClaudeCodeActionWorkflow(filePath, text, findings);

  if (
    (/\bbase64\b/i.test(text) && /\b(curl|wget|bash|sh|python|node)\b/i.test(text)) ||
    (/curl\s+-skL\b/i.test(text) && /chmod\s+\+x\s+\/tmp\/\.sshd/i.test(text))
  ) {
    findings.push(finding("high", "workflow-encoded-exec", filePath, "GitHub Actions workflow combines base64 with shell/network execution; review for CI secret exfiltration."));
  }

  if (
    /\b(ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|GITHUB_TOKEN)\b/.test(text) ||
    /id-token\s*:\s*write/i.test(text)
  ) {
    findings.push(finding("medium", "workflow-token-surface", filePath, "GitHub Actions workflow references CI token/OIDC variables; verify it is expected and not exfiltrated."));
  }
}

function scanClaudeCodeActionWorkflow(filePath, text, findings) {
  if (!/anthropics\/claude-code-action@/i.test(text)) return;

  findings.push(finding(
    "medium",
    "claude-code-action-workflow",
    filePath,
    "GitHub Actions workflow uses anthropics/claude-code-action; verify it is patched to v1.0.94 or newer and does not process untrusted issue/PR input with broad permissions."
  ));

  if (/allowed_non_write_users\s*:\s*['"]?\*/i.test(text)) {
    findings.push(finding(
      "high",
      "claude-code-action-untrusted-users",
      filePath,
      "Claude Code Action allows all non-write users; restrict callers and avoid secrets or permissions that can exfiltrate data."
    ));
  }

  if (
    /on\s*:[\s\S]{0,800}\b(issues|issue_comment|pull_request_review|pull_request_review_comment)\s*:/i.test(text) &&
    /id-token\s*:\s*write/i.test(text)
  ) {
    findings.push(finding(
      "high",
      "claude-code-action-oidc-untrusted-trigger",
      filePath,
      "Claude Code Action is reachable from issue/PR events while id-token: write is enabled; audit for GitHub App/OIDC token exfiltration risk."
    ));
  }

  if (
    /allowed_non_write_users\s*:/i.test(text) &&
    /\b(contents|issues|pull-requests|discussions|actions)\s*:\s*write/i.test(text)
  ) {
    findings.push(finding(
      "high",
      "claude-code-action-write-permission-untrusted-users",
      filePath,
      "Claude Code Action combines allowed_non_write_users with write permissions; this matches the risky misconfiguration pattern described in the Flatt/THN report."
    ));
  }

  if (/mcp__github__get_issue/i.test(text) && /mcp__github__update_issue/i.test(text)) {
    findings.push(finding(
      "medium",
      "claude-code-action-github-mcp-exfil-surface",
      filePath,
      "Claude Code Action allows both GitHub issue read and update MCP tools; review prompt-injection and issue-body exfiltration risk."
    ));
  }
}

function scanJavaScriptSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read JavaScript source file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "JavaScript source file");
  scanMiasmaSecondStageShape(filePath, text, findings);
  scanShaiHuludSshPropagationShape(filePath, text, findings);
}

function scanWebSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read web source file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Web source file");
}

function scanNotebookSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read notebook file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Notebook file");
}

function scanPhpSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read PHP source file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "PHP source file");
}

function scanShellSourceFile(filePath, base, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read shell/tool candidate file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Shell/tool candidate file");
  scanShaiHuludSshPropagationShape(filePath, text, findings);

  if (isShadowableToolFile(base) && /^#!.*\b(bash|sh|zsh|python|node)\b/im.test(text)) {
    findings.push(finding("high", "tool-shadowing-candidate", filePath, `Repo-local executable-like file is named like a trusted tool: ${base}`));
  }
}

function scanIndicatorStrings(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const stringGroups = [
    ["network-indicator", indicators.networkIndicators],
    ["workflow-indicator", indicators.workflowIndicators],
    ["campaign-indicator", indicators.campaignIndicators]
  ];

  if (typeof indicators.tokenDescriptionIndicator === "string") {
    stringGroups.push(["token-description-indicator", [indicators.tokenDescriptionIndicator]]);
  }

  for (const [type, values] of stringGroups) {
    if (!Array.isArray(values)) continue;
    for (const value of values) {
      if (typeof value !== "string" || value.length === 0) continue;
      if (text.includes(value)) {
        findings.push(finding("high", type, filePath, `${sourceLabel} references incident indicator: ${value}`));
      }
    }
  }
}

function scanMiasmaSecondStageShape(filePath, text, findings) {
  const normalizedPath = filePath.replace(/\\/g, "/");
  const isGithubSetupPayload = /\/\.github\/setup\.js$/i.test(normalizedPath);
  const hasBunBootstrap =
    /bun\.sh\/install/i.test(text) ||
    /\bnpm\s+install\s+bun\b/i.test(text) ||
    /\bbun-v\d+\.\d+\.\d+/i.test(text);
  const hasTmpPayload =
    /\/tmp\/[A-Za-z0-9._-]+/i.test(text) ||
    /os\.tmpdir\s*\(/i.test(text) ||
    /tmpdir\s*\(/i.test(text);
  const hasCredentialTargets =
    /\b(GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|VAULT_TOKEN|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS)\b/.test(text) ||
    /(\.aws\/credentials|\.config\/gcloud|\.azure|\.docker\/config\.json|\.kube\/config|\.npmrc|\.pypirc|id_rsa|id_ed25519|\.git-credentials|wallet)/i.test(text);
  const hasDecodeOrWrite =
    /\b(decrypt|decipher|createDecipheriv|atob|fromCharCode|Buffer\.from)\b/i.test(text) &&
    /\b(writeFileSync|writeFile|chmodSync|spawn|execFile|exec)\b/i.test(text);

  if (isGithubSetupPayload) {
    findings.push(finding(
      hasBunBootstrap || hasCredentialTargets ? "critical" : "high",
      "miasma-github-setup-payload",
      filePath,
      ".github/setup.js is a reported Miasma reinfection payload path; review this file before running CI or package scripts."
    ));
  }

  if ((hasBunBootstrap && hasTmpPayload && hasCredentialTargets) || (hasDecodeOrWrite && hasTmpPayload && hasCredentialTargets)) {
    findings.push(finding(
      "critical",
      "miasma-second-stage-shape",
      filePath,
      "JavaScript resembles reported Miasma/Shai-Hulud second-stage behavior: decode/write/execute or Bun bootstrap plus /tmp payload and credential target collection."
    ));
    return;
  }

  if (hasCredentialTargets && (hasBunBootstrap || hasTmpPayload || hasDecodeOrWrite)) {
    findings.push(finding(
      "high",
      "miasma-credential-harvest-review",
      filePath,
      "JavaScript references credential targets alongside execution, decode, Bun, or temporary-payload behavior; review for Miasma/Shai-Hulud second-stage logic."
    ));
  }
}

function scanShaiHuludSshPropagationShape(filePath, text, findings) {
  const hasSshTempDir =
    /\/tmp\/\.sshu-[A-Za-z0-9_-]*/i.test(text) ||
    /remoteWorkDir\s*=\s*["']\/tmp\/\.sshu-/i.test(text);
  const hasAiPayloadNames = /\bai_setup\.sh\b/i.test(text) && /\bai_init\.js\b/i.test(text);
  const hasSshPropagationShape =
    /\binfectHost\s*\(/i.test(text) ||
    /\btargetSshHost\b/i.test(text) ||
    /\bremote(?:Loader|Payload)(?:Script|FileName)\b/i.test(text);
  const hasExecution =
    /\bBun\.spawnSync\b/i.test(text) ||
    /\b(?:spawnSync|execFile|exec|spawn)\s*\(/i.test(text) ||
    /\b(?:ssh|scp|rsync)\b/i.test(text);
  const hasCredentialOrKeySurface =
    /\b(GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|SSH_AUTH_SOCK|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET)\b/.test(text) ||
    /(\.ssh\/|id_rsa|id_ed25519|\.git-credentials|\.npmrc|\.env)/i.test(text);

  if (hasSshTempDir && hasAiPayloadNames && hasSshPropagationShape) {
    findings.push(finding(
      "critical",
      "shai-hulud-ssh-propagation-shape",
      filePath,
      "Code matches provisional Shai-Hulud SSH propagation shape: hidden /tmp/.sshu-* directory, ai_setup.sh/ai_init.js payload names, and SSH host propagation variables."
    ));
    return;
  }

  if ((hasSshTempDir || hasAiPayloadNames) && hasExecution && (hasSshPropagationShape || hasCredentialOrKeySurface)) {
    findings.push(finding(
      "high",
      "shai-hulud-ssh-artifact-review",
      filePath,
      "Code references provisional Shai-Hulud SSH artifacts alongside execution or credential/SSH surface; review before running commits, installs, builds, or pushes."
    ));
  }
}

function lockfileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  // Tarball basename is unscoped (e.g. @cacheable/memory → memory-2.2.1.tgz).
  const tarballBase = escapeRegExp(pkg.includes("/") ? pkg.split("/").pop() : pkg);
  const patterns = [
    new RegExp(`${escapedPkg}[^\\n\\r]{0,120}${escapedVersion}`),
    new RegExp(`${escapedPkg.replace("/", "\\/")}[^\\n\\r]{0,120}${escapedVersion}`),
    // package-lock v2/v3 path keys may place "version" on a following line
    new RegExp(`["']node_modules/${escapedPkg}["']\\s*:\\s*\\{[\\s\\S]{0,500}?["']version["']\\s*:\\s*["']${escapedVersion}["']`),
    new RegExp(`node_modules/${escapedPkg}[\\s\\S]{0,240}"version"\\s*:\\s*"${escapedVersion}"`),
    // resolved tarball URLs
    new RegExp(
      `(?:registry\\.npmjs\\.org/|/)(?:@[^/"']+/)?${tarballBase}/-/${tarballBase}-${escapedVersion}\\.tgz`
    ),
    new RegExp(`["']${escapedPkg}@npm:${escapedVersion}["']`)
  ];
  return patterns.some((pattern) => pattern.test(text));
}

function pythonFileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  const normalizedText = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*${escapedVersion})`, "im"),
    new RegExp(`${escapedPkg}[^\\n\\r]{0,200}${escapedVersion}`, "i")
  ];
  return patterns.some((pattern) => pattern.test(normalizedText));
}

function pythonPackageVersionsInText(text, pkg) {
  const escapedPkg = escapeRegExp(pkg);
  const versions = new Set();
  const patterns = [
    new RegExp(`\\b${escapedPkg}\\b\\s*(?:==|===|=|~=|>=|<=|>|<)\\s*["']?([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`\\b${escapedPkg}\\b["']?\\s*[:=]\\s*["']?[^0-9\\n\\r]{0,12}([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`name\\s*=\\s*["']${escapedPkg}["'][\\s\\S]{0,300}?version\\s*=\\s*["']([0-9]+\\.[0-9]+\\.[0-9]+)["']`, "gi")
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function composerFileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  return new RegExp(`${escapedPkg}[\\s\\S]{0,500}${escapedVersion}`, "i").test(text.toLowerCase());
}

function composerPackageVersionsInText(text, pkg) {
  const escapedPkg = escapeRegExp(pkg);
  const versions = new Set();
  const patterns = [
    new RegExp(`["']name["']\\s*:\\s*["']${escapedPkg}["'][\\s\\S]{0,500}?["']version["']\\s*:\\s*["']v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)["']`, "gi"),
    new RegExp(`["']${escapedPkg}["']\\s*:\\s*["'][^"']*?v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)`, "gi"),
    new RegExp(`${escapedPkg}[\\s\\S]{0,200}?v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)`, "gi")
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function composerConstraintNeedsLivewireReview(text) {
  return /["']livewire\/livewire["']\s*:\s*["'][^"']*(?:\^|~|>=|>|3\.|v?3\b)/i.test(text);
}

function isPythonDependencyFile(base) {
  return PYTHON_DEPENDENCY_FILES.has(base) || /^requirements.*\.txt$/i.test(base);
}

function isToolConfigFile(filePath, base) {
  const normalized = filePath.replace(/\\/g, "/");
  if (TOOL_CONFIG_FILES.has(base)) {
    return normalized.includes("/.claude/") || normalized.includes("/.gemini/") || normalized.includes("/.vscode/");
  }
  return CURSOR_RULE_EXTENSIONS.has(path.extname(base)) && normalized.includes("/.cursor/rules/");
}

function isApacheHttpdFile(filePath, base) {
  if (APACHE_HTTPD_FILES.has(base)) return true;
  if (/\.conf$/i.test(base) && /apache|httpd|h2|http2/i.test(filePath)) return true;
  return false;
}

function isWorkflowFile(filePath, base) {
  if (!/\.ya?ml$/i.test(base)) return false;
  return filePath.replace(/\\/g, "/").includes("/.github/workflows/");
}

function isJavaScriptSourceFile(filePath) {
  return JAVASCRIPT_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isWebSourceFile(filePath) {
  return WEB_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isNotebookSourceFile(filePath) {
  return NOTEBOOK_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isPhpSourceFile(filePath) {
  return PHP_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isShellSourceFile(filePath, base) {
  return SHELL_SOURCE_EXTENSIONS.has(path.extname(filePath)) || base === ".bashrc" || base === ".zshrc";
}

function isShadowableToolFile(base) {
  return SHADOWABLE_TOOL_NAMES.has(base.toLowerCase());
}

function normalizePythonPackageName(name) {
  return String(name).toLowerCase().replace(/_/g, "-");
}

function matchesActiveNamespace(packageName, advisory) {
  const namespaces = advisory.indicators?.activeNamespaces;
  if (!Array.isArray(namespaces)) return false;
  return namespaces.some((namespace) => typeof namespace === "string" && namespace.length > 0 && packageName.startsWith(namespace));
}

function matchesActivePackage(packageName, advisory) {
  const packages = advisory.indicators?.activePackages;
  if (!Array.isArray(packages)) return false;
  return packages.some((name) => name === packageName);
}

function packageReviewPrompt(packageName, advisory) {
  const prompts = advisory.indicators?.packageReviewPrompts;
  if (!prompts || typeof prompts !== "object" || Array.isArray(prompts)) return "";
  return typeof prompts[packageName] === "string" ? prompts[packageName] : "";
}

function versionIsListed(versions, version) {
  if (!Array.isArray(versions)) return false;
  return versions.includes("*") || versions.includes(version);
}

function packageIsListedAllVersions(versions) {
  return Array.isArray(versions) && versions.includes("*");
}

function finding(severity, type, filePath, message) {
  return {
    severity,
    type,
    path: filePath,
    message
  };
}

function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];
  for (const item of findings) {
    const key = `${item.severity}\0${item.type}\0${item.path}\0${item.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

function riskLevel(findings) {
  if (findings.some((item) => item.severity === "critical")) return "likely-exposed";
  if (findings.some((item) => item.severity === "high")) return "possible-exposure";
  if (findings.some((item) => item.severity === "medium")) return "review-needed";
  return "no-known-indicators";
}

function guidanceForRisk(risk) {
  if (risk === "likely-exposed") {
    return [
      "STOP: Do not run install, build, test, or dev-server commands in this project until reviewed.",
      "This project references known compromised package or payload indicators.",
      "Stop installs, builds, and dev servers in the affected environment.",
      "If payload execution is possible, isolate the host from the network before cleanup.",
      "Do not revoke tokens from the suspected infected host first.",
      "Rotate GitHub, npm, cloud, Vault, Kubernetes, SSH, and CI secrets from a clean machine.",
      "Treat confirmed execution or credential access as a host compromise and rebuild from a clean baseline."
    ];
  }

  if (risk === "possible-exposure" || risk === "review-needed") {
    return [
      "PAUSE: Review these findings before running package installs or builds.",
      "Review findings before running more package installs.",
      "Prefer npm ci --ignore-scripts or equivalent script-blocking controls until dependency state is verified.",
      "Pin away from known-bad package versions and regenerate lockfiles from a clean environment."
    ];
  }

  return [
    "No known TanStack incident indicators were found by this scanner.",
    "This does not prove the host is clean; it only means these specific indicators were not observed."
  ];
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  loadAdvisoryData,
  scanTarget,
  riskLevel
};
