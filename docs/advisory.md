# Advisory Summary

On May 12, 2026, JFrog Security Research reported `Shai-Hulud: Here We Go
Again`, an active worm-like npm/PyPI supply-chain compromise affecting more
than 170 npm packages and 2 PyPI packages. The npm variant uses malicious
install-time JavaScript payloads to steal credentials, write GitHub dead drops,
and republish infected packages. The PyPI variant uses import-time loader code
that downloads `/tmp/transformers.pyz` from `83.142.209.194`.
JFrog later updated its analysis on May 12, 2026 to report that the remote PyPI
second-stage payload had changed from an attribution response into a Linux
credential stealer with persistence, exfiltration, and possible destructive
behavior.
Additional May 12-13 public reporting describes country/language-gated
destructive behavior in the Python payload, including Russian-language avoidance
and a reported Israel/Iran location check that may randomly trigger audio
playback and file deletion. Treat those details as destructive-payload triage
context; this scanner only promotes exact package, payload, persistence, hash,
network, and campaign indicators into automated findings.

On May 11, 2026, TanStack reported a related supply-chain compromise affecting 84
malicious versions across 42 `@tanstack/*` npm packages, published between
19:20 and 19:26 UTC. TanStack attributes the attack chain to a
`pull_request_target` workflow issue, GitHub Actions cache poisoning across a
fork-to-base trust boundary, and runtime extraction of an OIDC token from the
GitHub Actions runner process.

Socket's live campaign page reports 416 affected package artifacts across npm,
PyPI, and Composer as of May 12, 2026, including the TanStack wave, Mistral SDK
packages, UiPath packages, Squawk packages, OpenSearch, Guardrails AI, older SAP
CAP packages, Intercom, and PyPI `lightning`. This project does not claim
coverage for additional package artifacts unless exact package/version
indicators have been added to the relevant file under `data/packages/`.

JetBrains Marketplace AI-key stealer indicators are included for adjacent IDE
plugin supply-chain review. In addition to the Aikido/BleepingComputer plugin
IDs and `39.107.60[.]51/api/software/key` endpoint, DFIR Radar's June 25 note
adds implementation markers: `F48D2AA7CF341F782C1D`, `BaseUtil.request()`,
`save()`/Apply configuration persistence, `sk-` key validation, and plaintext
HTTP POST behavior from JetBrains processes.

Socket's May 19, 2026 @antv report describes an active npm publish wave tied to
Mini Shai-Hulud and the npm maintainer account `atool`. Socket names the
`@antv` ecosystem, `echarts-for-react`, `timeago.js`, `size-sensor`, and
`canvas-nest.js` as packages to review while the full affected-version list is
still developing. This scanner treats these as lower-confidence package or
namespace review prompts until exact malicious versions are added under
`data/packages/npm.json`.
Socket's technical analysis of the same wave describes a root-level `index.js`
payload launched by `preinstall: bun run index.js`, a direct C2 endpoint at
`t.m-kosche.com`, GitHub fallback exfiltration using `results/results-*.json`
paths and reversed Shai-Hulud repository markers, and npm propagation logic that
validates stolen npm tokens, enumerates maintainable packages, injects payloads,
bumps versions, and republishes under the compromised maintainer identity.

On May 21, 2026, Fuma Nama reported that the `fuma-content` repository was
affected by Shai-Hulud during or around a transition to pnpm v11. The reported
working theory is that affected TanStack Start package `postinstall` scripts ran
while the environment was still on pnpm v9; pnpm v11 should disable dependency
lifecycle scripts unless explicitly allowed. Fuma reported manually verifying no
affected published versions of `fuma-content`, `fumadb`, or `fumadocs` as of
that update, with the repository history retained for cause analysis, the
machine factory reset, and secrets revoked. This scanner therefore treats Fuma
package names as review prompts only, not as known compromised versions, unless
exact malicious package/version indicators are later published.

On May 21, 2026, SafeDep reported a compromise of the legitimate `art-template`
npm package tied to Coruna / iOS browser exploit-kit activity. Until exact
affected versions are added to `data/packages/npm.json`, this scanner treats
`art-template` as a review prompt rather than a known-bad version finding.
Operators should verify installed versions, install/update timing, and any
lifecycle-script execution against SafeDep's latest advisory before running
builds.

On May 21, 2026, OX/SafeDep-linked reporting described Megalodon, a mass GitHub
CI/CD workflow backdooring campaign using throwaway accounts, fake CI bot
identities, optimization-themed commit messages, base64/shell workflow payloads,
and CI secret exfiltration. Public summaries report the C2 indicator
`216.126.225.129:8443`. Operator-provided screenshots of a port 8080 listener
showed an ingest service with `/root/cicd/loot`, `POST /any ?h=&l=&id=&t=`,
`GET /health`, and `LISTENER_LOG=1` markers. This scanner treats those as
GitHub Actions workflow and network indicators.

On May 22, 2026, Aikido reported an ongoing Composer/Packagist supply-chain
attack affecting multiple `laravel-lang/*` packages, with payload execution at
autoload time. The public operator guidance was to pause updates, pin to a
clean commit rather than trusting package versions alone, and rotate secrets if
a compromised version may have executed. This scanner therefore treats
`laravel-lang/lang`, `laravel-lang/http-statuses`, and
`laravel-lang/attributes` as Composer review prompts until exact affected
versions or clean commit boundaries are encoded.

On May 22, 2026, International Cyber Digest reported a separate supply-chain
wave affecting PHP and Node.js projects, with 700+ GitHub repositories flagged
and eight Packagist packages reportedly infected. The described payload path
hides a malicious script in `package.json` rather than `composer.json`, downloads
a Linux binary from GitHub with TLS checks skipped, writes it to `/tmp/.sshd`,
marks it executable, and runs it in the background. The same reporting names a
GitHub Actions step `Dependency Cache Sync`, the GitHub account
`parikhpreyash4`, repository `systemd-network-helper-aa5c751f`, and `devdojo/wave`
and `devdojo/genesis` as high-risk Laravel template surfaces. Until exact
affected versions are encoded, this scanner flags those package names as
Composer review prompts and treats `/tmp/.sshd` install-script references as
likely-exposed payload references.

Also on May 22, 2026, operator-provided screenshots showed a misleading GitHub
SSH "shell access" demonstration. The underlying technique was not GitHub.com
providing a real shell; it used a repo-local script named `ssh`, prepended that
directory to `PATH`, printed a fake GitHub success banner, and launched a local
shell with a spoofed `git@github.com` prompt. This scanner treats that as
PATH/tool-shadowing tradecraft and flags executable-like local files named after
trusted tools when paired with shell shebangs, along with the specific fake
banner and PATH-prepend strings.

On May 22-23, 2026, public reporting and operator-provided VirusTotal context
described a ClickFix social-engineering campaign using compromised legitimate
websites as lure pages. The reported malicious page source loaded a remote
script from `staticcloudflare[.]pro` and contained the reversed loader string
`sj.ssc/ipa/orp.eralfduolccitats`. This scanner treats the domain, reported
`/api/css.js` loader URL, reversed string, and `ClickFix` text as source and
incident-note indicators. These strings identify copied page source or local
notes about the campaign; they do not prove compromise of a host by themselves
without execution or exposure context.

The Nightmare-Eclipse / Chaotic Eclipse Windows disclosures are out of scope for
this scanner. They are physical-access host disk-encryption and local-privilege
bugs, not Mini Shai-Hulud package indicators, and are tracked here only as
related public situational awareness because readers see the same reporting
stream. The campaign began early April 2026 and continues; the `GreatXML`
BitLocker bypass is the newest drop (June 2026), following the May 12, 2026
`YellowKey` and `GreenPlasma` round. `GreatXML` plants an `unattend.xml` plus a
`Recovery\WindowsRE` tree on the recovery partition and abuses a latent
Microsoft Defender Offline Scan state: a machine that has ever run an offline
scan stays exploitable with no login required. Host-side mitigation (out of this
tool's lane) is BitLocker TPM+PIN and a UEFI/BIOS password.

Do not add the actor's repositories, mirrors, or screenshots to scanner
detection data unless a confirmed Mini Shai-Hulud package, payload, or campaign
artifact overlaps. The actor opens and closes repos mid-campaign — treat any
clone of a named "hot 0-day PoC" as Miasma-style bait and run the pre-open check
first. Manual triage strings from public reporting include `Nightmare-Eclipse`,
`NightmareEclipse`, `Chaotic Eclipse`, `Dead Eclipse`, `MSNightmare`,
`projectnightcrawler`, `GreatXML`, `YellowKey`, `GreenPlasma`, `MiniPlasma`,
`UnDefend`, `BlueHammer` (CVE-2026-33825), `RedSun`, `CSRSS_TEST_SECTION`, and
WinRE / `wpeinit` / `unattend.xml` context.

Windows 11 `KB5094126` is also tracked as out-of-scope patch-regression
awareness. Public reporting describes freezes shortly after boot, BitLocker
Recovery loops even on systems where encryption had been disabled, OneDrive
Explorer integration failures on some domain-joined PCs, LAN disruption, and HP
device BSOD/update failures linked to small EFI System Partitions during Secure
Boot certificate updates. This scanner does not inspect Windows update state.
Treat these symptoms as patch triage, not supply-chain compromise, unless other
Mini Shai-Hulud evidence is present.

AlmaLinux's May 13, 2026 Fragnesia / `CVE-2026-46300` disclosure is also
adjacent Linux host-risk context, not a Here We Go Again or Mini Shai-Hulud
scanner indicator. It is a kernel local-root flaw affecting supported
AlmaLinux releases through the `esp4`, `esp6`, and, on some AlmaLinux 9/10
systems, `rxrpc` modules. Track it for Linux developer workstations, CI
runners, container build farms, and multi-tenant hosts where a package payload
or untrusted local user could chain local code execution into root.

Asim Viladi Oglu Manizada's May 27, 2026 CIFSwitch / `CVE-2026-46243`
disclosure is the same kind of adjacent Linux host-risk context, not a package
or malware indicator. It is a Linux local-root chain involving the kernel CIFS
client, `cifs-utils`, `cifs.spnego` request-key handling, and namespace/NSS
confusion. Track it for Linux developer workstations, CI runners, container
build farms, and multi-tenant hosts, especially where `cifs-utils` is present,
unprivileged user namespaces are enabled, and CIFS/SMB support is not required.

CISA's May 29, 2026 KEV addition for Palo Alto Networks PAN-OS GlobalProtect
`CVE-2026-0257` is retained as network-edge defensive triage context. It is not
a package supply-chain indicator, but copied incident notes mentioning the CVE,
PAN-OS GlobalProtect auth bypass, or unauthorized VPN connection language should
prompt review of VPN exposure, patch state, and authentication logs.

Calif's June 2026 HTTP/2 Bomb research, later covered by The Register, is
retained as Apache HTTP Server defensive triage context. The Apache issue is
tracked as `CVE-2026-49975` and fixed in standalone `mod_http2 v2.0.41`, where
merged cookie headers count against `LimitRequestFields`. This scanner flags
copied incident notes plus Apache `httpd.conf` / `apache2.conf` / related
`.conf` evidence that shows HTTP/2 enabled, `mod_http2` referenced, or a
reported `mod_http2` version below `2.0.41`.

Ammar Askar's June 2, 2026 GitHub token-stealing writeup for `github.dev` /
VS Code webview behavior is retained as developer-toolchain defensive triage
context. This scanner flags high-signal copied PoC markers in VS Code extension
recommendation/config files, local extension manifests, JavaScript files, and
notebooks; findings should prompt review of `github.dev` browser state and
GitHub token exposure.

Lupin & Holmes' May 14, 2026 node-ipc reporting describes malicious `node-ipc`
versions `9.1.6`, `9.2.3`, and `12.0.1` published by the dormant `atiertant`
maintainer identity, likely through email takeover tied to the re-registered
`atlantis-software.net` domain. The payload lives in `node-ipc.cjs`, harvests
local secrets, and uses DNS-tunneling style exfiltration with C2 at
`sh.azurestaticprovider.net`. This scanner treats the exact package versions,
maintainer/domain context, and high-signal payload strings as npm
supply-chain indicators.

A June 3, 2026 operator-provided package table added exact npm
package/version indicators for a Moika follow-up cluster under `@ccrm/*` and
`@emcd-vue/*`. The scanner treats the listed package/version pairs as critical
package indicators and warns on those namespaces while the campaign context is
active.

JFrog's June 3, 2026 IronWorm report describes a related self-replicating
developer supply-chain attack against asteroiddao/WeaveDB npm packages. The
observed npm payload path was a Linux ELF binary at `tools/setup`, executed
through `preinstall: ./tools/setup`; JFrog also described forged/backdated
commits attributed to `claude <claude@users.noreply.github.com>` and a possible
GitHub Actions secret-artifact path using `toJSON(secrets)` and
`format-results.txt`. Follow-up coverage also emphasized the Rust infostealer
payload, eBPF rootkit behavior, Tor communication, and Exodus wallet targeting.
This scanner treats JFrog's exact npm package/version IoCs as critical
indicators and keeps the install-hook/workflow/payload-note strings as source
and incident-note indicators.

June 5, 2026 operator-provided fallout notes, described as active OX Security
work with Wiz context, reported 49 Microsoft, Azure, and Azure-Samples GitHub
repositories taken offline for Terms of Service violations after suspected
regained attacker access following the earlier DurableTask compromise. This
scanner keeps the reported repository slugs as copied-note and repo-context
indicators only. They should prompt repository provenance, workflow,
maintainer-token, and release-artifact review, not automatic classification of
all related packages as malicious.
During local verification, GitHub's API returned `Repository access blocked`
with reason `tos` for the provided `Azure/durabletask` compare URL, and public
code-search triage centered on `node .github/setup.js` in `settings.json`, which
matches the Claude settings persistence pattern seen in earlier Mini
Shai-Hulud waves.
SafeDep's June 5, 2026 writeup describes the same Miasma family moving through
source repositories instead of only registry packages. The reported six-file
footprint plants `.github/setup.js` and connects it to Claude Code
`.claude/settings.json`, Gemini CLI `.gemini/settings.json`, Cursor
`.cursor/rules/setup.mdc`, VS Code `.vscode/tasks.json`, and the `package.json`
`test` script. This scanner treats an agent/editor config that auto-runs
`node .github/setup.js` as a critical source-repo persistence trigger.
June 5 operator-provided decoded payload snippets also showed token collector
branches for GitHub, npm, and RubyGems credentials, including the obfuscated
field names `matches?.ghtoken`, `matches?.fgghtoken`, `matches?.npmtoken`, and
`matches?.rubygemstoken`. This scanner keeps those strings as copied-code or
decoded-artifact indicators.
Moshe Siman Tov Bustan's June 5 Azure Miasma sample notes described hardcoded
StepSecurity / Harden-Runner strings and domains in the payload, apparently to
avoid detection when running in StepSecurity's Docker environment. The same
notes described reused public keys and the same `firedalazer` GitHub commit
search used to retrieve the next payload.
Additional June 5 screenshots shared through Moshe from heyosj.com showed a
decoded GitHub exfiltration path named `createPublicGithubExfilRepo`. The code
creates public repositories through `/user/repos`, sets the description
`Hades - The End for the Damned`, and uses Hades-themed generated repo names.
Related screenshots showed small JSON artifacts with `envelope` and `key`
fields; this scanner records only the field names, not the full key material.

Socket's June 8, 2026 Hades follow-up reported a PyPI branch using executable
`*-setup.pth` startup hooks, Bun bootstrapping, `_index.js` payload handoff,
`sys.path` payload searching, and trojanized `.abi3.so` native-extension import
triggers. This scanner treats the reported Hades PyPI package versions as
critical dependency indicators and records only structural markers such as
`langchain_core-setup.pth`, `_index.js`, Bun bootstrap artifacts, and reported
native-extension filenames. It does not store raw LLM anti-analysis prompt text.

JFrog's June 4, 2026 Red Hat / Miasma update expanded the affected
`@redhat-cloud-services/*` versions and documented an alternate install-time
execution path through `binding.gyp`. In that path, npm can fall back to
`node-gyp rebuild`; `node-gyp` command expansion syntax such as `<!(node
index.js > /dev/null 2>&1 && echo stub.c)` can execute an installer during
package configuration even when `package.json` has no explicit lifecycle hook.
This scanner treats JFrog's exact affected package/version entries as critical
package indicators and flags local `binding.gyp` command expansion for manual
review, with higher severity when the expansion launches `node`, `bun`,
network/shell tools, temp payload paths, or silent redirects.

OX's June 4, 2026 Miasma return report confirms the same `binding.gyp`
execution pivot, reports 57 affected npm packages with roughly 647K monthly
downloads, and adds the updated GitHub repository marker
`Miasma – The Spreading Blight`. OX later edited the same report with another
weaponized `binding.gyp` wave affecting `discord-search`, `create-cf-token`, 
`@forjacms/*`, `dbmux`, `creditcard.js`, `github-archiver`, and
`@contaazul/n8n-nodes-contaazul`. This scanner treats OX's additional exact
package/version entries as critical npm indicators and keeps the dash-variant
marker alongside the earlier colon variants.

OX's June 25, 2026 Shai-Hulud / Miasma / Hades npm variant report describes a
compromised maintainer account affecting `leo-*`, `serverless-*`, `solo-nav`,
and `rstreams-*` packages. JFrog's companion analysis confirms the Leo/RStreams
rows and adds affected `@immobiliarelabs/backstage-*` package versions plus
`SEED_PAT` / `Seeder` operator-seeding markers. Aikido also called out the
ImmobiliareLabs Backstage LDAP auth and GitLab plugins as credential-stealing
worm targets, so any hit on these packages should move directly to clean-device
rotation for GitHub, npm, LDAP, Backstage, CI, and cloud credentials after
persistence/exfiltration paths are contained. This scanner treats the
reported exact package/version pairs as critical npm indicators and flags
copied incident notes or source artifacts containing the reported GitHub exfil
strings, raw payload paths, account/repository markers, and public-key
fragments.

SafeDep's LeoPlatform follow-up confirms the 20 LeoPlatform npm rows and adds
repo-poisoning context around orphan `snapshot-*` branches, fake `Dependabot
Updates` GitHub Actions workflows, `_index.js`, `OIDC_PACKAGES`, `WORKFLOW_ID`,
`REPO_ID_SUFFIX`, and direct `NPM_TOKEN` publication surfaces.

SupplyChainAttack and GitHub Advisory Database full-compromise npm malware
entries are also included for package-name detection. The scanner treats
`ts-grok` and `signup-embedder` as affected for all versions (`>= 0`) with no
patched version, matching GHSA-qp73-r9hh-6vq9 and GHSA-8j4q-hx83-pfq9, and asks
operators to move to credential rotation and host compromise response if either
package was installed or run.

June 5 passive decode notes confirmed the live Shai-Hulud/Miasma second-stage
shape: `setup.js` decrypts or decodes a large payload, writes it under `/tmp`,
bootstraps Bun when missing, and executes the payload. The second stage targets
GitHub and npm tokens, AWS/GCP/Azure credentials, Docker auth, Kubernetes
configs, SSH keys, Git credentials, Vault tokens, private keys, chat app data,
wallet paths, and related developer secrets. This scanner therefore treats
`.github/setup.js` as a high-risk reinfection path and flags JavaScript that
combines decode/write/execute or Bun bootstrap behavior with `/tmp` payload
writes and credential-target collection.

OX's June 4, 2026 Malware-Slop 2 report describes `cms-store-ren`, a malicious
npm JavaScript infostealer reported as affecting all versions. OX describes
basic host telemetry and data exfiltration over the Telegram Bot API, hidden
PowerShell second-stage execution using `-WindowStyle Hidden` and
`-ExecutionPolicy Bypass`, and actor/operator markers including
`ebalvsehvrot10raz_bot`, `amaturesequoyah`, and `BREVNA LETYAT`. This scanner
treats any `cms-store-ren` package reference as a critical npm indicator and
flags copied local notes/source containing the high-signal Telegram and
PowerShell markers.

GitHub Advisory `GHSA-g6v5-9xpp-6hpx` and supplychainattack.org describe
`google-cloud-secret-manager-config-poc` as npm malware affecting all versions.
This scanner treats any package or lockfile reference to that name as a critical
npm indicator requiring full-compromise handling if the package was installed or
run.

Panther's April 2026 OtterCookie report describes a DPRK-attributed npm campaign
using benign wrapper packages and malicious payload dependencies. This scanner
tracks the exact reported package versions for `bjs-biginteger`,
`bjs-lint-builder(s)`, `hjs-lint-builders`, `sjs-builder(s)`, and
`npm-doc-builder`, plus the reported Vercel-hosted C2 domains. Treat hits as
install-time malware exposure because the reported payload exfiltrates files and
can modify SSH authorized keys on Linux hosts.

Flatt Security's June 1, 2026 Claude Code GitHub Action research described a
GitHub App actor bypass in agent mode and a common risky
`allowed_non_write_users` configuration in issue-triage workflows. The attack
path combines untrusted issue/PR content, Claude Code prompt injection,
environment/OIDC token exposure through `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and
`ACTIONS_ID_TOKEN_REQUEST_URL`, and GitHub write/exfiltration surfaces such as
`mcp__github__update_issue`. Anthropic fixed the GitHub App bypass as of Claude
Code GitHub Actions v1.0.94. This scanner treats Claude Code Action workflows
as review material when they combine untrusted issue/PR triggers with
`id-token: write`, broad write permissions, `allowed_non_write_users`, or
GitHub MCP issue read/update tools.

The key local indicators used by this project are:

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- `/tmp/transformers.pyz`
- `pgmonitor.py` and `pgsql-monitor.service`
- `gh-token-monitor.service`, `gh-token-monitor.sh`, and
  `com.user.gh-token-monitor.plist`
- known malicious payload SHA-256 values:
  `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
  and `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- updated PyPI `transformers.pyz` SHA-256:
  `5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b`
- known affected `@tanstack/*` package/version pairs in
  `data/packages/npm.json`
- known affected `@mistralai/mistralai`, `@mistralai/mistralai-azure`, and
  `@mistralai/mistralai-gcp` package/version pairs from Aikido's May 12 update
  in `data/packages/npm.json`
- known affected UiPath, TallyUI, DraftAuth, DraftLab, BeProduct, ML Toolkit,
  TaskFlow, Supersurkhet, Tolka, OpenSearch, Dirigible AI, Mesadev, and selected
  unscoped npm package/version pairs from Aikido's May 12 update in
  `data/packages/npm.json`
- known affected Squawk, SAP CAP, Intercom, and additional Socket-tracked npm
  package/version pairs from Socket's live campaign table
- lower-severity namespace and package-name warnings for namespaces and packages
  reported in the active campaign when exact package/version coverage may still
  be incomplete
- developing @antv / atool indicators from Socket's May 19 report: `@antv/*`,
  `echarts-for-react`, `timeago.js`, `size-sensor`, and `canvas-nest.js`
- @antv payload indicators from Socket's technical analysis: `@antv/setup`,
  `github:antvis/G2#1916faa365f2788b6e193514872d51a242876569`,
  `t.m-kosche.com`, `niagA oG eW ereH :duluH-iahS`,
  `niaga og ew ereh :duluh-iahs`, `results/results-`, and `fc2edea72`
- Fuma repository-context review prompts: `fuma-content`, `fumadb`,
  `fumadocs`, `fumadocs-core`, `fumadocs-mdx`, and `fumadocs-ui`
- SafeDep `art-template` / Coruna repository-context review prompt
- Megalodon CI/CD workflow indicators: `216.126.225.129`,
  `216.126.225.129:8443`, `/root/cicd/loot`, `ingest listener OK`,
  `POST /any ?h=&l=&id=&t=`, `GET /health`, `LISTENER_LOG=1`, fake CI bot
  strings such as `build-bot`, `auto-ci`, `ci-bot`, and `pipeline-bot`, and
  optimization-themed commit messages such as `ci: add build optimization step`
  and `chore: optimize pipeline runtime`
- Composer review prompts for the active Aikido/Packagist `laravel-lang/*`
  report: `laravel-lang/lang`, `laravel-lang/http-statuses`, and
  `laravel-lang/attributes`
- Packagist/GitHub supply-chain indicators from the International Cyber Digest
  report: `devdojo/wave`, `devdojo/genesis`, `parikhpreyash4`,
  `systemd-network-helper-aa5c751f`, `/tmp/.sshd`, `curl -skL`,
  `chmod +x /tmp/.sshd`, and `Dependency Cache Sync`
- PATH/tool-shadowing indicators from the fake GitHub SSH demo:
  `GitHub does provide shell access`, `export PATH=$(realpath`,
  `git@github.com ~`, and repo-local executable-like files named after trusted
  tools such as `ssh`, `git`, `npm`, `node`, `gh`, `claude`, or `codex`
- ClickFix/staticcloudflare indicators: `staticcloudflare.pro`,
  `staticcloudflare[.]pro`, `https://staticcloudflare.pro/api/css.js`,
  `sj.ssc/ipa/orp.eralfduolccitats`, and `ClickFix`
- Palo Alto Networks PAN-OS GlobalProtect defensive triage markers:
  `CVE-2026-0257`, `PAN-OS GlobalProtect`,
  `GlobalProtect Authentication Bypass`, and `unauthorized VPN connection`
- Apache HTTP/2 Bomb defensive triage markers: `CVE-2026-49975`,
  `HTTP/2 Bomb`, `HPACK Bomb`, `mod_http2 v2.0.41`, `LimitRequestFields`, and
  vulnerable Apache `mod_http2` versions below `2.0.41`
- VS Code / `github.dev` GitHub token-stealing PoC markers:
  `github-dev-token-steal-poc`, `vscode-github-token-grab-extension`,
  `AmmarTest.hello-ammar-github`, `workbench.extensions.installExtension`, and
  `skipPublisherTrust`
- node-ipc compromise indicators: malicious `node-ipc` versions `9.1.6`,
  `9.2.3`, and `12.0.1`, `node-ipc.cjs`, `__ntw`, `__ntRun`, `uname.txt`,
  `envs.txt`, `nt-<hash>`, `dns.Resolver`, `atiertant`,
  `atlantis-software.net`, and `sh.azurestaticprovider.net`
- Moika follow-up npm indicators for exact `@ccrm/*` and `@emcd-vue/*`
  package/version pairs
- IronWorm indicators from JFrog's June 3 report: exact asteroiddao/WeaveDB npm
  package/version pairs, `IronWorm`, `./tools/setup`,
  `.github/scripts/precheck`, automation-style forged commit messages,
  `toJSON(secrets)`, `format-results.txt`, Rust infostealer notes, eBPF rootkit
  notes, Tor communication notes, and Exodus wallet targeting notes
- Azure/Microsoft Mini Shai-Hulud repo-fallout copied-note indicators:
  `49 Repositories taken offline`, `Azure/azure-functions-core-tools`,
  `Azure/durabletask`, `Azure-Samples/llm-fine-tuning`,
  `microsoft/durabletask-js`, and related Azure Functions / DurableTask
  repository slugs, plus `Repository access blocked`, `github.com/tos`, and
  `node .github/setup.js` settings persistence markers
- SafeDep Miasma source-repo persistence indicators across `.claude`,
  `.gemini`, `.cursor/rules`, `.vscode`, and package test scripts, including
  `SessionStart`, `alwaysApply: true`, `runOn: folderOpen`, and
  `chore: update dependencies [skip ci]`
- Decoded token-collector indicators: `matches?.ghtoken`,
  `matches?.fgghtoken`, `matches?.npmtoken`, `matches?.rubygemstoken`,
  `handleGhTokens`, `handleFgGhTokens`, `handleNpmTokens`, and
  `handleRubygemsTokens`
- Azure Miasma sample indicators: `harden-runner`, `step-security`,
  `stepsecurity`, `agent.stepsecurity.io`, `api.stepsecurity.io`,
  `app.stepsecurity.io`, `AKIAFAKE`, reused public-key context, and the
  existing `firedalazer` payload-chain marker
- Hades GitHub exfil-repo indicators: `createPublicGithubExfilRepo`,
  `generateHadesRepoName`, `/user/repos`, `Hades - The End for the Damned`,
  Hades-themed repo-name prefixes, and `envelope` / `key` artifact fields
- Hades PyPI indicators: affected package versions, `*-setup.pth`,
  `langchain_core-setup.pth`, `_index.js`, Bun bootstrap markers, `sys.path`
  payload searching, and suspicious `.abi3.so` native-extension launcher
  layouts
- Miasma/Shai-Hulud second-stage shape indicators: `.github/setup.js`,
  `bun.sh/install`, `npm install bun`, `bun-v*`, `/tmp` JavaScript payload
  writes, decode/write/execute behavior, and credential-target strings such as
  `GITHUB_TOKEN`, `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, `VAULT_TOKEN`,
  `.docker/config.json`, `.kube/config`, `.git-credentials`, and SSH key paths
- known affected PyPI `mistralai` and `guardrails-ai` package/version pairs from
  OX Security's May 12 update in `data/packages/pypi.json`
- known affected PyPI `lightning` and `durabletask`, plus Composer
  `intercom/intercom-php`
  package/version pairs from Socket's live campaign table
- Langflow `CVE-2026-55450` dependency pins before `1.9.1`, where the
  deprecated upload endpoint allowed unauthenticated disk-exhaustion DoS and
  absolute path disclosure
- Composer package/plugin capability anomalies such as unexpected
  `composer-plugin`, `composer-plugin-api`, or plugin entry declarations. These
  are high-severity review prompts because Composer plugins can execute during
  install/update; confirm they are expected and match upstream source before
  continuing.
- Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json`
  references to known payload, network, token-description, and campaign strings
- Binary Defense BLUERABBIT Windows host indicators: `BLUERABBIT`,
  `HKCU\Software\OneDrive\Environment`, the `OneDrive Update` scheduled task,
  `New-ScheduledTaskAction`, `AllowStartIfOnBatteries`,
  `NoAutoRebootWithLoggedOnUsers`, `MaintenanceDisabled`,
  `AlwaysAutoRebootAtScheduledTime`, `.candy`, `High-Alert`,
  `RabbitMQ (AMQP)`, `S3-compatible data exfiltration`,
  `GUID-named directories`, and the reported SHA-256 file hashes
  `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` and
  `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc`

Additional TanStack-postmortem IOCs retained for investigation context include
the cache key
`Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11`,
the second-stage URLs `litter.catbox.moe/h8nc9u.js` and
`litter.catbox.moe/7rrc6l.mjs`, the Session/Oxen seed domains
`seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`, and the
forged commit identity `claude <claude@users.noreply.github.com>`. The scanner
also searches manifests and lockfiles for selected network, workflow,
token-description, and campaign marker strings stored in the advisory data.

Additional JFrog IOCs retained for investigation context include
`filev2.getsession.org`, `seed1.getsession.org`, `seed2.getsession.org`,
`seed3.getsession.org`, `git-tanstack.com`, `api.masscan.cloud`,
`83.142.209.194`, the repository description
`Shai-Hulud: Here We Go Again`, the author marker
`claude@users.noreply.github.com`, the branch
`dependabot/github_actions/format/setup-formatter`, and the workflow path
`.github/workflows/codeql_analysis.yml`.

Additional PyPI second-stage IOCs from JFrog's updated analysis include
`83.142.209.194/v1/models`, `83.142.209.194/v1/weights`,
`83.142.209.194/audio.mp3`, `api.github.com/search/commits?q=FIRESCALE`,
`PUSH UR T3MPRR`, `FIRESCALE`, `MISTRAL_INIT`, `pgsql-monitor.service`, and
`pgmonitor.py`.

May 12 public analysis from Ayush Anand / Securityinbits describes an additional
fallback C2 path in the unobfuscated Linux `transformers.pyz` payload. If the
hardcoded `83.142.209.194` C2 fails, the payload searches GitHub commits for
`FIRESCALE`, looks for a commit message matching
`FIRESCALE\s+([A-Za-z0-9+/=]+)\.([A-Za-z0-9+/=]+)`, decodes the URL material,
verifies the attacker signature, and uses the decoded URL as fallback C2. At
the time of that report, the latest checked GitHub commit did not contain a
fresh fallback C2 value.

Manual destructive-payload review strings reported in public analysis include
timezone markers such as `Jerusalem`, `Tel_Aviv`, and `Tehran`, random
one-in-six execution gates, audio playback from `audio.mp3`, and destructive
Linux file-removal logic. Do not treat any one of these generic strings alone as
proof of compromise; use them only when reviewing a confirmed payload or exposed
host.

If one of these indicators is found, treat the environment as potentially
exposed until reviewed. If payload execution or credential access is confirmed,
remove dead-man switch persistence before token revocation, then rotate secrets
from a clean device and rebuild the affected host.
