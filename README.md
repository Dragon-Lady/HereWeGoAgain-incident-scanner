# Here We Go Again Incident Scanner

Read-only exposure scanner and recovery guidance for the May 2026
`Shai-Hulud: Here We Go Again` npm/PyPI supply-chain incident and related
Mini Shai-Hulud npm/PyPI/Composer indicators.

This tool helps identify known indicators. It does not remove malware, revoke
credentials, execute package scripts, or prove that a host is clean.

> Built and maintained by Dragon Lady - [github.com/Dragon-Lady](https://github.com/Dragon-Lady) - X: [@answerislove2](https://x.com/answerislove2)

## Run From Source

```sh
git clone https://github.com/Dragon-Lady/HereWeGoAgain-incident-scanner
cd HereWeGoAgain-incident-scanner
npm test
```

Run against a local project:

```sh
node bin/herewegoagain-incident-scanner.js /path/to/project
node bin/herewegoagain-incident-scanner.js /path/to/project --json
node bin/herewegoagain-incident-scanner.js /path/to/project --report report.json
node bin/herewegoagain-incident-scanner.js /path/to/project --remediation-plan
```

## Safety

The scanner is read-only and dependency-free. It walks local files, parses
package manifests and lockfiles, and hashes known payload filenames. It does
not run `npm install`, execute lifecycle scripts, import project code, contact
package registries, or transmit scan results.

## Privacy

This scanner does not provide a hosted service, send telemetry to the
maintainers, or upload scan results. It does not contact a server while
scanning. Results are printed to the terminal or written only to the local path
an operator explicitly provides with `--report`.

Any output files are created in the operator's local environment unless the
operator separately chooses to share them.

Do not paste secrets, tokens, private keys, `.env` files, or full private logs
into issues or public reports. If a finding suggests credential exposure,
preserve evidence locally and rotate credentials from a clean environment.

## Scope

This scanner detects exact npm, PyPI, and Composer package/version indicators in
`data/packages/` plus shared payload, tool-persistence, and campaign
indicators.
JFrog reports more than 170 npm packages and 2 PyPI packages affected by
`Shai-Hulud: Here We Go Again` as of May 12, 2026. TanStack's official
postmortem confirms 84 malicious versions across 42 `@tanstack/*` packages,
published on May 11, 2026 between 19:20 and 19:26 UTC.
Socket's live campaign page reports 416 affected package artifacts across npm,
PyPI, and Composer as of May 12, 2026. This scanner includes the exact
package/version indicators currently represented in `data/packages/`.
Broader namespaces remain lower-severity review prompts unless an exact
package/version indicator is present.
Socket's May 19, 2026 @antv report describes an active npm publish wave tied to
Mini Shai-Hulud and the npm maintainer account `atool`. This scanner warns on
`@antv/*` packages and selected related packages by name while the exact
affected-version list is still developing.
Socket's technical update for the same wave describes an install-time
`index.js` payload with direct C2, GitHub fallback exfiltration, and worm-like
npm propagation using stolen npm tokens. The scanner now checks JavaScript files
for the exact high-signal C2 and GitHub exfil markers from that analysis.
Fuma Nama's May 21 update reported the `fuma-content` repository was affected
while moving toward pnpm v11, likely because affected TanStack Start
`postinstall` scripts ran while pnpm v9 was still in use. Fuma reported no
verified affected published versions of `fuma-content`, `fumadb`, or
`fumadocs` at that time. This scanner treats Fuma package names as
lower-severity review prompts only.
SafeDep's May 21 report on the legitimate `art-template` package describes a
separate npm supply-chain compromise tied to Coruna / iOS browser exploit-kit
activity. The scanner warns on `art-template` as a review prompt until exact
affected versions are encoded.
SafeDep/OX-linked May 21 reporting on Megalodon describes mass GitHub CI/CD
workflow backdooring with fake CI bot identities, boring optimization-themed
commit messages, base64/shell payloads, and secret exfiltration to attacker
infrastructure. Operator-provided screenshots of a port 8080 listener showed an
ingest endpoint storing raw POST bodies under `/root/cicd/loot`. The scanner now
checks GitHub Actions workflows for those workflow/C2 markers and generic
base64-plus-shell/network execution patterns.
Aikido's May 22 reporting and Socket's May 23 technical writeup described an
active Composer/Packagist compromise affecting Laravel-Lang packages across
700+ versions, including RCE backdoor behavior through Composer
`autoload.files -> src/helpers.php`, payload retrieval from
`flipboxstudio[.]info/payload`, cloud metadata access, and local secret
collection. Because exact affected versions are not encoded here yet, this
scanner treats `laravel-lang/lang`, `laravel-lang/http-statuses`,
`laravel-lang/attributes`, and `laravel-lang/actions` as Composer review
prompts, while flagging the reported autoload/payload shape as higher
confidence.
International Cyber Digest's May 22 reporting described another Packagist /
GitHub supply-chain wave affecting PHP and Node.js projects. Reported high-signal
indicators include the GitHub account `parikhpreyash4`, repository
`systemd-network-helper-aa5c751f`, the Linux drop path `/tmp/.sshd`, downloader
fragments `curl -skL` and `chmod +x /tmp/.sshd`, and a GitHub Actions step named
`Dependency Cache Sync`. This scanner treats `devdojo/wave` and
`devdojo/genesis` as Composer review prompts and flags the payload strings in
`package.json`, JavaScript files, and GitHub Actions workflows.
Operator-provided May 22 screenshots also showed a social-engineering demo where
a repo-local fake `ssh` script was placed ahead of the real SSH client in
`PATH`, printed a fake GitHub shell-access banner, and launched a local shell
with a spoofed prompt. This scanner now flags repo-local executable-like files
named after trusted tools, plus the specific fake GitHub banner and PATH-prepend
strings from that demonstration.
May 22-23 reporting and operator-provided VirusTotal context described a
ClickFix campaign where compromised legitimate websites loaded a remote script
from `staticcloudflare[.]pro`, including an obfuscated reversed loader string
`sj.ssc/ipa/orp.eralfduolccitats`. This scanner flags the domain, reported
`/api/css.js` loader URL, the reversed string, and `ClickFix` marker text when
they appear in local source, copied pages, or incident notes.
KnowBe4 Threat Labs later described a ClickFix phishing chain using a
`Review Past Due Doc.zip` / `.lnk` OneDrive lure, clipboard-injected
PowerShell, DNS TXT staging, and hosting domains `document-auth[.]icu`,
`italy-news[.]info`, and `lootrioya[.]info`. This scanner carries those
domains, the reported ZIP hash, and the reported MSI/RMM and password-stealer
hashes as local incident-note indicators.
Wordfence and The Hacker News reported a ShapedPlugin Pro supply-chain
compromise affecting licensed WordPress update channels. This scanner carries
the reported plugin slugs, CVEs, C2/exfil infrastructure, fake plugin paths,
loader/persistence filenames, REST endpoint, 2FA secret markers, login-bypass
hash, and loader SHA-256 as local incident-note indicators.
Aikido's June 1 report describes 30+ compromised `@redhat-cloud-services/*`
npm packages spread through GitHub Actions OIDC / trusted publishing abuse, with
a Mini Shai-Hulud variant calling itself `Miasma`. The scanner treats the exact
reported package versions as critical indicators and warns on the broader
`@redhat-cloud-services/` namespace while the campaign is active.
OX's June 1 follow-up adds high-signal Miasma details including the
`Miasma: The Spreading Blight` repository-description string, the dropped
sixth-stage payload's spaced-colon `Miasma : The Spreading Blight` variant,
decoy `api.anthropic.com` traffic, token-invalidation threat text, the
`firedalazer` commit search marker, and staged payload retrieval from
`letsgo0/sayyadina-phibian-159`.
Aikido's May 27 report, later covered by The Hacker News, describes
`codexui-android` npm builds from `0.1.82` onward exfiltrating OpenAI Codex
authentication data from `~/.codex/auth.json` or `$CODEX_HOME/auth.json` to
`sentry.anyclaw[.]store/startlog`. The scanner treats those exact package
versions as critical and flags related fake-Sentry, Android app, and Codex auth
path indicators when they appear in local source, lockfiles, copied notes, or
incident evidence.
CISA added Palo Alto Networks PAN-OS GlobalProtect `CVE-2026-0257` to the KEV
catalog on May 29, 2026 after observed exploitation. This is not a package
supply-chain indicator, but the scanner flags copied incident notes mentioning
the CVE, PAN-OS GlobalProtect auth bypass, or unauthorized VPN connection
language as defensive triage context.
Calif's June 2026 HTTP/2 Bomb research, later covered by The Register,
describes an Apache HTTP Server remote DoS tracked as `CVE-2026-49975`. Apache
fixed the issue in standalone `mod_http2 v2.0.41` by counting merged cookie
headers against `LimitRequestFields`; until the running module is verified at
that floor or newer, disable HTTP/2 or treat exposed Apache HTTP/2 service as a
patch-priority item. This scanner flags copied incident notes and local Apache
config/module inventory evidence for that fixed floor.
Ammar Askar's June 2, 2026 writeup describes a GitHub token-stealing path
through `github.dev` / VS Code webview and local workspace extension behavior.
The scanner flags high-signal copied PoC markers in `.vscode/extensions.json`,
local extension manifests, JavaScript files, and notebooks. These markers should
prompt review of GitHub token exposure and clearing/revoking affected
`github.dev` browser state where appropriate.
Lupin & Holmes' May 14, 2026 reporting describes malicious `node-ipc` versions
`9.1.6`, `9.2.3`, and `12.0.1` published by the dormant `atiertant` maintainer
identity, likely through email takeover tied to the re-registered
`atlantis-software.net` domain. The scanner treats those exact package versions
as critical indicators and flags high-signal payload/C2 artifacts such as
`node-ipc.cjs`, `__ntw`, `__ntRun`, `uname.txt`, `envs.txt`, DNS resolver
usage, and `sh.azurestaticprovider.net`.
A June 3 operator-provided package table added exact npm package/version
indicators for the Moika follow-up cluster under `@ccrm/*` and `@emcd-vue/*`.
The scanner treats those exact versions as critical package indicators and warns
on those namespaces while the campaign context is active.
JFrog's June 3 IronWorm report describes compromised asteroiddao/WeaveDB npm
packages that shipped a Linux ELF payload at `tools/setup` and executed it with
`preinstall: ./tools/setup`. The scanner treats JFrog's exact npm
package/version IoCs as critical indicators and flags local IronWorm install
hook, forged commit-message, GitHub Actions secret-artifact markers, and
payload-side notes such as Rust infostealer, eBPF rootkit, Tor communication,
and Exodus wallet targeting when they appear in source, manifests, lockfiles,
or copied incident notes.
June 5 operator-provided Mini Shai-Hulud fallout notes, described as being
worked by OX Security with Wiz context, reported 49 Microsoft, Azure, and
Azure-Samples GitHub repositories taken offline after suspected regained
attacker access following the earlier DurableTask compromise. The scanner keeps
those repository slugs as copied-note/repo-context indicators only; they are
not treated as exact package-version IoCs.
Observed GitHub API behavior for `Azure/durabletask` returned
`Repository access blocked` with reason `tos` at the same incident window, and
public code-search triage focused on Claude settings entries that run
`node .github/setup.js`.
SafeDep's June 5 writeup describes the source-repository arm of the same
campaign: commits such as `chore: update dependencies [skip ci]` planted
`.github/setup.js` and wired it into Claude Code, Gemini CLI, Cursor, VS Code,
and `npm test` through `.claude/settings.json`, `.gemini/settings.json`,
`.cursor/rules/setup.mdc`, `.vscode/tasks.json`, and `package.json`.
June 5 operator-provided decoded payload snippets showed token collector
handlers for GitHub, npm, and RubyGems token matches, including obfuscated
fields such as `matches?.ghtoken`, `matches?.fgghtoken`, `matches?.npmtoken`,
and `matches?.rubygemstoken`.
Moshe Siman Tov Bustan's June 5 Azure Miasma sample notes described hardcoded
StepSecurity / Harden-Runner domains used as Docker-environment detection
evasion, reuse of public keys from other Miasma infections, and the same
`firedalazer` GitHub commit-search payload chain.
Additional June 5 screenshots shared through Moshe from heyosj.com showed a
decoded `createPublicGithubExfilRepo` path that creates public GitHub
repositories under `/user/repos` with the description
`Hades - The End for the Damned`, generated Hades-themed repo names, and
`envelope` / `key` payload artifacts.
Socket's June 8, 2026 Hades follow-up reported a PyPI branch using executable
`*-setup.pth` startup hooks, Bun bootstrapping, `_index.js` payload handoff,
`sys.path` payload searching, and trojanized `.abi3.so` native-extension import
triggers. The scanner treats the reported Hades PyPI package versions as
critical dependency indicators and keeps structural markers such as
`langchain_core-setup.pth`, `_index.js`, Bun bootstrap artifacts, and the
reported `ensmallen` native-extension filenames as copied-artifact indicators.
JFrog's June 4 Red Hat / Miasma update expands the exact compromised
`@redhat-cloud-services/*` version set and describes an evasive install-time
execution path through root `binding.gyp` files. The scanner now treats JFrog's
additional exact npm package/version IoCs as critical indicators and flags
`node-gyp` command expansion through `<!(...)`, especially when it invokes
`node`, `bun`, shell/network tools, temp-file payloads, or silent redirects.
OX's June 4 Miasma return report confirms the same `binding.gyp` pivot, reports
57 affected npm packages / 647K monthly downloads, adds two non-Red-Hat exact
package/version IoCs, and documents the updated repository marker
`Miasma – The Spreading Blight`. OX later edited the report with another
weaponized `binding.gyp` wave affecting `discord-search`, `create-cf-token`, 
`@forjacms/*`, `dbmux`, `creditcard.js`, `github-archiver`, and
`@contaazul/n8n-nodes-contaazul`.
June 5 passive decode notes confirmed the same Shai-Hulud/Miasma execution
shape: `setup.js` decrypts or decodes a large second-stage payload, writes it
under `/tmp`, bootstraps Bun if missing, and executes the stage. The stage
targets GitHub/npm tokens, cloud credentials, Docker auth, Kubernetes configs,
SSH/Git credentials, Vault tokens, private keys, wallet paths, and related
developer secrets. The scanner now flags `.github/setup.js` and JavaScript that
combines decode/write/execute or Bun bootstrap behavior with `/tmp` payload
writes and credential-target collection.
OX's June 4 Malware-Slop 2 report describes `cms-store-ren`, a malicious npm
infostealer affecting all observed versions, with Telegram Bot API exfiltration,
a leaked actor bot token, and hidden PowerShell second-stage execution.
GitHub Advisory `GHSA-g6v5-9xpp-6hpx` and supplychainattack.org also mark
`google-cloud-secret-manager-config-poc` as npm malware affecting all versions,
requiring full-compromise handling if installed or run.
Supply Chain Attack's June 22-23 catalog updates add `free-claude`,
`free-anthropic-claude`, `search-from-search`, and a broader npm malware
package cluster as full-compromise indicators.
Checkmarx's ChainVeil report adds the successkey npm package cluster, including
`tailwindcss-merge`, `sass-format`, `sass-formats`, and `rate-limit-flexible`,
plus loader, C2, persistence, and wallet-drainer context.
JFrog's June 24 report adds hijacked `html-to-gutenberg@4.2.11` and
`fetch-page-assets@1.2.9` npm package indicators, a VS Code/Cursor
`runOn: "folderOpen"` autorun task pattern, fake `fa-solid-400.woff2` payload
filename and hashes, blockchain dead-drop terms, and C2/runtime artifact
strings. Nextron's follow-up Go-package telemetry is tracked as OSINT
correlation only.
Panther's April 2026 OtterCookie report adds exact malicious npm versions for
wrapper and payload packages including `bjs-biginteger`,
`bjs-lint-builder(s)`, `hjs-lint-builders`, `sjs-builder(s)`, and
`npm-doc-builder`, with Vercel-hosted C2 and SSH backdoor behavior.
Flatt Security's June 1 Claude Code GitHub Action research, later covered by
The Hacker News, describes a GitHub App actor bypass in agent mode and risky
`allowed_non_write_users` workflow configurations that could expose OIDC token
request credentials or let Claude write exfiltrated data back into GitHub
issues. The scanner now flags `anthropics/claude-code-action` workflows with
untrusted issue/PR triggers, broad write permissions, `id-token: write`, risky
non-write-user settings, and GitHub MCP issue read/update tool combinations.

## Out-of-Scope Windows Disclosures

The Nightmare-Eclipse actor runs a multi-week grudge campaign of Windows
proof-of-concept zero-days, timing GitHub drops right after Patch Tuesday. The
exploits are physical-access / host disk-encryption and local-privilege bugs.
They are not Mini Shai-Hulud package indicators, and this scanner does not test
or reproduce them — they are tracked here as situational awareness only because
defenders see the same reporting stream.

Known exploit names across the campaign: `GreatXML` (newest BitLocker bypass via
a planted `unattend.xml` + `Recovery\WindowsRE` tree, abusing a latent Microsoft
Defender Offline Scan state — a machine that has ever run an offline scan stays
exploitable with no login), `YellowKey` (earlier BitLocker bypass via an `FsTx`
folder on USB/EFI), `GreenPlasma` and `MiniPlasma` (local privilege escalation),
`UnDefend` (Defender disruption), `BlueHammer` (CVE-2026-33825, patched), and
`RedSun`. Known actor handles/aliases: `Nightmare-Eclipse`, `NightmareEclipse`,
`Chaotic Eclipse`, `Dead Eclipse`, `Eclipse`, and the `MSNightmare` GitHub org,
with a self-hosted mirror at `git.projectnightcrawler[.]dev`.

The actor opens and closes repos mid-campaign; do not browse or clone them. Treat
any clone of a "hot 0-day PoC" as Miasma-style clone-bait and run
`miasma-preopen-check.sh` before any agent or editor opens the path. For manual
defensive triage only, public screenshots and writeups mention `Nightmare-Eclipse`,
`GreatXML`, `YellowKey`, `GreenPlasma`, `CSRSS_TEST_SECTION`, and WinRE /
`wpeinit` / `unattend.xml` context.

Adjacent Windows patch-regression risk: Windows 11 cumulative update
`KB5094126`, released June 9, 2026 for Windows 11 `24H2` and `25H2`, has public
reports of boot freezes, forced BitLocker Recovery loops, OneDrive Explorer
integration failures, LAN disruption, and HP device BSOD/update failures tied to
small EFI System Partitions during Secure Boot certificate updates. This is not
evidence of Mini Shai-Hulud compromise and is not scanned by this tool. For
Windows endpoints, preserve BitLocker recovery keys before patch operations,
validate HP/EFI partition guidance, and use WinRE quality-update rollback if a
device becomes unstable immediately after this update.

## Quick Start

```powershell
node .\bin\herewegoagain-incident-scanner.js C:\path\to\project --report report.json
```

```bash
node ./bin/herewegoagain-incident-scanner.js /path/to/project --report report.json
```

Use `--json` to print a machine-readable report to stdout.

Exit code `2` means likely exposure indicators were found.

Human-readable output starts with a plain-language `STOP`, `PAUSE`, or clean-scan
summary for non-specialist users, followed by exact technical findings for
developers, security teams, and CI logs.

## Remediation Plans

`--remediation-plan` turns the findings into a personalized, step-by-step
cleanup plan so an affected developer does not have to map a generic playbook
onto their machine mid-incident. The plan is advisory text only: this tool never
removes files, stops services, revokes credentials, or executes any remediation
step. The operator reviews and runs every command themselves.

Plan items are grouped and ordered by handling class:

- `STOP - DO NOT REMOVE ANYTHING YET` - findings that match persistence
  reported to include a dead-man's switch (for example `gh-token-monitor` or
  `pgsql-monitor`). These print first, with the disarm sequence ordered before
  any credential rotation, because revoking tokens or deleting files in the
  wrong order is reported to trigger the switch and damage the machine.
- `CAUTION - ORDER MATTERS` - cleanup where sequence is load-bearing: isolate
  and preserve evidence before deleting payloads, disarm before rotating, pin
  versions before regenerating lockfiles.
- `REVIEW - SAFE TO HANDLE` - verification items with no compromise ordering,
  such as campaign-adjacent package checks and patch-priority items.

Each item lists the exact findings that triggered it, warnings, numbered steps,
and explicit `DO NOT` lines. With `--json` or `--report`, the same plan is
included in the report as a `remediationPlan` object. Rules live in
`data/remediation.json` and are derived from
[docs/recovery-playbook.md](docs/recovery-playbook.md) and the cited vendor
reporting; a finding type with no rule simply produces no plan item.

## What It Checks

- Known compromised `@tanstack/*` package versions
- Known compromised `@squawk/*` package versions from Socket's campaign table
- Known compromised `@mistralai/*` package versions from Aikido's May 12 update
- Known compromised UiPath, TallyUI, DraftAuth, DraftLab, BeProduct,
  ML Toolkit, TaskFlow, Supersurkhet, Tolka, OpenSearch, Dirigible AI, Mesadev,
  and selected unscoped package versions from Aikido's May 12 update
- Known compromised SAP CAP, Intercom, and older Mini Shai-Hulud npm artifacts
  from Socket's campaign table
- Developing @antv / atool npm publish-wave package indicators from Socket's
  May 19 report, including `@antv/*`, `echarts-for-react`, `timeago.js`,
  `size-sensor`, and `canvas-nest.js`
- @antv payload indicators from Socket's technical analysis, including
  `@antv/setup`, `github:antvis/G2#1916faa365f2788b6e193514872d51a242876569`,
  `t.m-kosche.com`, reversed Shai-Hulud GitHub repository markers,
  `results/results-`, and the `fc2edea72` decoder marker
- Fuma repository-context package review prompts: `fuma-content`, `fumadb`,
  `fumadocs`, `fumadocs-core`, `fumadocs-mdx`, and `fumadocs-ui`
- SafeDep `art-template` / Coruna package review prompt
- Megalodon CI/CD workflow indicators, including `216.126.225.129:8443`,
  `/root/cicd/loot`, `ingest listener OK`, `POST /any ?h=&l=&id=&t=`,
  `GET /health`, fake CI bot author/message strings, and suspicious
  base64-plus-shell/network execution in `.github/workflows/*.yml`
- Composer review prompts for the active Aikido/Socket `laravel-lang/*`
  reports: `laravel-lang/lang`, `laravel-lang/http-statuses`,
  `laravel-lang/attributes`, and `laravel-lang/actions`
- Socket Laravel-Lang backdoor indicators, including Composer
  `autoload.files -> src/helpers.php`, `flipboxstudio[.]info/payload`,
  `.laravel_locale`, `169.254.169.254`, `DebugChromium.exe`,
  `/var/run/secrets/`, and `/proc/[pid]/environ`
- Packagist/GitHub review prompts for reported `devdojo/wave` and
  `devdojo/genesis` exposure, plus `/tmp/.sshd`, `parikhpreyash4`,
  `systemd-network-helper-aa5c751f`, `curl -skL`, `chmod +x /tmp/.sshd`, and
  `Dependency Cache Sync` indicators
- PATH/tool-shadowing indicators, including repo-local executable-like files
  named `ssh`, `git`, `npm`, `node`, `python`, `powershell`, `gh`, `claude`,
  `codex`, `composer`, `pnpm`, or `yarn`, plus fake GitHub shell-access banner
  strings and `export PATH=$(realpath ...):$PATH` style prepends
- ClickFix/staticcloudflare indicators, including `staticcloudflare[.]pro`,
  `https://staticcloudflare[.]pro/api/css.js`, the reversed loader string
  `sj.ssc/ipa/orp.eralfduolccitats`, and `ClickFix`
- ClickFix/KnowBe4 Threat Labs indicators, including `document-auth[.]icu`,
  `italy-news[.]info`, `lootrioya[.]info`, `Review Past Due Doc.zip`, DNS TXT
  staging terms, and the reported ZIP/MSI/password-stealer SHA-256 values
- ShapedPlugin Pro WordPress supply-chain indicators, including
  `woo-product-slider-pro`, `testimonial-pro`, `smart-show-post-pro`,
  `account.shapedplugin[.]com`, `194.76.217[.]28:2871`,
  `generate[.]2faplugin[.]org`, `LicenseLoader.php`,
  `install-persistent.php`, fake `woocommerce-subscription` /
  `woocommerce-notification` plugin paths, and 2FA/login-bypass markers
- Red Hat / Miasma npm indicators from Aikido's June 1 report, including exact
  compromised `@redhat-cloud-services/*` package versions, OIDC/trusted
  publishing workflow strings, and the active `@redhat-cloud-services/`
  namespace review warning
- OX Red Hat / Miasma follow-up indicators, including exact package/version
  coverage for the edited `binding.gyp` wave: `discord-search`, 
  `create-cf-token`, `@forjacms/*`, `dbmux`, `creditcard.js`, 
  `github-archiver`, and `@contaazul/n8n-nodes-contaazul`
- OX/JFrog June 25 Miasma/Hades npm variant indicators, including affected
  `leo-*`, `serverless-*`, `solo-nav`, `rstreams-*`, and
  `@immobiliarelabs/backstage-*` package versions plus reported GitHub exfil,
  raw payload-path, `SEED_PAT`/`Seeder` markers, and SafeDep-reported
  `snapshot-*` / fake `Dependabot Updates` workflow poisoning terms
- OX Red Hat / Miasma follow-up indicators, including
  `Miasma: The Spreading Blight`,
  `Miasma : The Spreading Blight`, `Miasma – The Spreading Blight`,
  `api.anthropic.com/v1/api`,
  `firedalazer`, `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`,
  `letsgo0/sayyadina-phibian-159`, kitty-monitor persistence strings, Bun
  staging markers, `.github/setup.js` reinfection payload shape, JavaScript
  second-stage decode/write/execute behavior, `/tmp` payload writes, credential
  target collection, and JFrog's `binding.gyp` command-expansion package set
- OX Malware-Slop 2 npm indicators, including `cms-store-ren` all-version
  package detection, `api.telegram.org/bot`, `ebalvsehvrot10raz_bot`,
  `amaturesequoyah`, `BREVNA LETYAT`, the reported exfiltration group ID, and
  hidden PowerShell launch flags
- GitHub Advisory npm malware package detection for
  `google-cloud-secret-manager-config-poc`
- Supply Chain Attack catalog npm malware package detection, including
  `free-claude`, `free-anthropic-claude`, `node-fetch-utils`, and
  `node-core-libs`, and `ts-grok`
- Checkmarx ChainVeil / successkey npm package indicators
- JFrog VS Code folder-open autorun / blockchain dead-drop npm indicators for
  `html-to-gutenberg@4.2.11` and `fetch-page-assets@1.2.9`, plus fake
  `fa-solid-400.woff2` payload hashes and Nextron Go-package OSINT leads
- Panther OtterCookie npm indicators, including exact package versions and
  Vercel-hosted C2 domains
- Claude Code GitHub Action workflow-risk indicators, including
  `anthropics/claude-code-action`, `allowed_non_write_users`,
  `id-token: write`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`,
  `ACTIONS_ID_TOKEN_REQUEST_URL`, `mcp__github__get_issue`,
  `mcp__github__update_issue`, and broad write permissions on issue/PR events
- Codex UI token-theft indicators, including compromised `codexui-android`
  versions `0.1.82` through `0.1.125`, `sentry.anyclaw[.]store/startlog`,
  Codex `auth.json` path strings, `anyclaw2026`, `OpenClaw Codex Claude AI
  Agent`, `gptos.intelligence.assistant`, `app.anyclaw.*`,
  `rootfs.tar.zst.bin`, and `anyclaw://auth/codex-callback`
- Palo Alto Networks PAN-OS GlobalProtect `CVE-2026-0257` defensive triage
  markers, including `PAN-OS GlobalProtect`,
  `GlobalProtect Authentication Bypass`, and `unauthorized VPN connection`
- Apache HTTP/2 Bomb / `CVE-2026-49975` defensive triage markers, including
  `HTTP/2 Bomb`, `HPACK Bomb`, `mod_http2 v2.0.41`, `LimitRequestFields`, and
  Apache `httpd.conf` / `apache2.conf` evidence showing vulnerable
  `mod_http2` versions below `2.0.41`
- VS Code / `github.dev` GitHub token-stealing PoC markers, including
  `github-dev-token-steal-poc`, `vscode-github-token-grab-extension`,
  `AmmarTest.hello-ammar-github`, `workbench.extensions.installExtension`, and
  `skipPublisherTrust`
- Aikido / BleepingComputer JetBrains Marketplace AI-key stealer indicators,
  including exact reported plugin IDs such as `org.sm.yms.toolkit` and
  `com.dp.git.ai.tool`, plus `39.107.60[.]51/api/software/key`; DFIR Radar's
  June 25 note adds `F48D2AA7CF341F782C1D`, `BaseUtil.request()`, and
  `save()`/Apply plaintext HTTP POST behavior
- OX easy-day-js / Mastra npm package takeover indicators, including exact
  affected `@mastra/*` versions, `easy-day-js@1.11.22`, `setup.cjs`, and
  `23.254[.]164.92:8000` / `23.254[.]164.123:443`, with Socket's stage-2
  persistence markers such as `protocal.cjs`, `NvmProtocal`,
  `com.nvm.protocal`, `nvmconf.service`, `NodePackages`, `.pkg_history`,
  `.pkg_logs`, `browser-hist-`, `/update/49890878`, and Hostwinds C2
  hostnames
- SafeDep procwire / routecraft Windows npm dropper indicators, including exact
  versions for `procwire`, `routecraft`, `endpointmap`, `bytecraft`, and
  `staticlayer`, the staged `files[.]catbox[.]moe/j4loim[.]chk` payload,
  `Microsoft-Delivery-Optimization/10.0`, Mark-of-the-Web stripping, hidden
  Windows process execution, and updater-like executable names
- Binary Defense BLUERABBIT Windows backdoor/ransomware indicators, including
  `HKCU\Software\OneDrive\Environment`, the `OneDrive Update` scheduled task,
  recovery-suppression values such as `NoAutoRebootWithLoggedOnUsers` and
  `MaintenanceDisabled`, `.candy` encrypted-file markers, `High-Alert`
  wallpaper references, and the reported SHA-256 file hashes
- node-ipc compromise indicators, including malicious `node-ipc` versions
  `9.1.6`, `9.2.3`, and `12.0.1`, `node-ipc.cjs`, `__ntw`, `__ntRun`,
  `uname.txt`, `envs.txt`, `nt-<hash>`, `dns.Resolver`, `atiertant`,
  `atlantis-software.net`, and `sh.azurestaticprovider.net`
- Moika follow-up npm indicators, including exact `@ccrm/*` version `5.0.1`
  package entries and `@emcd-vue/auth@6.4.9`, `@emcd-vue/b2b-pay-form@5.7.4`,
  and `@emcd-vue/loans@7.1.8`
- IronWorm npm indicators from JFrog's June 3 report, including exact
  asteroiddao/WeaveDB package versions, `IronWorm`, `./tools/setup`,
  `.github/scripts/precheck`, forged automation-style commit messages, and
  GitHub Actions `toJSON(secrets)` / `format-results.txt` artifact markers,
  plus copied incident notes mentioning Rust infostealer behavior, eBPF
  rootkit hiding, Tor communication, or Exodus wallet targeting
- Mini Shai-Hulud Azure/Microsoft repo-fallout copied-note indicators,
  including `49 Repositories taken offline`, `Azure/azure-functions-core-tools`,
  `Azure/durabletask`, `Azure-Samples/llm-fine-tuning`, and related
  Azure Functions / DurableTask repository slugs, plus `Repository access
  blocked`, `github.com/tos`, and `node .github/setup.js` settings persistence
  markers
- SafeDep Miasma source-repo persistence indicators across Claude Code, Gemini
  CLI, Cursor, VS Code, and package test scripts: `.claude/settings.json`,
  `.gemini/settings.json`, `.cursor/rules/setup.mdc`, `.vscode/tasks.json`,
  `SessionStart`, `alwaysApply: true`, `runOn: folderOpen`,
  `chore: update dependencies [skip ci]`, and `github-actions` author context
- Decoded token-collector indicators from live Miasma/Shai-Hulud analysis,
  including `matches?.ghtoken`, `matches?.fgghtoken`, `matches?.npmtoken`,
  `matches?.rubygemstoken`, `handleGhTokens`, `handleFgGhTokens`,
  `handleNpmTokens`, and `handleRubygemsTokens`
- Azure Miasma sample indicators from OX research notes, including
  `harden-runner`, `step-security`, `stepsecurity`, `agent.stepsecurity.io`,
  `api.stepsecurity.io`, `app.stepsecurity.io`, `AKIAFAKE`, reused public-key
  context, and the existing `firedalazer` commit-search marker
- Hades GitHub exfil-repo indicators from decoded screenshots, including
  `createPublicGithubExfilRepo`, `generateHadesRepoName`, `/user/repos`,
  `Hades - The End for the Damned`, Hades-themed repo-name prefixes, and
  `envelope` / `key` artifact fields
- Hades PyPI indicators from Socket's June 8/10 wave reporting, including
  affected package versions, `*-setup.pth`, `langchain_core-setup.pth`,
  `_index.js`, Bun bootstrap markers, `sys.path` payload searching, and
  suspicious `.abi3.so` native-extension launcher layouts
- `.vscode/extensions.json` and `.ipynb` notebooks for exact incident strings
- JavaScript source files for exact incident network and campaign strings
- Known compromised PyPI `mistralai`, `guardrails-ai`, `lightning`, and
  `durabletask` versions, plus June 2026 Hades PyPI package versions reported
  by Socket
- Known compromised Composer `intercom/intercom-php` and
  `dcat-auth-google-2fa` versions
- Composer package/plugin capability anomalies such as unexpected
  `composer-plugin`, `composer-plugin-api`, or plugin entry declarations that
  can enable install/update-time execution
- Lower-severity namespace warnings for namespaces reported in the active
  campaign when exact package/version coverage may still be incomplete
- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`, `tanstack_runner.js`, `router_runtime.js`,
  `/tmp/transformers.pyz`, `pgmonitor.py`, `pgsql-monitor.service`, and
  `gh-token-monitor` persistence artifacts
- Known malicious payload SHA-256 hashes when a payload file is present
- Selected network, workflow, token-description, and campaign marker strings
- Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json` config
  references to known payload and campaign indicators
- Install lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`
- Root `binding.gyp` files that use `node-gyp` command expansion through
  `<!(...)`, especially when they invoke `node index.js`, `bun`, `curl`, `wget`,
  shell tools, temp payload paths, or silent redirects
- GitHub Actions workflows using `anthropics/claude-code-action` with public
  issue/PR triggers, `allowed_non_write_users`, `id-token: write`, broad
  write permissions, or GitHub MCP issue read/update tools
- GitHub-resolved dependencies in manifests

## If Indicators Are Found

Do not start by revoking tokens from the suspected infected host. First stop
builds and package installs, isolate the host if execution is possible, then use
a clean machine to rotate credentials and audit accounts.

JFrog's May 12 update reports that the PyPI second-stage payload changed from an
attribution response into a Linux credential stealer with cloud, Kubernetes,
Vault, password-manager, developer-tooling, persistence, and possible
destructive behavior. Treat `mistralai==2.4.6`, `/tmp/transformers.pyz`,
`pgsql-monitor.service`, or `pgmonitor.py` findings as host-compromise signals
until proven otherwise.

Additional May 12-13 public reporting describes country/language-gated
destructive behavior in the Python payload, including Russian-language avoidance
and a reported Israel/Iran location check with randomized file deletion. This is
kept as triage context, not a standalone clean/compromised decision.

See [docs/recovery-playbook.md](docs/recovery-playbook.md).

## Sources

- JFrog Security Research: https://research.jfrog.com/post/shai-hulud-here-we-go-again/
- TanStack official postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Security Advisory: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack issue: https://github.com/TanStack/router/issues/7383
- StepSecurity writeup: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- Socket writeup: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- Aikido broader campaign update: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- OX Security broader npm/PyPI campaign update: https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/
- Resultsense / Decrypt PyPI malware summary: https://www.resultsense.com/news/2026-05-13-mistral-ai-pypi-supply-chain-malware-shai-hulud/
- GitHub Security Advisory GHSA-x223-p2gf-v735 / Langflow CVE-2026-55450: https://github.com/langflow-ai/langflow/security/advisories/GHSA-x223-p2gf-v735
- Snyk TanStack/Mini Shai-Hulud update: https://snyk.io/jp/blog/tanstack-npm-packages-compromised/
- Socket live Mini Shai-Hulud campaign table: https://socket.dev/supply-chain-attacks/mini-shai-hulud
- Socket @antv active publish-wave writeup: https://socket.dev/blog/antv-packages-compromised
- Socket Laravel-Lang compromise writeup: https://socket.dev/blog/laravel-lang-compromise
- Aikido Security May 22, 2026 `laravel-lang/*` Composer/Packagist compromise report: https://x.com/AikidoSecurity
- International Cyber Digest May 22, 2026 Packagist/GitHub supply-chain report: https://x.com/IntCyberDigest
- Endor Labs durabletask PyPI compromise writeup: https://www.endorlabs.com/learn/trojanized-microsoft-sdk-durabletask-1-4-1-through-1-4-3-deliver-credential-stealing-malware
- Wiz durabletask / TeamPCP writeup: https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack
- StepSecurity durabletask supply-chain writeup: https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack
- OX Security Megalodon CI/CD malware report: https://www.ox.security/blog/megalodon-cicd-malware-github/
- SafeDep Megalodon CI workflow backdooring report: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
- VirusTotal domain report for `staticcloudflare[.]pro`: https://www.virustotal.com/gui/domain/staticcloudflare.pro/detection
- Hybrid Analysis URL submission context for `staticcloudflare[.]pro`: https://hybrid-analysis.com/submissions/sandbox/urls
- Wordfence ShapedPlugin Pro supply-chain compromise PSA: https://www.wordfence.com/blog/2026/06/psa-supply-chain-compromise-targets-shapedplugin-backdoored-pro-plugins-distributed-via-official-channels/
- The Hacker News ShapedPlugin Pro supply-chain compromise summary: https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html
- Socket Packagist/Intercom Composer plugin report: https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package
- Aikido Codex remote UI token-theft report: https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
- The Hacker News Codex authentication token theft coverage: https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html
- BleepingComputer / Aikido JetBrains Marketplace AI-key stealer report: https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/
- OX Security easy-day-js / Mastra npm supply-chain report: https://www.ox.security/blog/easy-day-js-supply-chain-attack-hits-mastra-ai-in-npm/
- Socket Mastra npm package compromise analysis: https://socket.dev/blog/mastra-npm-packages-compromised
- SafeDep procwire / routecraft Windows npm dropper campaign: https://safedep.io/procwire-npm-windows-dropper-campaign/
- Aikido Red Hat npm / Miasma compromise report: https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm
- OX Red Hat npm / Miasma compromise report: https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised
- OX Miasma return / `binding.gyp` npm package expansion: https://www.ox.security/blog/600000-monthly-downloads-affected-miasma-supply-chain-attack-is-back-on-npm/
- OX Malware-Slop 2 `cms-store-ren` npm / Telegram exfiltration report: https://www.ox.security/blog/malware-slop-2-malicious-npm-package-leaks-its-own-bots-telegram-private-token/
- GitHub Advisory for `google-cloud-secret-manager-config-poc`: https://github.com/advisories/GHSA-g6v5-9xpp-6hpx
- supplychainattack.org incident for `google-cloud-secret-manager-config-poc`: https://supplychainattack.org/incident/malware-in-google-cloud-secret-manager-config-poc-1fs99l
- Supply Chain Attack incident catalog, ts-grok npm malware: https://supplychainattack.org/incident/malware-in-ts-grok-jjsh0j
- GitHub Advisory Database, GHSA-qp73-r9hh-6vq9 / ts-grok npm malware: https://github.com/advisories/GHSA-qp73-r9hh-6vq9
- Supply Chain Attack incident catalog, latest npm malware batch: https://supplychainattack.org/
- Supply Chain Attack incident catalog, free-claude npm malware: https://supplychainattack.org/incident/malware-in-free-claude-7fjbqi
- Checkmarx ChainVeil / successkey npm supply-chain report: https://checkmarx.com/zero-post/chainveil-a-malicious-npm-supply-chain-attack-by-successkey/
- JFrog VS Code autorun / blockchain dead-drop npm hijack report: https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/
- SafeDep Miasma LeoPlatform npm package and workflow poisoning analysis: https://safedep.io/miasma-worm-hits-leoplatform-20-npm-packages/
- Panther OtterCookie npm campaign: https://panther.com/blog/tracking-an-ottercookie-infostealer-campaign-across-npm
- Lupin & Holmes node-ipc compromise report: https://www.landh.tech/blog/20260514-node-ipc-compromised/
- JFrog IronWorm / Shai-Hulud's Rustier Cousin report: https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
- Palo Alto Networks CVE-2026-0257 advisory: https://security.paloaltonetworks.com/CVE-2026-0257
- CISA KEV catalog entry for CVE-2026-0257: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Calif HTTP/2 Bomb research: https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb
- Apache `mod_http2 v2.0.41` release: https://github.com/icing/mod_h2/releases/tag/v2.0.41
- The Register HTTP/2 Bomb coverage: https://www.theregister.com/security/2026/06/04/openais-codex-chains-decade-old-dos-techniques-into-http/2-bomb/5251377
- Ammar Askar GitHub token stealing via VS Code / github.dev writeup: https://blog.ammaraskar.com/github-token-stealing/
- SafeDep Miasma source-repository AI coding agent config injection writeup: https://safedep.io/miasma-worm-ai-coding-agent-config-injection/

## License

MIT
