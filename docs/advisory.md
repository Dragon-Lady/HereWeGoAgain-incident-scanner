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

Separate May 12, 2026 Nightmare-Eclipse / Chaotic Eclipse Windows disclosures
for `YellowKey` and `GreenPlasma` are out of scope for this scanner. They are
tracked here only as related public situational awareness because readers may see
the same reporting stream. Do not add those repositories or screenshots to
scanner detection data unless a confirmed Mini Shai-Hulud package, payload, or
campaign artifact overlaps. Manual triage strings from the public reporting
include `Nightmare-Eclipse`, `YellowKey`, `GreenPlasma`, `CSRSS_TEST_SECTION`,
and WinRE / `wpeinit` context.

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
`format-results.txt`. This scanner treats JFrog's exact npm package/version
IoCs as critical indicators and keeps the install-hook/workflow strings as
source and incident-note indicators.

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
`Miasma – The Spreading Blight`. This scanner treats OX's additional exact
package/version entries as critical npm indicators and keeps the dash-variant
marker alongside the earlier colon variants.

OX's June 4, 2026 Malware-Slop 2 report describes `cms-store-ren`, a malicious
npm JavaScript infostealer reported as affecting all versions. OX describes
basic host telemetry and data exfiltration over the Telegram Bot API, hidden
PowerShell second-stage execution using `-WindowStyle Hidden` and
`-ExecutionPolicy Bypass`, and actor/operator markers including
`ebalvsehvrot10raz_bot`, `amaturesequoyah`, and `BREVNA LETYAT`. This scanner
treats any `cms-store-ren` package reference as a critical npm indicator and
flags copied local notes/source containing the high-signal Telegram and
PowerShell markers.

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
  `toJSON(secrets)`, and `format-results.txt`
- known affected PyPI `mistralai` and `guardrails-ai` package/version pairs from
  OX Security's May 12 update in `data/packages/pypi.json`
- known affected PyPI `lightning` and `durabletask`, plus Composer
  `intercom/intercom-php`
  package/version pairs from Socket's live campaign table
- Composer package/plugin capability anomalies such as unexpected
  `composer-plugin`, `composer-plugin-api`, or plugin entry declarations. These
  are high-severity review prompts because Composer plugins can execute during
  install/update; confirm they are expected and match upstream source before
  continuing.
- Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json`
  references to known payload, network, token-description, and campaign strings

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
