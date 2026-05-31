# Here We Go Again Incident Scanner

Read-only exposure scanner and recovery guidance for the May 2026
`Shai-Hulud: Here We Go Again` npm/PyPI supply-chain incident and related
Mini Shai-Hulud npm/PyPI/Composer indicators.

This tool helps identify known indicators. It does not remove malware, revoke
credentials, execute package scripts, or prove that a host is clean.

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

## Out-of-Scope Windows Disclosures

On May 12, 2026, Dark Web Informer amplified separate Nightmare-Eclipse /
Chaotic Eclipse disclosures for `YellowKey` and `GreenPlasma`. These are not
Mini Shai-Hulud package indicators and this scanner does not test or reproduce
them. For manual defensive triage only, public screenshots and writeups mention
`Nightmare-Eclipse`, `YellowKey`, `GreenPlasma`, `CSRSS_TEST_SECTION`, and
WinRE / `wpeinit` context.

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
- JavaScript source files for exact incident network and campaign strings
- Known compromised PyPI `mistralai`, `guardrails-ai`, `lightning`, and
  `durabletask` versions
- Known compromised Composer `intercom/intercom-php` version
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
- Socket Packagist/Intercom Composer plugin report: https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package

## License

MIT
