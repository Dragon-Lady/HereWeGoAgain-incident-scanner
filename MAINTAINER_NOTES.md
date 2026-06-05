# Maintainer Notes

Current public repo:
https://github.com/Dragon-Lady/HereWeGoAgain-incident-scanner

Initial release state:

- Branch: `main`
- Initial commit: pending
- Runtime: Node.js >= 18
- Dependencies: none
- Safety stance: read-only scanner, no package installs, no script execution, no malware removal claims

## Core Commands

```powershell
cd C:\path\to\HereWeGoAgain-incident-scanner
npm test
node bin\herewegoagain-incident-scanner.js C:\path\to\project --report report.json
node bin\herewegoagain-incident-scanner.js C:\path\to\project --json
```

## Current Indicators

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- `/tmp/transformers.pyz`
- `gh-token-monitor` persistence files
- network/workflow/token/campaign marker strings in `data/indicators.json`
- payload SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- payload SHA-256 `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- affected package/version pairs in `data/packages/`

## Campaign Scope Note

JFrog Security Research reports more than 170 npm packages and 2 PyPI packages
affected by `Shai-Hulud: Here We Go Again` as of May 12, 2026. TanStack's
official postmortem confirms 84 malicious versions across 42 `@tanstack/*`
packages, published on May 11, 2026 between 19:20 and 19:26 UTC.
The associated GitHub Security Advisory is GHSA-g7cv-rxg3-hmpx /
CVE-2026-45321.

As of the May 12, 2026 update, Aikido and Socket reporting track broader Mini
Shai-Hulud package artifacts across npm, PyPI, and Composer. Additional
package/version indicators should only be added after exact confirmation.

For Composer/Packagist incidents, keep exact known-bad package versions in
`data/packages/composer.json`, but also retain behavioral coverage for
unexpected Composer plugin capability. A legitimate package unexpectedly
declaring `composer-plugin`, `composer-plugin-api`, or plugin entry classes can
enable install/update-time execution and should be treated as a high-severity
review prompt even when the exact package/version is not yet encoded.

## Public Response Rules

- Do not ask users to paste secrets, `.env` files, private keys, tokens, or full logs.
- Do not claim the tool proves a host is clean.
- If indicators are found, advise containment first.
- Do not advise revoking tokens from the suspected infected machine.
- Credential rotation should happen from a clean machine.
- If payload execution, persistence, or secret exposure is plausible, recommend rebuild/reimage.

## Public Signal Log

- 2026-05-11: Tanner Linsley (`@tannerlinsley`), creator of TanStack, liked related public activity. Treat as a morale/visibility signal only, not formal endorsement or technical validation.
- 2026-05-11: GitHub analysis showed a user scan reached Ubuntu and reported about 7 seconds per pass. Scope is partial Ubuntu/Linux coverage only; do not treat this as full matrix completion or broad platform validation. No errors were observed in the reported completed portion.
- 2026-05-13: JFrog Security publicly reported false positives for
  `GHSA-grrc-v84p-qwv3` (`@puppeteer/browsers` 3.0.1) and
  `GHSA-rvxm-vq55-8p53` (`puppeteer-core` 25.0.1), noting that
  automation is a tool rather than a judge. Do not add these advisory IDs as
  malicious Here We Go Again/Mini Shai-Hulud indicators without later corrected
  confirmation. If users ask about them, route to manual review and explain
  that advisory-scale noise can be large because `puppeteer-core` has very high
  install volume.
- 2026-05-13: Public reporting/social chatter indicates active abuse and
  incentive-driven spread attempts around this campaign. Keep the scanner
  defensive: read-only detection, containment-first guidance, and no malware
  removal claims until trusted vendors publish tested removal steps.
- 2026-05-13: TechCrunch/WIRED reported that Nitrogen ransomware claimed a
  Foxconn breach affecting North American factory operations, with alleged
  theft of customer project data from Apple, Google, Dell, Intel, Nvidia, and
  others. Treat as adjacent hardware/manufacturing supply-chain context only.
  Do not add scanner rules from this incident unless public reporting provides
  concrete developer-package, file/hash, network, or tool-persistence IOCs that
  overlap this scanner's local detection scope.
- 2026-05-13: AlmaLinux disclosed Fragnesia / `CVE-2026-46300`, a Linux kernel
  local-root issue in the same broad surface as Copy Fail and Dirty Frag. Treat
  as adjacent Linux host-risk context for developer workstations, CI runners,
  container build farms, and multi-tenant hosts only. Do not add scanner rules
  unless a confirmed Here We Go Again/Mini Shai-Hulud payload starts using this
  CVE or leaves concrete package, file/hash, network, or persistence IOCs.
- 2026-05-27: Asim Viladi Oglu Manizada disclosed CIFSwitch /
  `CVE-2026-46243`, a Linux local-root chain involving the kernel CIFS client,
  `cifs-utils`, `cifs.spnego` request-key handling, and namespace/NSS
  confusion. Treat as adjacent Linux host-risk context only. Do not add scanner
  rules unless a confirmed Here We Go Again/Mini Shai-Hulud payload starts
  using this CVE or leaves concrete package, file/hash, network, or persistence
  IOCs.
- 2026-06-03: JFrog Security Research published IronWorm / "Shai-Hulud's
  rustier cousin" IoCs for compromised asteroiddao/WeaveDB npm packages. This
  is scanner material because it includes exact npm package/version indicators
  and high-signal local strings such as `preinstall: ./tools/setup`,
  `IronWorm`, forged automation-style commit messages, `toJSON(secrets)`, and
  `format-results.txt`.
- 2026-06-05: The Hacker News roll-up coverage emphasized IronWorm payload-side
  behavior: Rust infostealer, eBPF rootkit hiding, Tor communication, Exodus
  wallet targeting, and broad environment/credential-file collection. Added
  those as copied-note/local-artifact campaign indicators.
- 2026-06-05: Operator-provided Mini Shai-Hulud fallout screenshot, described
  as active OX Security work with Wiz context, reported 49 Microsoft, Azure,
  and Azure-Samples GitHub repositories taken offline after suspected regained
  attacker access following the DurableTask compromise. Added the banner text
  and repository slugs as copied-note/repo-context indicators only, not exact
  package-version IoCs.
- 2026-06-05: Verification of the supplied `Azure/durabletask` compare link via
  GitHub API returned `Repository access blocked` with reason `tos`; added that
  as copied-note evidence context. Also added `node .github/setup.js` and the
  related GitHub code-search query as Claude settings persistence indicators.
- 2026-06-05: SafeDep published a Miasma source-repository config-injection
  writeup covering Claude Code, Gemini CLI, Cursor, VS Code, and package test
  triggers that all launch `node .github/setup.js`. Added exact trigger
  strings and expanded scanner coverage to `.gemini/settings.json` and
  `.cursor/rules/*.mdc`, plus a critical config-shape finding for tool configs
  that auto-run the reported payload path.
- 2026-06-04: JFrog Security Research updated Red Hat / Miasma reporting with
  expanded exact `@redhat-cloud-services/*` package/version indicators and an
  evasive `binding.gyp` install-time execution path through node-gyp command
  expansion. This is scanner material because it includes exact npm
  package/version IoCs and local package-file behavior that can execute before
  ordinary `package.json` lifecycle-script checks fire.
- 2026-06-04: OX Security published a Miasma return report naming 57 affected
  npm packages, roughly 647K monthly downloads, the same `binding.gyp`
  execution pivot, and the exact `Miasma – The Spreading Blight` repository
  marker. This is scanner material because it adds exact package/version IoCs
  and a high-signal local marker variant.
- 2026-06-05: OX edited the same Miasma return report with another weaponized
  `binding.gyp` npm wave. Added exact indicators for `discord-search`, 
  `create-cf-token`, `@forjacms/*`, `dbmux`, `creditcard.js`, 
  `github-archiver`, and `@contaazul/n8n-nodes-contaazul`.
- 2026-06-04: OX Security published Malware-Slop 2 reporting for
  `cms-store-ren`, a malicious npm infostealer affecting all observed versions
  with Telegram Bot API exfiltration, leaked actor bot/account markers, and
  hidden PowerShell execution flags. This is scanner material because it has a
  concrete npm package indicator and high-signal local strings.
- 2026-06-04: Flatt Security / The Hacker News described Claude Code GitHub
  Action risk from GitHub App actor bypasses, risky `allowed_non_write_users`
  settings, OIDC token request credentials, and GitHub MCP issue read/update
  exfiltration paths. This is scanner material because the risky local state is
  visible in `.github/workflows/*.yml` without executing anything.
- 2026-06-05: Calif / The Register HTTP/2 Bomb reporting added Apache HTTP
  Server defensive triage for `CVE-2026-49975`. The Apache fix floor is
  standalone `mod_http2 v2.0.41`; this is scanner material when copied
  incident notes or local Apache config/module inventory expose HTTP/2 state or
  a vulnerable `mod_http2` version.
- 2026-06-05: Live passive decode notes confirmed Shai-Hulud/Miasma `setup.js`
  second-stage behavior: decrypt/decode, write a large payload under `/tmp`,
  bootstrap Bun when missing, execute it, and collect developer/cloud secrets.
  Added shape-based JavaScript detection for `.github/setup.js` and clustered
  Bun/tmp/credential-target behavior.

## Fast Update Flow

1. Update the relevant file under `data/packages/` for new confirmed package/version indicators.
2. Add a fixture or smoke assertion if the scanner behavior changes.
3. Run `npm test`.
4. Commit with a narrow message.
5. Push `main`.

## Good Next Improvements

- Add `--severity-threshold` for CI use.
- Add `--ignore-review-needed` if lifecycle script findings are too noisy.
- Add examples for npm, pnpm, yarn, and monorepo scans.
- Add a signed GitHub release once public feedback stabilizes.

