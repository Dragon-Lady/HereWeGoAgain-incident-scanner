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
cd C:\Users\tanya\HereWeGoAgain-incident-scanner
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
- network/workflow/token/campaign marker strings in `data/affected-packages.json`
- payload SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- payload SHA-256 `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- affected package/version pairs in `data/affected-packages.json`

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

## Fast Update Flow

1. Update `data/affected-packages.json` for new confirmed package/version indicators.
2. Add a fixture or smoke assertion if the scanner behavior changes.
3. Run `npm test`.
4. Commit with a narrow message.
5. Push `main`.

## Good Next Improvements

- Add `--severity-threshold` for CI use.
- Add `--ignore-review-needed` if lifecycle script findings are too noisy.
- Add examples for npm, pnpm, yarn, and monorepo scans.
- Add a signed GitHub release once public feedback stabilizes.
