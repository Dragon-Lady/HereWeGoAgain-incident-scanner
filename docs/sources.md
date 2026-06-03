# Sources

- JFrog Security Research: https://research.jfrog.com/post/shai-hulud-here-we-go-again/
- TanStack official postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Security Advisory GHSA-g7cv-rxg3-hmpx / CVE-2026-45321: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack Router issue #7383: https://github.com/TanStack/router/issues/7383
- StepSecurity technical writeup: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- Socket TanStack/Mini Shai-Hulud writeup: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- Aikido broader Mini Shai-Hulud campaign update: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- OX Security broader npm/PyPI campaign update: https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/
- Resultsense / Decrypt PyPI malware summary: https://www.resultsense.com/news/2026-05-13-mistral-ai-pypi-supply-chain-malware-shai-hulud/
- Snyk TanStack/Mini Shai-Hulud update: https://snyk.io/jp/blog/tanstack-npm-packages-compromised/
- Socket live Mini Shai-Hulud campaign table: https://socket.dev/supply-chain-attacks/mini-shai-hulud
- Socket @antv active publish-wave writeup: https://socket.dev/blog/antv-packages-compromised
- Fuma Nama May 21, 2026 update on `fuma-content` repository impact and pnpm v9/v11 postinstall context: https://x.com/fuma_nama
- SafeDep `art-template` / Coruna npm supply-chain compromise report: https://safedep.io/art-template-npm-supply-chain-compromise/
- OX Security Megalodon CI/CD malware report: https://www.ox.security/blog/megalodon-cicd-malware-github/
- SafeDep Megalodon CI workflow backdooring report: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
- Aikido Security May 22, 2026 `laravel-lang/*` Composer/Packagist compromise report: https://x.com/AikidoSecurity
- International Cyber Digest May 22, 2026 Packagist/GitHub supply-chain report: https://x.com/IntCyberDigest
- Packagist `laravel-lang/lang`: https://packagist.org/packages/laravel-lang/lang
- Packagist `laravel-lang/http-statuses`: https://packagist.org/packages/laravel-lang/http-statuses
- Packagist `laravel-lang/attributes`: https://packagist.org/packages/laravel-lang/attributes
- Endor Labs durabletask PyPI compromise writeup: https://www.endorlabs.com/learn/trojanized-microsoft-sdk-durabletask-1-4-1-through-1-4-3-deliver-credential-stealing-malware
- Wiz durabletask / TeamPCP writeup: https://www.wiz.io/blog/durabletask-teampcp-supply-chain-attack
- StepSecurity durabletask supply-chain writeup: https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack
- VirusTotal domain report for `staticcloudflare[.]pro`: https://www.virustotal.com/gui/domain/staticcloudflare.pro/detection
- Hybrid Analysis URL submission context for `staticcloudflare[.]pro`: https://hybrid-analysis.com/submissions/sandbox/urls
- Socket Packagist/Intercom Composer plugin report: https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package
- Aikido Codex remote UI token-theft report: https://www.aikido.dev/blog/codex-remote-ui-steals-ai-tokens
- The Hacker News Codex authentication token theft coverage: https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html
- Aikido Red Hat npm / Miasma compromise report: https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm
- OX Red Hat npm / Miasma compromise report: https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised

## Out-of-Scope Related Public Intel

- Dark Web Informer X post amplifying the Nightmare-Eclipse disclosures: https://x.com/DarkWebInformer/status/2054264278044000262
- Chaotic Eclipse PGP-signed disclosure naming `YellowKey` and `GreenPlasma`: https://deadeclipse666.blogspot.com/2026/05/two-more-public-disclosures-it-will.html
- Nightmare-Eclipse `YellowKey` repository: https://github.com/Nightmare-Eclipse/YellowKey
- Nightmare-Eclipse `GreenPlasma` repository: https://github.com/Nightmare-Eclipse/GreenPlasma
- Microsoft MSRC CVE-2026-41096 advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41096
- NVD CVE-2026-41096 record: https://nvd.nist.gov/vuln/detail/CVE-2026-41096
- Zero Day Initiative May 2026 security update review: https://www.zerodayinitiative.com/blog/2026/5/12/the-may-2026-security-update-review
- AlmaLinux Fragnesia / CVE-2026-46300 disclosure: https://almalinux.org/blog/2026-05-13-fragnesia-cve-2026-46300/
- NVD CVE-2026-46300 record: https://nvd.nist.gov/vuln/detail/CVE-2026-46300
- Palo Alto Networks CVE-2026-0257 PAN-OS GlobalProtect advisory: https://security.paloaltonetworks.com/CVE-2026-0257
- CISA Known Exploited Vulnerabilities catalog entry for CVE-2026-0257: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Ammar Askar GitHub token stealing via VS Code / github.dev writeup: https://blog.ammaraskar.com/github-token-stealing/

These Windows, Linux, network-edge, and developer-toolchain disclosure links are
retained primarily for manual context. They are not Mini Shai-Hulud package
indicators.

This project intentionally avoids publishing exploit reproduction steps or
malware execution guidance.
