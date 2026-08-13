# Security Policy

## Report a Project Vulnerability Privately

Use GitHub's private vulnerability reporting form:

https://github.com/Dragon-Lady/HereWeGoAgain-incident-scanner/security/advisories/new

Report vulnerabilities in this scanner, its repository automation, or its
published package through that private channel. If private reporting is not
available, open a minimal public issue asking the maintainer for a private
contact path; do not include sensitive details in the issue.

## Redaction and Data Handling

Send only the minimum information needed to reproduce the project defect. Do
not submit tokens, credentials, private keys, `.env` contents, raw or full scan
output, user or repository paths, proprietary logs, personal data, or malware
samples. Prefer synthetic examples and redacted finding types, severity, exit
code, platform, and Node.js version.

The scanner is a local, read-only referral tool. It does not upload or retain
scan results. Public issue reports should preserve that no-retention boundary.

## Scope

Ordinary false-positive, false-negative, usability, and documentation reports
may use the redacted public issue templates. Suspected vulnerabilities that
could expose users, execute code, leak data, or weaken the scanner's safety
contract should use private vulnerability reporting.
