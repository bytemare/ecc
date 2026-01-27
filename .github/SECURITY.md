# Security Policy

## Supported Versions

Only the latest minor release of each supported major version receives security fixes. Consumers should stay current with tagged releases. Patch-level updates are fast-forward compatible unless otherwise documented in the [CHANGELOG](CHANGELOG.md).

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** via [GitHub Security Advisories](https://github.com/bytemare/ecc/security/advisories).

Using the advisory workflow ensures that the report is shared only with the maintainers. Do **not** open a public issue for security reports.

## Disclosure Process

1. Submit a draft advisory with as much detail as possible (affected APIs, impact, reproduction steps).
2. Maintainers aim to acknowledge receipt within 7 calendar days.
3. We will coordinate on a fix, validate it with regression tests, and prepare a coordinated disclosure and release. Typical remediation targets 30 days or less depending on severity and complexity.
4. Once a fix is available, we will publish the advisory, issue a patched release, and credit reporters who request attribution.

If you have not heard back within the acknowledgement window, please bump the advisory thread before considering alternative contact methods.

## Out of Scope

- Vulnerabilities that stem from misuse of the API outside documented preconditions (e.g., reusing identity encodings against decode functions).
- Issues in third-party dependencies unless they demonstrably expose this project to risk without upstream mitigation.

Thank you for helping keep this project and its users secure!
