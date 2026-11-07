# Security Policy

## Overview

Security policy, supported releases, and vulnerability reporting procedures for MetaScan.

---

## Supported Versions

Security updates and patches are maintained for the following versions:

| Version | Supported          | Status                                 |
| ------- | ------------------ | -------------------------------------- |
| 1.1.x   | :white_check_mark: | Currently supported with security fixes |
| 1.0.x   | :white_check_mark: | Security maintenance only              |
| < 1.0   | :x:                | End of Life (Unsupported)              |

All operators are advised to update their installations to the latest release.

---

## Reporting a Vulnerability

If you identify a security vulnerability in MetaScan, report it privately.

> [!IMPORTANT]
> **Do not open public GitHub Issues or discussions for security vulnerabilities.**
> Disclosing vulnerabilities publicly before a fix is available puts operators at risk.

### Disclosure Contact

Submit vulnerability reports via email:

**`[m.konyaev@proton.me]`**

*Subject line prefix*: `[SECURITY] MetaScan Vulnerability Report`

### Information to Include

To assist the development and security engineering team in rapid triage and reproduction, please provide:
1. **Description**: A comprehensive description of the vulnerability and its potential impact.
2. **Affected Component**: Target module, file, CLI parameter, or network validation layer.
3. **Environment**: Operating system, Python version, MetaScan version, and relevant runner packages.
4. **Steps to Reproduce**: Minimal, reproducible proof-of-concept (PoC) code or command sequence.
5. **Mitigation Suggestion**: Any proposed remediation or patches (if available).

### Response SLA and Process

- **Initial Acknowledgment**: Within **48 hours** of receiving your report.
- **Triage & Assessment**: Within **5 business days**, detailing vulnerability confirmation and severity rating (CVSS).
- **Remediation & Patching**: A dedicated hotfix release will be prepared and thoroughly regression-tested.
- **Public Disclosure**: Coordinated disclosure will occur only after a fixed release is available for operators.

---

## Security Best Practices for Operators

1. **Supply Chain Integrity**: Use the provided provisioning scripts (`install_dependencies.sh` / `install_dependencies.ps1`), which enforce commit-pinned checkouts and hash verification for external tools.
2. **Execution Context**: Execute scans in dedicated virtual environments (`.venv`) or isolated containers.
3. **Target Validation**: MetaScan enforces input sanitization on usernames to prevent command and path injection. Do not bypass CLI validation.
4. **Local Execution**: MetaScan operates with 100% local execution and zero telemetry. Do not expose local report outputs to untrusted networks without access controls.
