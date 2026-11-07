<a id="readme-top"></a>

<div align="center">
  <img src="https://i.imgur.com/zOcvR1j.jpeg" alt="MetaScan Banner" width="100%">
  <br />
  <br />
  <h1>MetaScan</h1>
  <p>
    <strong>Asynchronous OSINT Username Reconnaissance and Verification Tool</strong>
  </p>
  <p>
    <a href="https://github.com/fondgard/metascan/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
    <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-policy-blue.svg" alt="Security Policy"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  </p>
  <p>
    <em>CI/CD: SAST scanning with Bandit, dependency audits, Flake8 linting, and pytest suite.</em>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#core-capabilities">Core Capabilities</a></li>
        <li><a href="#validation-pipeline">Validation Pipeline</a></li>
        <li><a href="#system-architecture">System Architecture</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#basic-execution">Basic Execution</a></li>
        <li><a href="#advanced-workflows">Advanced Workflows</a></li>
        <li><a href="#command-line-reference">Command-Line Reference</a></li>
        <li><a href="#reporting-and-artifacts">Reporting and Artifacts</a></li>
      </ul>
    </li>
    <li><a href="#data-privacy">Data Privacy</a></li>
    <li><a href="#continuous-integration--security-audits">CI/CD & Security Audits</a></li>
    <li><a href="#security-policy">Security Policy</a></li>
    <li><a href="#disclaimer">Disclaimer</a></li>
  </ol>
</details>

## About The Project

MetaScan is an asynchronous OSINT command-line tool for username reconnaissance across multiple online services. It aggregates findings from **Sherlock**, **Maigret**, and **Blackbird**, removes duplicates, and filters false positives through a multi-stage HTTP/2 validation pipeline.

Standard username enumeration scanners often produce false positives due to soft-404 pages (HTTP 200 with "user not found" body text), unhandled redirects to login walls, or anti-bot challenge pages. MetaScan validates candidate profile endpoints before writing reports.

### Core Capabilities

- **Concurrent Multi-Engine Orchestration**: Executes Sherlock, Maigret, and Blackbird in parallel as non-blocking asynchronous subprocesses.
- **URL Normalization and Deduplication**: Canonicalizes scheme, host casing, default ports, trailing slashes, and platform-specific aliases to merge duplicate results across tools.
- **Asynchronous HTTP/2 Validation**: Verifies discovered profile URLs using `httpx` with HTTP/2 support, throttled by asyncio semaphores.
- **Standalone HTML & JSON Reports**: Generates an offline HTML dashboard with client-side search filtering, separated valid and filtered result tables, and embedded raw JSON data.

### Validation Pipeline

MetaScan evaluates candidate endpoints through four sequential checks:

1. **HTTP Status Code Verification**: Rejects standard negative codes (`404 Not Found`, `410 Gone`, `451 Unavailable`) and server errors (`5xx`). Flags WAF challenges (`401`, `403`, `429`).
2. **Redirect Inspection**: Traces redirect chains. Requests redirected to domain roots (`/`, `/home`), authentication gates (`/login`, `/signin`, `/authwall`), or generic landing/error pages (`/404`, `/error`, `/lander`) are marked as invalid.
3. **Soft-404 Detection**: Scans DOM `<title>` tags and body content for account-absence signatures in English and Russian.
4. **Platform-Specific Heuristics**: Custom validation logic for platforms with SPA rendering or non-standard status responses (Twitter/X, Instagram, TikTok, Reddit, Telegram, YouTube, Twitch, Pinterest, Spotify).

### System Architecture

The following diagram illustrates the lifecycle of a MetaScan execution from target input to finalized artifacts:

```
Target Username
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Async Orchestrator                       │
│  ┌─────────────────┬───────────────────┬─────────────────┐  │
│  │ Sherlock Runner │  Maigret Runner   │ Blackbird Runner│  │
│  └────────┬────────┴─────────┬─────────┴────────┬────────┘  │
└───────────┼──────────────────┼──────────────────┼───────────┘
            │                  │                  │
            ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                       Result Registry                       │
│      URL Canonicalization & Engine Provenance Merging       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   AsyncValidator Engine                     │
│  - Tier 1: Connection & Protocol Negotiation (HTTP/2)       │
│  - Tier 2: HTTP 200 OK Status Enforcement                   │
│  - Tier 3: Redirect Path and Landing Page Traps             │
│  - Tier 4: Stop-Word Corpus & Service-Specific Probes       │
└──────────────────────────────┬──────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
     Confirmed Profiles                   Filtered Results
     (Status: Found)                      (Reason Tagged)
            │                                     │
            └──────────────────┬──────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        Report Exporter                      │
│   - Standalone Interactive HTML Dashboard                   │
│   - Embedded Machine-Readable JSON Export                   │
└─────────────────────────────────────────────────────────────┘
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

- **Python**: Version 3.11 or later.
- **Git**: Installed and available in the system `PATH`.
- **Operating System**: Linux, macOS, or Windows (PowerShell 5.1+ or Core).

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fondgard/metascan.git
   cd metascan
   ```

2. **Configure a virtual environment**:
   - **Linux / macOS**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - **Windows (PowerShell)**:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```

3. **Install MetaScan and Python dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   ```

4. **Install external scanner dependencies**:
   MetaScan uses external tools (including Blackbird, managed outside standard PyPI packages). Run the provisioning script for your operating system:
   - **Linux / macOS**:
     ```bash
     chmod +x install_dependencies.sh
     ./install_dependencies.sh
     ```
   - **Windows (PowerShell)**:
     ```powershell
     .\install_dependencies.ps1
     ```

   The script clones external repositories into `~/.local/share/metascan` (or `%LOCALAPPDATA%\metascan`), checks out pinned commits with SHA-256 verification, installs Python requirements, and sets up CLI wrappers.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

### Basic Execution

Scan a target username across all configured engines. By default, MetaScan saves results to `reports/metascan_<username>.html` and opens the report in the system browser:

```bash
mns target_username
```

### Advanced Workflows

Specify custom output paths, concurrency limits, runner timeouts, or disable browser launching:

```bash
mns target_username -o reports/audit_target.html -c 40 -t 90 --no-open
```

### Command-Line Reference

| Argument / Option | Short | Default Value | Description |
|---|---|---|---|
| `USERNAME` | — | *(Required)* | Target username to investigate across platforms. |
| `--output` | `-o` | `reports/metascan_<user>.html` | Output file path for the generated HTML report. |
| `--concurrency` | `-c` | `20` | Maximum number of concurrent asynchronous HTTP validation requests. |
| `--timeout` | `-t` | `120` | Subprocess timeout (in seconds) for each external scanner. |
| `--no-open` | — | `False` | Disables opening the report in the browser automatically. |
| `--version` | `-v` | — | Displays the installed MetaScan version and exits. |
| `--help` | — | — | Displays command-line help instructions and available options. |

### Reporting and Artifacts

Upon completion, MetaScan produces an offline HTML report containing:

- **Summary Header**: Target username and count of confirmed profiles.
- **Valid Results**: Table of verified profiles with service name, detecting tools, and copyable URLs.
- **Filtered Results**: Diagnostic log documenting rejected URLs alongside explicit failure reasons (`404 Not Found`, `Soft-404 (User Not Found)`, `Redirect to Login/404`, `Timeout`).
- **Raw JSON Data Block**: Formatted JSON dataset embedded directly within the report:

```json
{
  "target": "target_username",
  "scanners": ["Sherlock", "Maigret", "Blackbird"],
  "results": {
    "Github": {
      "url": "https://github.com/target_username",
      "status": "Found",
      "tools": ["Sherlock", "Maigret", "Blackbird"]
    },
    "ExampleService": {
      "url": "https://example.com/target_username",
      "status": "Error",
      "error_type": "Soft-404 (User Not Found)",
      "tools": ["Sherlock"]
    }
  }
}
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Data Privacy

- **Zero-Telemetry**: All operations run locally. No target queries, usernames, or telemetry metrics are sent to remote servers.
- **Local Storage**: Generated HTML reports and JSON datasets are saved exclusively to the local filesystem (`reports/`).
- **Direct Requests**: Reconnaissance and validation requests are sent directly to target services without intermediate logging or telemetry.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Continuous Integration & Security Audits

Code contributions and releases are validated via GitHub Actions (`.github/workflows/security-audit.yml`):

- **SAST Auditing**: Static application security testing via **Bandit** (`bandit -r metascan`).
- **PEP-8 Linting**: Code style and syntax checking via **Flake8** (`flake8 metascan tests`).
- **Regression Testing**: Automated test suite execution via **pytest** and **pytest-asyncio** across Python 3.11, 3.12, and 3.13.
- **Supply Chain Integrity**: External dependencies pinned to audited Git commit hashes with SHA-256 integrity verification.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security Policy

Security issues should be reported responsibly and privately. Please refer to [SECURITY.md](SECURITY.md) for reporting procedures and contact details (`[m.konyaev@proton.me]`). Do not disclose vulnerabilities in public GitHub Issues.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Disclaimer

This software is developed strictly for educational purposes, academic research, and authorized security assessments conducted within explicit contractual or organizational boundaries. 

The authors and contributors accept no responsibility or liability for any misuse, unauthorized access, degradation of service, or legal infringements resulting from the operation of this software. End users are solely responsible for ensuring that all reconnaissance activities strictly adhere to applicable local, national, and international laws, as well as the terms of service governing any third-party platforms queried.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
