<a id="readme-top"></a>

<div align="center">
  <img src="https://i.imgur.com/zOcvR1j.jpeg" alt="MetaScan Banner" width="100%">
  <br />
  <br />
  <h1>MetaScan</h1>
  <p>
    <strong>High-Performance Asynchronous OSINT Identity Aggregation and Verification Engine</strong>
  </p>
  <p>
    <a href="https://github.com/fondgard/metascan/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#core-capabilities">Core Capabilities</a></li>
        <li><a href="#validation-and-false-positive-reduction">Validation and False-Positive Reduction</a></li>
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
    <li><a href="#disclaimer">Disclaimer</a></li>
  </ol>
</details>

## About The Project

MetaScan is an asynchronous Open Source Intelligence (OSINT) framework engineered to resolve digital identities across disparate online services while mitigating the high false-positive rates inherent to username enumeration tools.

Traditional reconnaissance scanners typically operate as isolated utilities with divergent pattern heuristics, non-standardized output structures, and minimal post-discovery validation. This frequently results in analytical overhead due to deceptive HTTP status codes (such as soft-404 pages returning HTTP 200 OK), unhandled redirect chains to login portals, and bot-mitigation defenses.

MetaScan addresses these challenges through a unified orchestration layer that aggregates the reconnaissance engines of **Sherlock**, **Maigret**, and **Blackbird**. Discovered candidate profiles are consolidated into a centralized registry, normalized, and subjected to a multi-tiered asynchronous HTTP/2 validation pipeline before report compilation.

### Core Capabilities

- **Multi-Engine Concurrent Orchestration**: Executes Sherlock, Maigret, and Blackbird as asynchronous subprocesses within a non-blocking event loop, consolidating coverage across thousands of platform signatures.
- **URI Normalization and Deduplication**: Ingests disparate URL structures, standardizes protocol schemes and subdomain variations, and merges discovery provenance to prevent redundant network traffic.
- **Asynchronous High-Throughput Validation**: Validates discovered endpoints concurrently using `httpx` with HTTP/2 support, controlled by configurable concurrency semaphores to prevent localized network saturation.
- **Interactive Offline Reporting**: Generates standalone, zero-dependency HTML dashboards with client-side search filtering, validated vs. filtered categorizations, and embedded raw JSON data representations for integration into threat intelligence pipelines.

### Validation and False-Positive Reduction

MetaScan implements a multi-tier validation architecture designed to systematically eliminate invalid profiles:

1. **HTTP Status Code Verification**: Enforces rigorous status checking. Endpoints returning standard negative codes (`404 Not Found`, `410 Gone`, `451 Unavailable`) or server faults (`5xx`) are filtered immediately.
2. **Redirect Destination Traps**: Follows redirect chains and inspects terminal paths. Responses redirected to generic domain roots (`/`, `/home`, `/index.html`), authentication barriers (`/login`, `/signin`, `/authwall`), or generic error locations (`/404`, `/error`, `/lander`) are marked as invalid.
3. **Soft-404 and Stop-Word Heuristics**: Analyzes the parsed DOM (`<title>` elements and normalized body content) against a multilingual corpus of profile-absence signatures (e.g., *"User not found"*, *"Page doesn't exist"*, *"Account suspended"*, *"Profile unavailable"*).
4. **Platform-Specific DOM Probes**: Employs specialized inspection logic for platforms with complex client-side rendering or non-standard status returns, including Twitter/X, Instagram, TikTok, Reddit, Telegram, YouTube, Twitch, Pinterest, and Spotify.

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
   MetaScan relies on external utilities (including Blackbird, which is managed outside standard PyPI packages). Execute the dedicated automated provisioning script for your operating system:
   - **Linux / macOS**:
     ```bash
     chmod +x install_dependencies.sh
     ./install_dependencies.sh
     ```
   - **Windows (PowerShell)**:
     ```powershell
     .\install_dependencies.ps1
     ```

   *The script provisions required scanner repositories into a dedicated user directory (`~/.local/share/metascan` or `%LOCALAPPDATA%\metascan`), installs their respective runtime requirements, and establishes necessary execution wrappers without modifying the working directory tree.*

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

### Basic Execution

Initiate an automated scan against a target username across all configured engines. By default, MetaScan compiles results into `reports/metascan_<username>.html` and launches the artifact in the default web browser upon completion:

```bash
mns target_username
```

### Advanced Workflows

Specify custom output destinations, tune network concurrency, set runner subprocess timeouts, or disable automated browser launching:

```bash
mns target_username -o reports/audit_target.html -c 40 -t 90 --no-open
```

### Command-Line Reference

| Argument / Option | Short | Default Value | Description |
|---|---|---|---|
| `USERNAME` | — | *(Required)* | Target username to investigate across platforms. |
| `--output` | `-o` | `reports/metascan_<user>.html` | Output file path for the generated standalone HTML report. |
| `--concurrency` | `-c` | `20` | Maximum number of concurrent asynchronous HTTP validation requests. |
| `--timeout` | `-t` | `120` | Maximum execution timeout (in seconds) allocated to each external scanner. |
| `--no-open` | — | `False` | Prevents automated opening of the generated report in the system browser. |
| `--version` | `-v` | — | Displays the installed MetaScan version and exits. |
| `--help` | — | — | Displays command-line help instructions and available options. |

### Reporting and Artifacts

Upon completion of the analysis and validation lifecycle, MetaScan produces an autonomous HTML report containing:

- **Identity Overview**: Quantitative summary of verified profiles, discarded false positives, and scanner execution metrics.
- **Interactive Verification Grid**: Client-side filtering mechanism to inspect confirmed endpoints, corresponding services, and detection engines.
- **Filtered Artifacts Log**: Complete diagnostic transparency documenting rejected URLs alongside explicit reasons (e.g., `404 Not Found`, `Soft-404 (User Not Found)`, `Redirect to Login/404`, `Timeout`).
- **Raw JSON Data Block**: Formatted, machine-readable dataset embedded directly within the document for automated extraction into SIEM or external analysis tooling:

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

## Disclaimer

This software is developed strictly for educational purposes, academic research, and authorized security assessments conducted within explicit contractual or organizational boundaries. 

The authors and contributors accept no responsibility or liability for any misuse, unauthorized access, degradation of service, or legal infringements resulting from the operation of this software. End users are solely responsible for ensuring that all reconnaissance activities strictly adhere to applicable local, national, and international laws, as well as the terms of service governing any third-party platforms queried.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
