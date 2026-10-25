# MetaScan — Architecture Document

## Overview

**MetaScan** (`mns`) is an async CLI OSINT tool that aggregates username search results
from multiple external scanners, deduplicates and validates every found URL, and
exports a polished HTML report.

---

## Tech Stack

| Layer | Technology |
|---|---|
| CLI framework | [Typer](https://typer.tiangolo.com/) ≥ 0.12 |
| Terminal UI | [Rich](https://rich.readthedocs.io/) ≥ 13.7 |
| HTTP client | [HTTPX](https://www.python-httpx.org/) ≥ 0.27 (HTTP/2) |
| HTML parsing | [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) ≥ 4.12 |
| Data models | [Pydantic v2](https://docs.pydantic.dev/) ≥ 2.7 |
| HTML templates | [Jinja2](https://jinja.palletsprojects.com/) ≥ 3.1.4 |
| Python runtime | Python 3.11+ |
| Build backend | setuptools |

---

## Directory Layout

```
metascan/
├── __init__.py
├── cli.py              # Typer app; entry point `mns`
├── models.py           # Pydantic models (ScanResult, FilteredResult, ReportData)
├── core/
│   ├── __init__.py
│   ├── registry.py     # ResultRegistry — dedup store keyed by normalized URL
│   ├── validator.py    # AsyncValidator — HTTP validation, soft-404 detection
│   └── orchestrator.py # Top-level async coordinator
├── runners/
│   ├── __init__.py
│   ├── base.py         # BaseRunner ABC
│   ├── sherlock.py     # Sherlock subprocess runner
│   ├── maigret.py      # Maigret subprocess runner
│   └── blackbird.py    # Blackbird subprocess runner
├── exporters/
│   ├── __init__.py
│   └── html_exporter.py # Renders Jinja2 template → report HTML
└── templates/
    └── report.html.j2   # Jinja2 template (mirrors example.html design)

tests/
└── __init__.py
```

---

## Data Flow

```
mns <username>
        │
        ▼
  Orchestrator
  ┌──────────────────────────────────────────────┐
  │  asyncio.gather(Sherlock, Maigret, Blackbird) │
  │          (subprocess + stdout parsing)         │
  └──────────────┬───────────────────────────────┘
                 │  raw hits (service, url, tool)
                 ▼
          ResultRegistry
          (dedup by normalized URL; merges `tools` list)
                 │
                 ▼
          AsyncValidator
          (HTTP GET via httpx; checks status, redirects,
           title/body stop-phrases → classifies Found / Error)
                 │
         ┌───────┴────────┐
         ▼                ▼
    VALID results    FILTERED results  (with `reason`)
         └───────┬────────┘
                 ▼
          HTMLExporter
          (Jinja2 → report_<username>.html)
```

---

## JSON Data Model (from `example.html`)

This is the canonical shape embedded in every report's **RAW JSON DATA** block:

```json
{
  "target": "nickname",
  "scanners": ["Sherlock", "Maigret", "Blackbird"],
  "results": {
    "<ServiceName>": {
      "url": "https://example.com/nickname",
      "status": "Found",
      "tools": ["Maigret"]
    },
    "<ServiceName>": {
      "url": "https://example.com/nickname",
      "status": "Error",
      "error_type": "404 Not Found",
      "tools": ["Sherlock"]
    }
  }
}
```

### Field Semantics

| Field | Type | Description |
|---|---|---|
| `target` | `str` | The queried username |
| `scanners` | `list[str]` | All scanners that were invoked |
| `results` | `dict[str, ServiceEntry]` | Keyed by **service name** (e.g. `"Github"`) |
| `results[*].url` | `str` | Canonical, normalized URL |
| `results[*].status` | `"Found" \| "Error"` | Validation outcome |
| `results[*].tools` | `list[str]` | Scanners that reported this profile |
| `results[*].error_type` | `str` | Present when `status == "Error"` — human-readable reason |

### Known `error_type` values

- `"404 Not Found"` — HTTP 404 response
- `"Soft-404: Page Not Found"` — 200 response but stop-phrase matched in `<title>` or body
- `"Redirect to Home"` — final URL differs significantly from expected profile URL
- `"Connection Error"` — network / timeout failure

---

## HTML Report Design (from `example.html`)

| Section | Behaviour |
|---|---|
| **Header** | `MetaScan` title + tagline in JetBrains Mono |
| **Search bar** | Client-side JS filter across all `.result-row` elements |
| **VALID RESULTS** | Expandable card; columns: SERVICE / TOOL / LINK (click-to-copy) |
| **FILTERED RESULTS** | Collapsible `<details>`; extra REASON column |
| **RAW JSON DATA** | Collapsible `<details>` with pretty-printed JSON |
| **Footer** | `METASCAN \| MADE BY FONDGARD 2026` |

Colour palette: `bg #000000`, accent `#2EA043`, error `#d73a49`, text `#ffffff`.
Font: **JetBrains Mono** (Google Fonts CDN).
