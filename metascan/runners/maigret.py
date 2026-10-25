"""MaigretRunner — adapter for Maigret OSINT scanner."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from metascan.core.registry import ResultRegistry
from metascan.runners.base import BaseRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_STDOUT_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://[^\s\)]+)")


def _extract_metadata(site_dict: dict[str, Any]) -> dict[str, Any]:
    """Extract metadata dictionary from a Maigret JSON report entry.

    Supports both current nested simple report format (status -> ids)
    and legacy formats where ids_data is stored flat.

    Args:
        site_dict: Dictionary representing a single site entry.

    Returns:
        Cleaned metadata dictionary with empty values excluded.
    """
    meta: dict[str, Any] = {}

    status_block = site_dict.get("status")
    if isinstance(status_block, dict):
        ids = status_block.get("ids") or {}
        meta.update({k: v for k, v in ids.items() if v not in (None, "", [], {})})
    elif hasattr(status_block, "ids_data"):
        ids = status_block.ids_data or {}
        meta.update({k: v for k, v in ids.items() if v not in (None, "", [], {})})

    direct_ids = site_dict.get("ids_data") or {}
    for k, v in direct_ids.items():
        if k not in meta and v not in (None, "", [], {}):
            meta[k] = v

    return meta


class MaigretRunner(BaseRunner):
    """Adapter for executing Maigret and parsing real-time stdout and JSON."""

    name = "Maigret"

    def _python_module(self) -> str:
        return "maigret"

    @staticmethod
    async def _line_cb(line: str, registry: ResultRegistry, username: str) -> None:
        """Parse single stdout line in real-time.

        Args:
            line: Raw line from runner stdout.
            registry: Target ResultRegistry instance.
            username: Target username.
        """
        clean_line = _ANSI_RE.sub("", line).strip()
        m = _STDOUT_RE.match(clean_line)
        if m:
            service, url = m.group(1).strip(), m.group(2).strip()
            await registry.add_result(service, url, "Maigret")

    @staticmethod
    def _parse_json(report_path: Path) -> list[tuple[str, str, dict[str, Any]]]:
        """Parse Maigret JSON report file supporting wrapped, direct, and list formats.

        Args:
            report_path: Path to the generated JSON report.

        Returns:
            List of (service_name, url, metadata) tuples.
        """
        if not report_path.exists():
            return []
        try:
            raw = report_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return []

        hits: list[tuple[str, str, dict[str, Any]]] = []

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                url = item.get("url_user") or item.get("url", "")
                service = item.get("sitename") or item.get("site", "")
                status = str(item.get("status", "")).lower()
                if status == "found" and url and service:
                    meta = _extract_metadata(item)
                    hits.append((service, url, meta))
            return hits

        if not isinstance(data, dict):
            return []

        sites: dict[str, Any] = data.get("sites", data)

        for service, info in sites.items():
            if not isinstance(info, dict):
                continue
            url = info.get("url_user") or info.get("url", "")
            status = info.get("status", "")
            if isinstance(status, dict):
                status_id = status.get("id") or status.get("status", "")
            elif hasattr(status, "status"):
                status_id = str(status.status)
            else:
                status_id = str(status)
            if status_id.lower() in ("found", "claimed") and url:
                meta = _extract_metadata(info)
                hits.append((service, url, meta))

        return hits

    async def run(
        self,
        username: str,
        registry: ResultRegistry,
        timeout: int = 120,
    ) -> int:
        """Run Maigret subprocess and aggregate found profiles.

        Args:
            username: Target username.
            registry: Central registry.
            timeout: Subprocess timeout in seconds.

        Returns:
            Number of profiles discovered by Maigret.
        """
        if not self.is_available():
            return 0

        maigret_bin = shutil.which("maigret")
        if maigret_bin:
            base_cmd = [maigret_bin]
        else:
            base_cmd = [sys.executable, "-m", "maigret"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            cmd = [
                *base_cmd,
                username,
                "--folderoutput", tmp_dir,
                "-J", "simple",
                "--top-sites", "250",
                "--timeout", "10",
                "--no-color",
                "--no-progressbar",
            ]

            await self._run_subprocess(
                cmd, registry, username, timeout, self._line_cb
            )

            report_candidates = [
                Path(tmp_dir) / f"report_{username}_simple.json",
                Path(tmp_dir) / f"{username}.json",
            ]
            report_candidates += list(Path(tmp_dir).glob("*.json"))

            for path in report_candidates:
                if path.exists():
                    for service, url, meta in self._parse_json(path):
                        await registry.add_result(service, url, self.name, metadata=meta)
                    break

        return len([e for e in registry.all_entries() if self.name in e.tools])
