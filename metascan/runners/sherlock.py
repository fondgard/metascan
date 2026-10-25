"""SherlockRunner — adapter for Sherlock OSINT scanner."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

from metascan.core.registry import ResultRegistry
from metascan.runners.base import BaseRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_STDOUT_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://[^\s\)]+)")


class SherlockRunner(BaseRunner):
    """Adapter for executing Sherlock and parsing real-time stdout and JSON."""

    name = "Sherlock"

    def _python_module(self) -> str | None:
        for mod in ("sherlock_project", "sherlock"):
            if importlib.util.find_spec(mod) is not None:
                return mod
        return "sherlock_project"

    def _resolve_cmd(self, username: str, tmp_dir: str = "", json_path: str = "") -> list[str]:
        """Resolve executable command: PATH binary or python -m sherlock_project.

        Args:
            username: Target username.
            tmp_dir: Optional folder path where results will be saved.
            json_path: Optional JSON destination path.

        Returns:
            List of CLI command tokens.
        """
        folder = tmp_dir or ""
        if not folder and json_path:
            p = Path(json_path)
            folder = str(p.parent if p.suffix else p)
        elif folder and Path(folder).suffix == ".json":
            folder = str(Path(folder).parent)

        sherlock_bin = shutil.which("sherlock")
        if sherlock_bin:
            cmd = [
                sherlock_bin,
                username,
                "--print-found",
                "--timeout", "10",
                "--no-color",
            ]
        else:
            mod = self._python_module() or "sherlock_project"
            cmd = [
                sys.executable, "-m", mod,
                username,
                "--print-found",
                "--timeout", "10",
                "--no-color",
            ]

        if folder:
            cmd.extend(["--folderoutput", folder])
        return cmd

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
            await registry.add_result(service, url, "Sherlock")

    @staticmethod
    def _parse_json(json_path: Path, username: str) -> list[tuple[str, str]]:
        """Parse Sherlock JSON output file.

        Args:
            json_path: Path to the generated JSON file.
            username: Target username.

        Returns:
            List of (service_name, url) tuples.
        """
        if not json_path.exists():
            return []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        hits: list[tuple[str, str]] = []
        for service, info in data.items():
            if not isinstance(info, dict):
                continue
            status = info.get("status", "")
            url = info.get("url_user") or info.get("url", "")
            if isinstance(status, dict):
                status = status.get("status", "")
            if str(status).lower() in ("claimed", "found") and url:
                hits.append((service, url))
        return hits

    async def run(
        self,
        username: str,
        registry: ResultRegistry,
        timeout: int = 120,
    ) -> int:
        """Run Sherlock subprocess and aggregate found profiles.

        Args:
            username: Target username.
            registry: Central registry.
            timeout: Subprocess timeout in seconds.

        Returns:
            Number of profiles discovered by Sherlock.
        """
        if not self.is_available():
            return 0

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / f"{username}.json"
            cmd = self._resolve_cmd(username, tmp_dir=tmp_dir, json_path=str(json_path))

            await self._run_subprocess(
                cmd, registry, username, timeout, self._line_cb
            )

            json_candidates = [
                json_path,
                Path(tmp_dir) / "sherlock.json",
                *Path(tmp_dir).glob("*.json"),
            ]
            for candidate in json_candidates:
                if candidate.exists():
                    for service, url in self._parse_json(candidate, username):
                        await registry.add_result(service, url, self.name)
                    break

        return len([
            e for e in registry.all_entries() if self.name in e.tools
        ])
