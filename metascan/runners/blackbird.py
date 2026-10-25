"""BlackbirdRunner — adapter for Blackbird OSINT scanner."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from metascan.core.registry import ResultRegistry
from metascan.runners.base import BaseRunner

_DOMAIN_TO_SERVICE: dict[str, str] = {
    "github.com": "Github",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "reddit.com": "Reddit",
    "twitter.com": "Twitter",
    "x.com": "Twitter",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "linkedin.com": "LinkedIn",
    "steamcommunity.com": "Steam",
    "vk.com": "VKontakte",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "pinterest.com": "Pinterest",
    "tumblr.com": "Tumblr",
    "pastebin.com": "Pastebin",
    "medium.com": "Medium",
    "dev.to": "Dev.to",
    "habr.com": "Habr",
    "keybase.io": "Keybase",
    "twitch.tv": "Twitch",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "mastodon.social": "Mastodon",
    "news.ycombinator.com": "HackerNews",
    "hackerone.com": "HackerOne",
    "producthunt.com": "ProductHunt",
    "dribbble.com": "Dribbble",
    "behance.net": "Behance",
    "soundcloud.com": "SoundCloud",
    "gravatar.com": "Gravatar",
    "about.me": "About.me",
    "freelancer.com": "Freelancer",
    "upwork.com": "Upwork",
    "stackoverflow.com": "StackOverflow",
    "stackexchange.com": "StackExchange",
    "npmjs.com": "npm",
    "pypi.org": "PyPI",
    "hub.docker.com": "DockerHub",
    "replit.com": "Replit",
    "codepen.io": "CodePen",
    "leetcode.com": "LeetCode",
    "hackerrank.com": "HackerRank",
    "codeforces.com": "Codeforces",
    "last.fm": "Last.fm",
    "discordapp.com": "Discord",
    "discord.com": "Discord",
    "slack.com": "Slack",
    "chess.com": "Chess.com",
    "lichess.org": "Lichess",
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_STDOUT_RE = re.compile(r"(?:^\[\+\]\s+)?(.+?):\s+(https?://[^\s\)]+)")


def url_to_service_name(url: str) -> str:
    """Resolve human-readable service name from profile URL hostname.

    Args:
        url: Full profile URL.

    Returns:
        Service display name (e.g. "Github", "Twitter", or capitalized domain).
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]

    if host in _DOMAIN_TO_SERVICE:
        return _DOMAIN_TO_SERVICE[host]

    for domain, service in _DOMAIN_TO_SERVICE.items():
        if host == domain or host.endswith("." + domain):
            return service

    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2].capitalize()
    return host.capitalize() or "Unknown"


def _find_blackbird_cmd() -> list[str] | None:
    """Locate Blackbird binary, python script, or installed module.

    Returns:
        Executable command list or None if not installed.
    """
    env_path = os.environ.get("BLACKBIRD_PATH")
    if env_path and Path(env_path).exists():
        p = Path(env_path)
        return [sys.executable, str(p)] if p.suffix == ".py" else [str(p)]

    if shutil.which("blackbird"):
        return ["blackbird"]

    default_script = Path.home() / ".local" / "share" / "metascan" / "blackbird" / "blackbird.py"
    if default_script.exists():
        return [sys.executable, str(default_script)]

    if importlib.util.find_spec("blackbird") is not None:
        return [sys.executable, "-m", "blackbird"]

    return None


class BlackbirdRunner(BaseRunner):
    """Adapter for executing Blackbird and parsing real-time stdout and JSON."""

    name = "Blackbird"

    def is_available(self) -> bool:
        """Check whether Blackbird executable or script is reachable."""
        return _find_blackbird_cmd() is not None

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
            raw_service = m.group(1).strip()
            url = m.group(2).strip()
            service = (
                url_to_service_name(raw_service)
                if raw_service.startswith("http")
                else raw_service
            )
            await registry.add_result(service, url, "Blackbird")

    @staticmethod
    def _parse_json(json_path: Path) -> list[tuple[str, str, dict[str, Any]]]:
        """Parse Blackbird dump JSON report.

        Args:
            json_path: Path to the generated JSON file.

        Returns:
            List of (service_name, url, metadata) tuples.
        """
        if not json_path.exists():
            return []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        records: list[dict[str, Any]] = []
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = (
                data.get("accounts")
                or data.get("results")
                or []
            )

        hits: list[tuple[str, str, dict[str, Any]]] = []
        for item in records:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "")).lower()
            url = item.get("url", "")
            if status == "found" and url:
                service = item.get("name") or item.get("site") or url_to_service_name(url)
                meta: dict[str, Any] = {}
                for meta_key in ("metadata", "extra", "data", "ids"):
                    candidate = item.get(meta_key)
                    if isinstance(candidate, dict):
                        meta.update({k: v for k, v in candidate.items() if v not in (None, "", [], {})})
                        break

                known_meta_fields = (
                    "fullname", "name", "image", "avatar", "bio",
                    "created_at", "follower_count", "following_count",
                    "uid", "username", "is_verified", "location",
                )
                for field in known_meta_fields:
                    if field in item and field not in meta and item[field] not in (None, "", [], {}):
                        meta[field] = item[field]
                hits.append((service, url, meta))
        return hits

    async def run(
        self,
        username: str,
        registry: ResultRegistry,
        timeout: int = 120,
    ) -> int:
        """Run Blackbird subprocess and aggregate found profiles.

        Args:
            username: Target username.
            registry: Central registry.
            timeout: Subprocess timeout in seconds.

        Returns:
            Number of profiles discovered by Blackbird.
        """
        base_cmd = _find_blackbird_cmd()
        if base_cmd is None:
            return 0

        with tempfile.TemporaryDirectory() as tmp_dir:
            cmd = [
                *base_cmd,
                "-u", username,
                "--dump",
                "--no-color",
            ]

            await self._run_subprocess(
                cmd, registry, username, timeout, self._line_cb, cwd=tmp_dir
            )

            for json_file in Path(tmp_dir).glob("**/*.json"):
                for service, url, meta in self._parse_json(json_file):
                    await registry.add_result(service, url, self.name, metadata=meta)
                break

        return len([e for e in registry.all_entries() if self.name in e.tools])
