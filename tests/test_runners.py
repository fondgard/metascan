"""Unit tests for OSINT runners and Orchestrator.

All tests are isolated — no real subprocess calls are made:
parsers are invoked directly, and external runners are mocked.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from metascan.core.orchestrator import Orchestrator
from metascan.core.registry import ResultRegistry
from metascan.runners.blackbird import BlackbirdRunner, url_to_service_name
from metascan.runners.maigret import MaigretRunner
from metascan.runners.sherlock import SherlockRunner


# ===========================================================================
# Helper fixtures
# ===========================================================================

def _registry(target: str = "testuser") -> ResultRegistry:
    return ResultRegistry(target=target, scanners=["Sherlock", "Maigret", "Blackbird"])


# ===========================================================================
# SherlockRunner — stdout parsing
# ===========================================================================

class TestSherlockStdoutParser:

    @pytest.mark.asyncio
    async def test_valid_found_line(self) -> None:
        reg = _registry()
        line = "[+] Github: https://github.com/testuser"
        await SherlockRunner._line_cb(line, reg, "testuser")

        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Github"
        assert entries[0].url == "https://github.com/testuser"
        assert "Sherlock" in entries[0].tools

    @pytest.mark.asyncio
    async def test_multiple_lines(self) -> None:
        reg = _registry()
        lines = [
            "[+] Github: https://github.com/testuser",
            "[+] Reddit: https://reddit.com/user/testuser",
            "[+] Twitter: https://twitter.com/testuser",
        ]
        for line in lines:
            await SherlockRunner._line_cb(line, reg, "testuser")

        assert len(reg.all_entries()) == 3

    @pytest.mark.asyncio
    async def test_non_matching_line_ignored(self) -> None:
        reg = _registry()
        await SherlockRunner._line_cb("[*] Searching ...", reg, "testuser")
        await SherlockRunner._line_cb("", reg, "testuser")
        await SherlockRunner._line_cb("[-] Steam: Not found", reg, "testuser")

        assert len(reg.all_entries()) == 0

    @pytest.mark.asyncio
    async def test_duplicate_url_deduplicated(self) -> None:
        """The same URL from stdout should not create a second entry."""
        reg = _registry()
        line = "[+] Github: https://github.com/testuser"
        await SherlockRunner._line_cb(line, reg, "testuser")
        await SherlockRunner._line_cb(line, reg, "testuser")

        assert len(reg.all_entries()) == 1

    @pytest.mark.asyncio
    async def test_sherlock_carriage_return_handled(self) -> None:
        reg = _registry()
        line = "\r[+] Twitter: https://twitter.com/testuser"
        await SherlockRunner._line_cb(line, reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Twitter"

    @pytest.mark.asyncio
    async def test_sherlock_ansi_escapes_handled(self) -> None:
        reg = _registry()
        line = "\x1b[1;32;40m[+] \x1b[0m\x1b[1;37;40mGithub\x1b[0m: \x1b[1;32;40mhttps://github.com/testuser\x1b[0m"
        await SherlockRunner._line_cb(line, reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Github"
        assert entries[0].url == "https://github.com/testuser"


# ===========================================================================
# SherlockRunner — JSON parsing
# ===========================================================================

class TestSherlockJsonParser:

    def test_parse_claimed_status(self, tmp_path: Path) -> None:
        data = {
            "Github": {"status": "Claimed", "url_user": "https://github.com/testuser"},
            "Reddit": {"status": "Claimed", "url_user": "https://reddit.com/user/testuser"},
            "Steam":  {"status": "Available", "url_user": "https://steamcommunity.com/id/testuser"},
        }
        p = tmp_path / "sherlock.json"
        p.write_text(json.dumps(data), encoding="utf-8")

        hits = SherlockRunner._parse_json(p, "testuser")
        services = {h[0] for h in hits}

        assert "Github" in services
        assert "Reddit" in services
        assert "Steam" not in services   # Available — not found

    def test_parse_dict_status(self, tmp_path: Path) -> None:
        """status may be a dictionary {"status": "Claimed"}."""
        data = {
            "Keybase": {
                "status": {"status": "Claimed"},
                "url": "https://keybase.io/testuser",
            },
        }
        p = tmp_path / "sherlock.json"
        p.write_text(json.dumps(data), encoding="utf-8")

        hits = SherlockRunner._parse_json(p, "testuser")
        assert len(hits) == 1
        assert hits[0][0] == "Keybase"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        hits = SherlockRunner._parse_json(tmp_path / "nonexistent.json", "x")
        assert hits == []

    def test_malformed_json_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{ not valid json }", encoding="utf-8")
        hits = SherlockRunner._parse_json(p, "x")
        assert hits == []


# ===========================================================================
# MaigretRunner — JSON parsing (formats A, B, C)
# ===========================================================================

class TestMaigretJsonParser:

    def _write(self, tmp_path: Path, data) -> Path:
        p = tmp_path / "report.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_format_a_wrapped_sites(self, tmp_path: Path) -> None:
        """Format A: {"username": ..., "sites": {ServiceName: {...}}}"""
        data = {
            "username": "testuser",
            "sites": {
                "Github": {"status": "found", "url_user": "https://github.com/testuser"},
                "Reddit": {"status": "found", "url_user": "https://reddit.com/user/testuser"},
                "Steam":  {"status": "not found", "url_user": "https://steamcommunity.com/id/testuser"},
            }
        }
        hits = MaigretRunner._parse_json(self._write(tmp_path, data))
        services = {h[0] for h in hits}

        assert "Github" in services
        assert "Reddit" in services
        assert "Steam" not in services

    def test_format_b_direct_dict(self, tmp_path: Path) -> None:
        """Format B: direct dict {ServiceName: {status: {id: "found"}}}"""
        data = {
            "Twitter": {
                "status": {"id": "found"},
                "url": "https://twitter.com/testuser",
            }
        }
        hits = MaigretRunner._parse_json(self._write(tmp_path, data))
        assert len(hits) == 1
        assert hits[0][0] == "Twitter"

    def test_format_c_list(self, tmp_path: Path) -> None:
        """Format C: list of entries."""
        data = [
            {"sitename": "Keybase", "url_user": "https://keybase.io/testuser", "status": "found"},
            {"sitename": "Missing", "url_user": "https://example.com/testuser", "status": "not found"},
        ]
        hits = MaigretRunner._parse_json(self._write(tmp_path, data))
        assert len(hits) == 1
        assert hits[0][0] == "Keybase"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        hits = MaigretRunner._parse_json(tmp_path / "nope.json")
        assert hits == []

    @pytest.mark.asyncio
    async def test_stdout_line_cb(self) -> None:
        reg = _registry()
        await MaigretRunner._line_cb("[+] Dev.to: https://dev.to/testuser", reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Dev.to"
        assert "Maigret" in entries[0].tools

    @pytest.mark.asyncio
    async def test_stdout_line_cb_with_carriage_return(self) -> None:
        reg = _registry()
        line = "\r[+] Twitter: https://twitter.com/testuser"
        await MaigretRunner._line_cb(line, reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Twitter"
        assert "Maigret" in entries[0].tools

    @pytest.mark.asyncio
    async def test_maigret_stdout_with_trailing_status(self) -> None:
        reg = _registry()
        line = "[+] Github: https://github.com/testuser (found in 0.42s)"
        await MaigretRunner._line_cb(line, reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Github"
        assert entries[0].url == "https://github.com/testuser"
        assert "Maigret" in entries[0].tools

    @pytest.mark.asyncio
    async def test_maigret_ansi_escapes_handled(self) -> None:
        reg = _registry()
        line = "\x1b[32m[+] Reddit: https://reddit.com/user/testuser\x1b[0m"
        await MaigretRunner._line_cb(line, reg, "testuser")
        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "Reddit"
        assert entries[0].url == "https://reddit.com/user/testuser"


# ===========================================================================
# BlackbirdRunner — url_to_service_name
# ===========================================================================

class TestUrlToServiceName:

    @pytest.mark.parametrize("url, expected", [
        ("https://github.com/user",             "Github"),
        ("https://www.reddit.com/user/u",       "Reddit"),
        ("https://steamcommunity.com/id/u",     "Steam"),
        ("https://gitlab.com/u",                "GitLab"),
        ("https://medium.com/@u",               "Medium"),
        ("https://dev.to/u",                    "Dev.to"),
        ("https://keybase.io/u",                "Keybase"),
        ("https://twitch.tv/u",                 "Twitch"),
        ("https://twitter.com/u",               "Twitter"),
        ("https://x.com/u",                     "Twitter"),       # x.com -> Twitter
        ("https://t.me/u",                      "Telegram"),
        ("https://news.ycombinator.com/u",      "HackerNews"),
        ("https://unknown-platform.io/u",       "Unknown-platform"),
    ])
    def test_known_domain(self, url: str, expected: str) -> None:
        assert url_to_service_name(url) == expected


# ===========================================================================
# BlackbirdRunner — JSON parsing
# ===========================================================================

class TestBlackbirdJsonParser:

    def _write(self, tmp_path: Path, data) -> Path:
        p = tmp_path / "result.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_accounts_format(self, tmp_path: Path) -> None:
        """{"username": ..., "accounts": [...]}"""
        data = {
            "username": "testuser",
            "accounts": [
                {"name": "Github", "url": "https://github.com/testuser", "status": "found"},
                {"name": "Steam",  "url": "https://steamcommunity.com/id/testuser", "status": "not found"},
            ]
        }
        hits = BlackbirdRunner._parse_json(self._write(tmp_path, data))
        assert len(hits) == 1
        assert hits[0][0] == "Github"

    def test_results_format(self, tmp_path: Path) -> None:
        """{"results": [...]}"""
        data = {
            "results": [
                {"name": "Reddit", "url": "https://reddit.com/user/testuser", "status": "found"},
                {"name": "Twitter", "url": "https://twitter.com/testuser", "status": "found"},
            ]
        }
        hits = BlackbirdRunner._parse_json(self._write(tmp_path, data))
        assert len(hits) == 2

    def test_list_format(self, tmp_path: Path) -> None:
        """Root list."""
        data = [
            {"name": "Twitch", "url": "https://twitch.tv/testuser", "status": "found"},
        ]
        hits = BlackbirdRunner._parse_json(self._write(tmp_path, data))
        assert len(hits) == 1
        assert hits[0][0] == "Twitch"

    def test_service_name_from_url_when_name_missing(self, tmp_path: Path) -> None:
        """If name is not set, extract from URL."""
        data = {"results": [
            {"url": "https://habr.com/users/testuser", "status": "found"},
        ]}
        hits = BlackbirdRunner._parse_json(self._write(tmp_path, data))
        assert hits[0][0] == "Habr"

    @pytest.mark.asyncio
    async def test_stdout_line_cb_with_bracket(self) -> None:
        reg = _registry()
        await BlackbirdRunner._line_cb(
            "[+] Twitch: https://twitch.tv/testuser", reg, "testuser"
        )
        entries = reg.all_entries()
        assert entries[0].service == "Twitch"
        assert "Blackbird" in entries[0].tools

    @pytest.mark.asyncio
    async def test_stdout_line_cb_no_bracket(self) -> None:
        reg = _registry()
        await BlackbirdRunner._line_cb(
            "Github: https://github.com/testuser", reg, "testuser"
        )
        entries = reg.all_entries()
        assert entries[0].service == "Github"


# ===========================================================================
# Graceful Degradation Tests
# ===========================================================================

class TestGracefulDegradation:

    @pytest.mark.asyncio
    async def test_sherlock_unavailable_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = SherlockRunner()
        monkeypatch.setattr(runner, "is_available", lambda: False)
        reg = _registry()
        count = await runner.run("testuser", reg)
        assert count == 0

    @pytest.mark.asyncio
    async def test_maigret_unavailable_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = MaigretRunner()
        monkeypatch.setattr(runner, "is_available", lambda: False)
        reg = _registry()
        count = await runner.run("testuser", reg)
        assert count == 0

    @pytest.mark.asyncio
    async def test_orchestrator_skips_unavailable_runner_gracefully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If a tool is unavailable or crashes, orchestrator does not crash."""
        orch = Orchestrator()
        reg = _registry()

        # Mock native probes to avoid real network requests
        async def _noop_probes(u, r):
            pass

        monkeypatch.setattr(orch, "_run_native_probes", _noop_probes)

        # Runner 1 is unavailable, Runner 2 is available but raises an error, Runner 3 works normally
        class MockFailingRunner(SherlockRunner):
            name = "FailingRunner"
            def is_available(self) -> bool:
                return True
            async def run(self, username, registry, timeout=120) -> int:
                raise RuntimeError("External tool crashed!")

        class MockWorkingRunner(MaigretRunner):
            name = "WorkingRunner"
            def is_available(self) -> bool:
                return True
            async def run(self, username, registry, timeout=120) -> int:
                await registry.add_result("WorkingService", f"https://example.com/{username}", self.name)
                return 1

        class MockMissingRunner(BlackbirdRunner):
            name = "MissingRunner"
            def is_available(self) -> bool:
                return False

        orch._runners = [MockMissingRunner(), MockFailingRunner(), MockWorkingRunner()]

        # Run should not raise exceptions (Graceful degradation)
        await orch.run("testuser", reg)

        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].service == "WorkingService"
