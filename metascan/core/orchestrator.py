"""Orchestrator — coordinates runner execution and scan lifecycle."""

from __future__ import annotations

import asyncio
import json
from typing import Callable

import httpx
from bs4 import BeautifulSoup
from rich.console import Console

from metascan.core.registry import ResultRegistry
from metascan.runners.base import BaseRunner
from metascan.runners.blackbird import BlackbirdRunner
from metascan.runners.maigret import MaigretRunner
from metascan.runners.sherlock import SherlockRunner

console = Console(highlight=False)

class Orchestrator:
    """Coordinates concurrent execution of OSINT runners and fallback native probes.

    Args:
        runner_timeout: Max execution time for each runner in seconds.
    """

    def __init__(
        self,
        runner_timeout: int = 120,
        **kwargs,
    ) -> None:
        self.runner_timeout = runner_timeout
        self._runners: list[BaseRunner] = [
            SherlockRunner(),
            MaigretRunner(),
            BlackbirdRunner(),
        ]

    def available_runners(self) -> list[BaseRunner]:
        """Return runners whose underlying binaries or modules are installed."""
        return [r for r in self._runners if r.is_available()]

    def runner_status(self) -> dict[str, bool]:
        """Return dictionary mapping runner names to their availability status."""
        return {r.name: r.is_available() for r in self._runners}

    async def run(
        self,
        username: str,
        registry: ResultRegistry,
        on_runner_start: Callable[[str], None] | None = None,
        on_runner_done: Callable[[str, int], None] | None = None,
    ) -> None:
        """Run all available scanners and native probes concurrently.

        Args:
            username: Target username to investigate.
            registry: Central registry for aggregating findings.
            on_runner_start: Callback invoked when a runner begins execution.
            on_runner_done: Callback invoked when a runner finishes, receiving count.
        """
        for runner in self._runners:
            if not runner.is_available():
                console.print(
                    f"[yellow]⚠️  {runner.name} not found in system (PATH / venv), skipping...[/yellow]"
                )

        runners = self.available_runners()
        if not runners:
            console.print(
                "No external OSINT tools found in PATH.\n"
                "Running native fallback probes for major platforms..."
            )
            await self._run_native_probes(username, registry)
            return

        async def _wrapped_run(runner: BaseRunner) -> None:
            if on_runner_start:
                on_runner_start(runner.name)
            try:
                count = await runner.run(username, registry, timeout=self.runner_timeout)
            except Exception as exc:
                console.print(f"[red]⚠️  {runner.name} encountered an error: {exc}[/red]")
                count = 0
            if on_runner_done:
                on_runner_done(runner.name, count)

        native_task = asyncio.create_task(self._run_native_probes(username, registry))
        await asyncio.gather(native_task, *[_wrapped_run(r) for r in runners])

    async def _run_native_probes(self, username: str, registry: ResultRegistry) -> None:
        """Execute direct HTTP checks for high-value targets (Instagram, Twitter, etc.).

        Guarantees discovery on platforms where legacy runners often fail due to
        outdated scrapers, dead mirrors, or strict anti-bot systems.

        Args:
            username: Target username.
            registry: Central registry.
        """
        browser_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        crawler_headers = {
            "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            async def _check_instagram() -> None:
                try:
                    url = f"https://www.instagram.com/{username}/"
                    r = await client.get(url, headers=crawler_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        og_title = soup.find("meta", property="og:title")
                        content = (og_title.get("content", "") if og_title else "").lower()
                        u_lower = username.lower()
                        if f"(@{u_lower})" in content or f"@{u_lower}" in content or u_lower in content:
                            await registry.add_result("Instagram", url, "MetaScan")
                except Exception:
                    pass

            async def _check_twitter() -> None:
                try:
                    url = f"https://twitter.com/{username}"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        title = (soup.title.string or "").lower() if soup.title else ""
                        body_lower = r.text.lower()
                        if (
                            "account suspended" in title
                            or "account suspended" in body_lower
                            or "account has been suspended" in body_lower
                        ):
                            return
                        if ("page not found" not in title and "doesn’t exist" not in r.text) and (
                            "/ x" in title or f"@{username.lower()}" in title
                        ):
                            await registry.add_result("Twitter", url, "MetaScan")
                except Exception:
                    pass

            async def _check_telegram() -> None:
                try:
                    url = f"https://t.me/{username}"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        extra = soup.find(class_="tgme_page_extra")
                        title = soup.find(class_="tgme_page_title")
                        if extra or title:
                            await registry.add_result("Telegram", url, "MetaScan")
                except Exception:
                    pass

            async def _check_github() -> None:
                try:
                    url = f"https://github.com/{username}"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200 and "not found" not in r.text[:2000].lower():
                        await registry.add_result("Github", url, "MetaScan")
                except Exception:
                    pass

            async def _check_youtube() -> None:
                try:
                    url = f"https://www.youtube.com/@{username}"
                    r = await client.get(
                        url,
                        headers=browser_headers,
                        cookies={
                            "SOCS": "CAISNQgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjMwODI5LjA3X3AwGgJlbiACGgYIgPjcpwY",
                        },
                    )
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        t = (soup.title.string or "").strip().lower() if soup.title else ""
                        body = soup.get_text().lower()
                        if (
                            "404 not found" not in t
                            and "not found" not in t
                            and "эта страница недоступна" not in body
                            and "this page isn't available" not in body
                        ):
                            await registry.add_result("YouTube", url, "MetaScan")
                except Exception:
                    pass

            async def _check_tiktok() -> None:
                try:
                    url = f"https://www.tiktok.com/@{username}"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        s = soup.find("script", id="__UNIVERSAL_DATA_FOR_REHYDRATION__")
                        if s and s.string:
                            d = json.loads(s.string)
                            ud = d.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {})
                            if ud.get("statusCode") == 0 and "userInfo" in ud:
                                await registry.add_result("TikTok", url, "MetaScan")
                except Exception:
                    pass

            async def _check_twitch() -> None:
                try:
                    url = f"https://twitch.tv/{username}"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        t = (soup.title.string or "").strip().lower() if soup.title else ""
                        u_lower = username.lower()
                        if t and t != "twitch" and (u_lower in t or "- twitch" in t):
                            await registry.add_result("Twitch", url, "MetaScan")
                except Exception:
                    pass

            async def _check_pinterest() -> None:
                try:
                    url = f"https://www.pinterest.com/{username}/"
                    r = await client.get(url, headers=browser_headers)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, "html.parser")
                        og = soup.find("meta", property="og:title")
                        t = (soup.title.string or "").strip().lower() if soup.title else ""
                        u_lower = username.lower()
                        if og or (t and t != "pinterest" and u_lower in t):
                            await registry.add_result("Pinterest", url, "MetaScan")
                except Exception:
                    pass

            async def _check_spotify() -> None:
                try:
                    url = f"https://open.spotify.com/user/{username}"
                    r = await client.get(url, headers={"User-Agent": "Twitterbot/1.0"})
                    if r.status_code == 200:
                        await registry.add_result("Spotify", url, "MetaScan")
                except Exception:
                    pass

            tasks = [
                _check_instagram(),
                _check_twitter(),
                _check_telegram(),
                _check_github(),
                _check_youtube(),
                _check_tiktok(),
                _check_twitch(),
                _check_pinterest(),
                _check_spotify(),
            ]
            await asyncio.gather(*tasks)
