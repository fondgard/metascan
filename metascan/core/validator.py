"""AsyncValidator — HTTP validation engine for discovered OSINT profiles."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Callable
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from metascan.models import ProfileEntry, ValidationStatus

if TYPE_CHECKING:
    from metascan.core.registry import ResultRegistry

SOFT_404_SIGNATURES: list[str] = [
    # English
    "user not found",
    "page not found",
    "page doesn't exist",
    "this page doesn't exist",
    "this account doesn't exist",
    "profile is unavailable",
    "sorry, nobody on reddit goes by that name",
    "the specified profile could not be found",
    "doesn't have any public repositories",
    "404 not found",
    "error 404",
    "account suspended",
    "user does not exist",
    "no such user",
    "this page isn't available",
    "try searching for something else",
    "channel does not exist",
    "could not find this account",
    "user unavailable",
    # Russian
    "страница не найдена",
    "пользователь не найден",
    "такого страницы нет",
    "аккаунт удален",
    "профиль не существует",
    "эта страница недоступна",
    "может, поискать что-нибудь другое",
    "попробуйте ввести другой поисковый запрос",
    "канал не существует",
    "пользователь заблокирован",
    "страница удалена",
]

_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "DNT": "1",
}

_BAD_REDIRECT_PATHS: frozenset[str] = frozenset({"/", "/home", "/index", "/index.html", ""})
_BAD_REDIRECT_SUFFIXES: tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/404",
    "/error",
    "/not-found",
    "/notfound",
    "/missing",
    "/authwall",
    "/checkpoint",
    "/lander",
)

# SOCS cookie bypasses Google/YouTube GDPR consent screens
_DEFAULT_COOKIES: dict[str, str] = {
    "SOCS": "CAISNQgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjMwODI5LjA3X3AwGgJlbiACGgYIgPjcpwY",
}


class AsyncValidator:
    """Multi-tiered asynchronous HTTP profile validator.

    Eliminates false positives through layered network, status-code,
    redirect-target, and body/title content analysis.

    Args:
        concurrency: Max concurrent HTTP requests controlled by an asyncio semaphore.
        timeout: Single request timeout in seconds.
        accept_waf_as_valid: When True, 403/429 WAF responses proceed to content analysis.
        _transport: Optional injected transport for unit testing with mock backends.
    """

    def __init__(
        self,
        concurrency: int = 20,
        timeout: float = 10.0,
        accept_waf_as_valid: bool = False,
        _transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.accept_waf_as_valid = accept_waf_as_valid
        self._transport = _transport

    def _make_client(self) -> httpx.AsyncClient:
        """Create configured AsyncClient instance."""
        return httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            headers=_BROWSER_HEADERS,
            cookies=_DEFAULT_COOKIES,
            http2=True,
            transport=self._transport,
        )

    async def _validate_with_client(
        self,
        client: httpx.AsyncClient,
        entry: ProfileEntry,
        target_username: str,
    ) -> None:
        """Execute validation pipeline for a single profile entry.

        Args:
            client: Shared httpx.AsyncClient session.
            entry: Profile entry to validate in-place.
            target_username: Target username for identity matching.
        """
        url_lower = entry.url.lower()

        # Service-specific probe: F3.cool
        if "f3.cool" in url_lower:
            entry.status = ValidationStatus.ERROR
            entry.reason = "Redirect to /lander"
            return

        # Service-specific probe: Wikipedia
        if "special:centralauth" in url_lower:
            entry.status = ValidationStatus.ERROR
            entry.reason = "Special:CentralAuth Query"
            return

        # Service-specific probe: Instagram
        if "instagram.com" in url_lower:
            insta_headers = {
                "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }
            try:
                response = await client.get(entry.url, headers=insta_headers)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                og_title = soup.find("meta", property="og:title")
                title_content = (og_title.get("content", "") if og_title else "").lower()
                target_lower = target_username.lower()
                if f"(@{target_lower})" in title_content or f"@{target_lower}" in title_content or target_lower in title_content:
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return
                else:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: Twitter / X
        if "twitter.com" in url_lower or "x.com" in url_lower:
            check_url = f"https://x.com/{target_username}"
            try:
                response = await client.get(check_url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return
            elif response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title_text = (soup.title.string or "").strip().lower() if soup.title else ""
                body_lower = response.text.lower()
                if (
                    "account suspended" in title_text
                    or "account suspended" in body_lower
                    or "account has been suspended" in body_lower
                ):
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Account suspended"
                    return
                if "page not found" in title_text or "doesn’t exist" in response.text:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
                if f"@{target_username.lower()}" in title_text or "/ x" in title_text or "twitter" in title_text:
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return

        # Service-specific probe: Telegram
        if "t.me" in url_lower:
            try:
                response = await client.get(entry.url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                extra = soup.find(class_="tgme_page_extra")
                title = soup.find(class_="tgme_page_title")
                if extra or title:
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return
                else:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: YouTube
        if "youtube.com" in url_lower or "youtu.be" in url_lower:
            try:
                response = await client.get(entry.url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

            final_url_str = str(response.url).lower()
            if "consent.youtube.com" in final_url_str or "consent.google.com" in final_url_str:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Consent Wall Redirect"
                return

            soup = BeautifulSoup(response.text, "html.parser")
            title_text = (soup.title.string or "").strip().lower() if soup.title else ""
            if "404 not found" in title_text or "not found" in title_text:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

            body_text = soup.get_text(separator=" ", strip=True).lower()[:15_000]
            if (
                "эта страница недоступна" in body_text
                or "может, поискать что-нибудь другое" in body_text
                or "this page isn't available" in body_text
                or "try searching for something else" in body_text
            ):
                entry.status = ValidationStatus.ERROR
                entry.reason = "Soft-404 (User Not Found)"
                return

            if response.status_code == 200:
                entry.status = ValidationStatus.FOUND
                entry.reason = None
                return

        # Service-specific probe: TikTok
        if "tiktok.com" in url_lower:
            try:
                response = await client.get(entry.url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                s = soup.find("script", id="__UNIVERSAL_DATA_FOR_REHYDRATION__")
                if s and s.string:
                    try:
                        d = json.loads(s.string)
                        ud = d.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {})
                        if ud.get("statusCode") == 0 and "userInfo" in ud:
                            entry.status = ValidationStatus.FOUND
                            entry.reason = None
                            return
                        entry.status = ValidationStatus.ERROR
                        entry.reason = "Soft-404 (User Not Found)"
                        return
                    except Exception:
                        pass
                body_text = soup.get_text(separator=" ", strip=True).lower()[:15_000]
                if "could not find this account" in body_text:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: Reddit
        if "reddit.com" in url_lower:
            try:
                response = await client.get(entry.url, headers={"User-Agent": "Twitterbot/1.0"})
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title_text = (soup.title.string or "").strip().lower() if soup.title else ""
                target_lower = target_username.lower()
                if f"u/{target_lower}" in title_text or f"({target_lower})" in title_text:
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return
                else:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: Pinterest
        if "pinterest.com" in url_lower:
            try:
                response = await client.get(entry.url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                og = soup.find("meta", property="og:title")
                title_text = (soup.title.string or "").strip().lower() if soup.title else ""
                target_lower = target_username.lower()
                if og or (title_text and title_text != "pinterest" and target_lower in title_text):
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return
                else:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: Twitch
        if "twitch.tv" in url_lower:
            try:
                response = await client.get(entry.url)
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title_text = (soup.title.string or "").strip().lower() if soup.title else ""
                target_lower = target_username.lower()
                if title_text and title_text != "twitch" and (target_lower in title_text or "- twitch" in title_text):
                    entry.status = ValidationStatus.FOUND
                    entry.reason = None
                    return
                else:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = "Soft-404 (User Not Found)"
                    return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Service-specific probe: Spotify
        if "open.spotify.com" in url_lower:
            try:
                response = await client.get(entry.url, headers={"User-Agent": "Twitterbot/1.0"})
            except httpx.TimeoutException:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Timeout"
                return
            except httpx.RequestError:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Connection Error"
                return

            if response.status_code == 200:
                entry.status = ValidationStatus.FOUND
                entry.reason = None
                return
            elif response.status_code == 404:
                entry.status = ValidationStatus.ERROR
                entry.reason = "404 Not Found"
                return

        # Tier 1: Generic network checks
        try:
            response = await client.get(entry.url)
        except httpx.TimeoutException:
            entry.status = ValidationStatus.ERROR
            entry.reason = "Timeout"
            return
        except httpx.RequestError:
            entry.status = ValidationStatus.ERROR
            entry.reason = "Connection Error"
            return

        sc = response.status_code

        # Tier 2: HTTP status codes
        if sc == 404:
            entry.status = ValidationStatus.ERROR
            entry.reason = "404 Not Found"
            return

        if sc in (410, 451):
            entry.status = ValidationStatus.ERROR
            entry.reason = f"{sc} Gone/Unavailable"
            return

        if sc >= 500:
            entry.status = ValidationStatus.ERROR
            entry.reason = f"{sc} Server Error"
            return

        if sc in (401, 403, 429):
            server_hdr = response.headers.get("server", "").lower()
            body_snippet = response.text[:500].lower()
            is_waf = "cloudflare" in server_hdr or "just a moment" in body_snippet

            if is_waf:
                if not self.accept_waf_as_valid:
                    entry.status = ValidationStatus.ERROR
                    entry.reason = f"{sc} WAF/AntiBot"
                    return
            else:
                entry.status = ValidationStatus.ERROR
                entry.reason = f"HTTP {sc}"
                return

        elif sc != 200:
            entry.status = ValidationStatus.ERROR
            entry.reason = f"HTTP {sc}"
            return

        # Tier 3: Redirect destination analysis
        if response.history:
            final_url = str(response.url)
            final_path = urlparse(final_url).path.lower().rstrip("/")
            if final_path in _BAD_REDIRECT_PATHS or any(
                final_path.endswith(s) for s in _BAD_REDIRECT_SUFFIXES
            ):
                entry.status = ValidationStatus.ERROR
                entry.reason = "Redirect to Login/404"
                return

        # Tier 4: Content & Soft-404 analysis
        content_type = response.headers.get("content-type", "text/html")
        if content_type and "text" not in content_type and "html" not in content_type:
            entry.status = ValidationStatus.FOUND
            entry.reason = None
            return

        if "/lander" in response.text or "/lander" in str(response.url).lower():
            entry.status = ValidationStatus.ERROR
            entry.reason = "Redirect to /lander"
            return

        soup = BeautifulSoup(response.text, "html.parser")

        title_text = ""
        if soup.title and soup.title.string:
            title_text = soup.title.string.strip().lower()

        body_text = soup.get_text(separator=" ", strip=True).lower()[:15_000]

        for phrase in SOFT_404_SIGNATURES:
            if phrase in title_text:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Soft-404 (Title)"
                return

        username_in_title = target_username.lower() in title_text
        for phrase in SOFT_404_SIGNATURES:
            if phrase in body_text and not username_in_title:
                entry.status = ValidationStatus.ERROR
                entry.reason = "Soft-404 (User Not Found)"
                return

        entry.status = ValidationStatus.FOUND
        entry.reason = None

    async def validate_entry(
        self,
        entry: ProfileEntry,
        target_username: str,
    ) -> None:
        """Validate a single profile entry in isolation.

        Args:
            entry: Profile entry to validate.
            target_username: Target username to verify against.
        """
        async with self._make_client() as client:
            await self._validate_with_client(client, entry, target_username)

    async def validate_all(
        self,
        registry: ResultRegistry,
        progress_callback: Callable[[ProfileEntry], None] | None = None,
    ) -> None:
        """Validate all entries in the registry concurrently under a semaphore.

        Args:
            registry: Central ResultRegistry containing profile entries.
            progress_callback: Optional callback invoked after each validated entry.
        """
        entries = registry.all_entries()
        target = registry.target
        semaphore = asyncio.Semaphore(self.concurrency)

        async with self._make_client() as client:

            async def _task(entry: ProfileEntry) -> None:
                async with semaphore:
                    await self._validate_with_client(client, entry, target)
                if progress_callback is not None:
                    progress_callback(entry)

            await asyncio.gather(*[_task(e) for e in entries])
