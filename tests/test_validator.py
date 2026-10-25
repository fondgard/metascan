"""Unit tests for AsyncValidator using httpx mock transport.

Each test is isolated: uses DictMockTransport — a simple router,
matching URL substrings to predefined responses.
"""

from __future__ import annotations

import pytest
import httpx

from metascan.core.registry import ResultRegistry
from metascan.core.validator import AsyncValidator, SOFT_404_SIGNATURES
from metascan.models import ProfileEntry, ValidationStatus


# ===========================================================================
# Helper infrastructure
# ===========================================================================

def _make_entry(
    service: str = "TestService",
    url: str = "https://example.com/testuser",
) -> ProfileEntry:
    """Creates ProfileEntry in PENDING status for tests."""
    from metascan.core.registry import normalize_url
    return ProfileEntry(
        service=service,
        url=url,
        normalized_url=normalize_url(url),
        tools=["Sherlock"],
    )


class RoutedMockTransport(httpx.AsyncBaseTransport):
    """Mock transport routing by URL substring.

    ``routes`` — ordered list of tuples ``(url_fragment, status_code, body, extra_headers)``.
    The first matching route wins.
    If none match — returns 404.
    """

    def __init__(self, routes: list[tuple[str, int, str, dict]]) -> None:
        self._routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for fragment, status, body, extra_headers in self._routes:
            if fragment in url:
                headers = {"content-type": "text/html; charset=utf-8", **extra_headers}
                return httpx.Response(status, text=body, headers=headers)
        return httpx.Response(
            404,
            text="<html><title>404 Not Found</title></html>",
            headers={"content-type": "text/html; charset=utf-8"},
        )


class TimeoutMockTransport(httpx.AsyncBaseTransport):
    """Transport that always raises TimeoutException."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("Mocked timeout", request=request)


def _make_validator(**kwargs) -> AsyncValidator:
    """Creates validator with injected transport."""
    return AsyncValidator(**kwargs)


# ===========================================================================
# Check 1: Network errors
# ===========================================================================

class TestNetworkErrors:

    @pytest.mark.asyncio
    async def test_timeout_gives_error(self) -> None:
        validator = AsyncValidator(_transport=TimeoutMockTransport())
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Timeout"

    @pytest.mark.asyncio
    async def test_connection_error_gives_error(self) -> None:
        class ConnErrTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.ConnectError("Connection refused", request=request)

        validator = AsyncValidator(_transport=ConnErrTransport())
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Connection Error"


# ===========================================================================
# Check 2: HTTP status codes
# ===========================================================================

class TestHttpStatusCodes:

    @pytest.mark.asyncio
    async def test_404_gives_error(self) -> None:
        transport = RoutedMockTransport([
            ("example.com", 404, "<html><title>404</title></html>", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "404 Not Found"

    @pytest.mark.asyncio
    async def test_410_gone(self) -> None:
        transport = RoutedMockTransport([
            ("example.com", 410, "", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "410 Gone/Unavailable"

    @pytest.mark.asyncio
    async def test_451_unavailable(self) -> None:
        transport = RoutedMockTransport([
            ("example.com", 451, "", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "451 Gone/Unavailable"

    @pytest.mark.asyncio
    async def test_500_server_error(self) -> None:
        transport = RoutedMockTransport([
            ("example.com", 500, "", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "500 Server Error"

    @pytest.mark.asyncio
    async def test_503_server_error(self) -> None:
        transport = RoutedMockTransport([
            ("example.com", 503, "", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "503 Server Error"

    @pytest.mark.asyncio
    async def test_403_generic_gives_http_error(self) -> None:
        """403 without Cloudflare signatures -> HTTP 403."""
        transport = RoutedMockTransport([
            ("example.com", 403, "<html><title>Forbidden</title></html>", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "HTTP 403"

    @pytest.mark.asyncio
    async def test_403_cloudflare_waf(self) -> None:
        """403 with header server: cloudflare -> WAF/AntiBot."""
        transport = RoutedMockTransport([
            ("example.com", 403, "<html><title>Just a moment...</title></html>",
             {"server": "cloudflare"}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert "WAF/AntiBot" in entry.reason

    @pytest.mark.asyncio
    async def test_403_cloudflare_waf_accept_as_valid(self) -> None:
        """403 WAF + accept_waf_as_valid=True -> proceed to content analysis."""
        html = "<html><title>testuser - Example</title><body>Welcome testuser!</body></html>"
        transport = RoutedMockTransport([
            ("example.com", 403, html, {"server": "cloudflare"}),
        ])
        # accept_waf_as_valid allows analyzing WAF responses as potentially valid
        validator = AsyncValidator(_transport=transport, accept_waf_as_valid=True)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        # Username in title -> FOUND (soft-404 not triggered)
        assert entry.status == ValidationStatus.FOUND


# ===========================================================================
# Check 3: Redirects
# ===========================================================================

class TestRedirectDetection:

    @pytest.mark.asyncio
    async def test_redirect_to_login_gives_error(self) -> None:
        """Redirect to /login -> Redirect to Login/404."""
        transport = RoutedMockTransport([
            # First request -> 302 to /login
            ("example.com/testuser", 302, "",
             {"location": "https://example.com/login"}),
            # httpx follows redirect -> 200 to /login
            ("example.com/login", 200,
             "<html><title>Login</title><body>Please sign in.</body></html>",
             {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://example.com/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Redirect to Login/404"

    @pytest.mark.asyncio
    async def test_redirect_to_404_path(self) -> None:
        """Redirect to /404 -> Redirect to Login/404."""
        transport = RoutedMockTransport([
            ("example.com/testuser", 302, "",
             {"location": "https://example.com/404"}),
            ("example.com/404", 200,
             "<html><title>Not Found</title></html>", {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://example.com/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Redirect to Login/404"

    @pytest.mark.asyncio
    async def test_redirect_to_profile_subpage_is_valid(self) -> None:
        """Redirect to /testuser/overview (non-bad path) -> not a redirect error."""
        html = "<html><title>testuser - Example</title><body>Profile of testuser.</body></html>"

        # Use different domains to prevent route prefix collision.
        # profile.example.com/testuser -> 302 -> overview.example.com/testuser/overview
        transport = RoutedMockTransport([
            ("profile.example.com", 302, "",
             {"location": "https://overview.example.com/testuser/overview"}),
            ("overview.example.com", 200, html, {}),
        ])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://profile.example.com/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.FOUND


# ===========================================================================
# Check 4: Content analysis (Soft-404)
# ===========================================================================

class TestContentAnalysis:

    @pytest.mark.asyncio
    async def test_valid_profile_200_with_username_in_title(self) -> None:
        """HTTP 200, username in title, no stop phrases -> FOUND."""
        html = (
            "<html><title>testuser - Github</title>"
            "<body><h1>testuser</h1><p>This is a profile page.</p></body></html>"
        )
        transport = RoutedMockTransport([("github.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://github.com/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_soft404_stop_phrase_in_title(self) -> None:
        """Stop phrase in <title> -> Soft-404 (Title), regardless of body."""
        html = (
            "<html><title>Page not found - Example</title>"
            "<body><p>Nothing here.</p></body></html>"
        )
        transport = RoutedMockTransport([("example.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Soft-404 (Title)"

    @pytest.mark.asyncio
    async def test_soft404_stop_phrase_in_body_no_username_in_title(self) -> None:
        """Stop phrase in body, username NOT in title -> Soft-404 (User Not Found)."""
        html = (
            "<html><title>Profile Lookup</title>"
            "<body><p>The specified profile could not be found on this platform.</p></body></html>"
        )
        transport = RoutedMockTransport([("example.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Soft-404 (User Not Found)"

    @pytest.mark.asyncio
    async def test_stop_phrase_in_body_but_username_in_title_is_valid(self) -> None:
        """Stop phrase in body, but username in title -> considered valid.

        Scenario: profile page contains external quote with "user not found",
        but title unambiguously names profile owner.
        """
        html = (
            "<html><title>testuser — Personal Page</title>"
            "<body>"
            "  <p>testuser's favourite quote: 'Sorry, user not found in the archives.'</p>"
            "</body></html>"
        )
        transport = RoutedMockTransport([("example.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.FOUND

    @pytest.mark.asyncio
    async def test_reddit_soft404_signature(self) -> None:
        """Specific Reddit phrase -> Soft-404 (User Not Found)."""
        html = (
            "<html><title>reddit: the front page of the internet</title>"
            "<body>"
            "<p>Sorry, nobody on reddit goes by that name. "
            "Try a search instead?</p>"
            "</body></html>"
        )
        transport = RoutedMockTransport([("reddit.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://reddit.com/user/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Soft-404 (User Not Found)"

    @pytest.mark.asyncio
    async def test_russian_soft404_signature(self) -> None:
        """Russian stop phrase in body -> Soft-404."""
        html = (
            "<html><title>Профиль</title>"
            "<body><p>Страница не найдена. Попробуйте другой запрос.</p></body></html>"
        )
        transport = RoutedMockTransport([("example.ru", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry(url="https://example.ru/testuser")
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Soft-404" in entry.reason

    @pytest.mark.asyncio
    async def test_404_error_type_in_title(self) -> None:
        """'error 404' in <title> (HTTP 200) -> Soft-404 (Title)."""
        html = "<html><title>Error 404 - User Not Found</title><body>Nothing.</body></html>"
        transport = RoutedMockTransport([("example.com", 200, html, {})])
        validator = AsyncValidator(_transport=transport)
        entry = _make_entry()
        await validator.validate_entry(entry, "testuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Soft-404 (Title)"


# ===========================================================================
# validate_all — integration test with ResultRegistry
# ===========================================================================

class TestValidateAll:

    @pytest.mark.asyncio
    async def test_validate_all_updates_registry(self) -> None:
        """validate_all updates statuses of all entries in the registry."""
        valid_html = (
            "<html><title>nick - Github</title><body>nick's repos</body></html>"
        )
        missing_html = (
            "<html><title>Profile Lookup</title>"
            "<body>The specified profile could not be found.</body></html>"
        )
        transport = RoutedMockTransport([
            ("github.com", 200, valid_html, {}),
            ("steam", 404, "<html><title>404</title></html>", {}),
            ("reddit.com", 200, missing_html, {}),
        ])

        registry = ResultRegistry(target="nick", scanners=["Sherlock"])
        await registry.add_result("Github", "https://github.com/nick", "Sherlock")
        await registry.add_result("Steam", "https://steamcommunity.com/id/nick", "Sherlock")
        await registry.add_result("Reddit", "https://reddit.com/user/nick", "Sherlock")

        validator = AsyncValidator(_transport=transport, concurrency=5)
        await validator.validate_all(registry)

        valid = registry.get_valid_results()
        filtered = registry.get_filtered_results()

        assert len(valid) == 1
        assert valid[0].service == "Github"

        assert len(filtered) == 2
        filtered_services = {e.service for e in filtered}
        assert "Steam" in filtered_services
        assert "Reddit" in filtered_services

    @pytest.mark.asyncio
    async def test_validate_all_calls_progress_callback(self) -> None:
        """progress_callback is called exactly once per entry."""
        transport = RoutedMockTransport([
            ("example.com", 200,
             "<html><title>testuser - Example</title></html>", {}),
        ])
        registry = ResultRegistry(target="testuser", scanners=["Sherlock"])
        await registry.add_result("Example", "https://example.com/testuser", "Sherlock")
        await registry.add_result("Example2", "https://example.com/testuser2", "Sherlock")

        call_count = 0

        def cb(entry: ProfileEntry) -> None:
            nonlocal call_count
            call_count += 1

        validator = AsyncValidator(_transport=transport)
        await validator.validate_all(registry, progress_callback=cb)

        assert call_count == 2


# ===========================================================================
# Verification of SOFT_404_SIGNATURES directory integrity
# ===========================================================================

class TestSoft404Signatures:

    def test_signatures_not_empty(self) -> None:
        assert len(SOFT_404_SIGNATURES) > 0

    def test_all_signatures_lowercase(self) -> None:
        for phrase in SOFT_404_SIGNATURES:
            assert phrase == phrase.lower(), (
                f"Signature must be lowercase: {phrase!r}"
            )

    def test_no_duplicate_signatures(self) -> None:
        assert len(SOFT_404_SIGNATURES) == len(set(SOFT_404_SIGNATURES)), (
            "Duplicate signatures found in SOFT_404_SIGNATURES"
        )


# ===========================================================================
# Specialized validation for popular social platforms
# ===========================================================================

class TestSpecializedPlatformValidation:

    @pytest.mark.asyncio
    async def test_instagram_valid_with_og_title(self) -> None:
        html = '<html><head><meta property="og:title" content="John Doe (@alex) • Instagram photos"></head></html>'
        transport = RoutedMockTransport([
            ("instagram.com/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Instagram", "https://www.instagram.com/alex/")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_instagram_invalid_missing_og_title(self) -> None:
        html = "<html><head><title>Instagram</title></head><body>No content</body></html>"
        transport = RoutedMockTransport([
            ("instagram.com/fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Instagram", "https://www.instagram.com/fakeuser/")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_twitter_x_valid(self) -> None:
        html = "<html><head><title>Alex (@alex) / X</title></head></html>"
        transport = RoutedMockTransport([
            ("x.com/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Twitter", "https://x.com/alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_twitter_x_404_invalid(self) -> None:
        transport = RoutedMockTransport([
            ("x.com/fakeuser", 404, "<html><title>Page not found / X</title></html>", {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Twitter", "https://x.com/fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "404 Not Found"

    @pytest.mark.asyncio
    async def test_telegram_valid_with_extra(self) -> None:
        html = '<html><body><div class="tgme_page_extra">@alex</div></body></html>'
        transport = RoutedMockTransport([
            ("t.me/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Telegram", "https://t.me/alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_telegram_invalid(self) -> None:
        html = "<html><body>No user here</body></html>"
        transport = RoutedMockTransport([
            ("t.me/fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Telegram", "https://t.me/fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_youtube_valid(self) -> None:
        html = "<html><head><title>Alex Channel - YouTube</title></head><body>Welcome to my channel</body></html>"
        transport = RoutedMockTransport([
            ("youtube.com/@alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("YouTube", "https://www.youtube.com/@alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_youtube_invalid_russian_soft404(self) -> None:
        html = "<html><head><title>YouTube</title></head><body>Эта страница недоступна. Может, поискать что-нибудь другое?</body></html>"
        transport = RoutedMockTransport([
            ("youtube.com/@fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("YouTube", "https://www.youtube.com/@fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_youtube_invalid_404(self) -> None:
        transport = RoutedMockTransport([
            ("youtube.com/@fakeuser", 404, "<html><title>404 Not Found</title></html>", {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("YouTube", "https://www.youtube.com/@fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "404 Not Found"

    @pytest.mark.asyncio
    async def test_tiktok_valid(self) -> None:
        data = {
            "__DEFAULT_SCOPE__": {
                "webapp.user-detail": {
                    "statusCode": 0,
                    "userInfo": {"user": {"id": "123", "uniqueId": "alex"}},
                }
            }
        }
        import json as _json
        html = f'<html><script id="__UNIVERSAL_DATA_FOR_REHYDRATION__">{_json.dumps(data)}</script></html>'
        transport = RoutedMockTransport([
            ("tiktok.com/@alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("TikTok", "https://www.tiktok.com/@alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_tiktok_invalid(self) -> None:
        data = {
            "__DEFAULT_SCOPE__": {
                "webapp.user-detail": {
                    "statusCode": 10221,
                    "statusMsg": "user banned",
                }
            }
        }
        import json as _json
        html = f'<html><script id="__UNIVERSAL_DATA_FOR_REHYDRATION__">{_json.dumps(data)}</script></html>'
        transport = RoutedMockTransport([
            ("tiktok.com/@fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("TikTok", "https://www.tiktok.com/@fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_reddit_valid(self) -> None:
        html = "<html><head><title>Alex (u/alex) - Reddit</title></head></html>"
        transport = RoutedMockTransport([
            ("reddit.com/user/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Reddit", "https://www.reddit.com/user/alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_reddit_invalid(self) -> None:
        html = "<html><head><title>Reddit - The heart of the internet</title></head></html>"
        transport = RoutedMockTransport([
            ("reddit.com/user/fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Reddit", "https://www.reddit.com/user/fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_twitch_valid(self) -> None:
        html = "<html><head><title>alex - Twitch</title></head></html>"
        transport = RoutedMockTransport([
            ("twitch.tv/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Twitch", "https://www.twitch.tv/alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_twitch_invalid(self) -> None:
        html = "<html><head><title>Twitch</title></head></html>"
        transport = RoutedMockTransport([
            ("twitch.tv/fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Twitch", "https://www.twitch.tv/fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_pinterest_valid(self) -> None:
        html = '<html><head><meta property="og:title" content="Alex (alex) - Profile | Pinterest"></head></html>'
        transport = RoutedMockTransport([
            ("pinterest.com/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Pinterest", "https://www.pinterest.com/alex/")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_pinterest_invalid(self) -> None:
        html = "<html><head><title>Pinterest</title></head></html>"
        transport = RoutedMockTransport([
            ("pinterest.com/fakeuser", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Pinterest", "https://www.pinterest.com/fakeuser/")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "Not Found" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_spotify_valid(self) -> None:
        html = "<html><head><title>Alex | Spotify</title></head></html>"
        transport = RoutedMockTransport([
            ("open.spotify.com/user/alex", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Spotify", "https://open.spotify.com/user/alex")
        await v.validate_entry(entry, "alex")

        assert entry.status == ValidationStatus.FOUND
        assert entry.reason is None

    @pytest.mark.asyncio
    async def test_spotify_invalid(self) -> None:
        transport = RoutedMockTransport([
            ("open.spotify.com/user/fakeuser", 404, "404 Not Found", {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Spotify", "https://open.spotify.com/user/fakeuser")
        await v.validate_entry(entry, "fakeuser")

        assert entry.status == ValidationStatus.ERROR
        assert "404" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_f3_cool_rejected_lander(self) -> None:
        v = AsyncValidator()
        entry = _make_entry("F3.cool", "https://f3.cool/ponchegg/")
        await v.validate_entry(entry, "ponchegg")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Redirect to /lander"

    @pytest.mark.asyncio
    async def test_wikipedia_centralauth_rejected(self) -> None:
        v = AsyncValidator()
        entry = _make_entry("Wikipedia", "https://en.wikipedia.org/wiki/Special:CentralAuth/ponchegg?uselang=qqx")
        await v.validate_entry(entry, "ponchegg")

        assert entry.status == ValidationStatus.ERROR
        assert "Special:CentralAuth" in (entry.reason or "")

    @pytest.mark.asyncio
    async def test_twitter_x_suspended(self) -> None:
        html = "<html><head><title>Account suspended / X</title></head><body>This account has been suspended.</body></html>"
        transport = RoutedMockTransport([
            ("x.com/suspended_user", 200, html, {}),
        ])
        v = AsyncValidator(_transport=transport)
        entry = _make_entry("Twitter", "https://x.com/suspended_user")
        await v.validate_entry(entry, "suspended_user")

        assert entry.status == ValidationStatus.ERROR
        assert entry.reason == "Account suspended"




