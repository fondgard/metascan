"""Unit tests for models, normalize_url, and ResultRegistry."""

from __future__ import annotations

import json

import pytest

from metascan.core.registry import ResultRegistry, normalize_url
from metascan.models import ProfileEntry, ValidationStatus


# ===========================================================================
# normalize_url
# ===========================================================================

class TestNormalizeUrl:
    """Covers URL normalisation rules: scheme, www, case, trailing slash, QS."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # Basic http → https, trailing slash stripped, www removed, lowercase
            (
                "http://www.Reddit.com/user/nickname/",
                "https://reddit.com/user/nickname",
            ),
            # HTTPS passthrough, uppercase host
            (
                "HTTPS://GitHub.com/nickname",
                "https://github.com/nickname",
            ),
            # Root URL (no path) — trailing slash omitted
            (
                "http://www.example.com/",
                "https://example.com",
            ),
            # No www, already https, no trailing slash
            (
                "https://twitter.com/user/nickname",
                "https://twitter.com/user/nickname",
            ),
            # Query string and fragment are removed
            (
                "https://vk.com/nickname?ref=search#top",
                "https://vk.com/nickname",
            ),
            # Subdomain that is NOT www stays intact
            (
                "https://api.github.com/users/nickname",
                "https://api.github.com/users/nickname",
            ),
            # Leading/trailing whitespace ignored
            (
                "  https://instagram.com/nickname/  ",
                "https://instagram.com/nickname",
            ),
            # Mixed case path is preserved (usernames can be case-sensitive)
            (
                "https://GitHub.com/UserName",
                "https://github.com/UserName",
            ),
            # YouTube channel with /about normalizes to channel URL
            (
                "https://www.youtube.com/@ponchegg/about",
                "https://youtube.com/@ponchegg",
            ),
            (
                "https://youtube.com/@ponchegg/about/",
                "https://youtube.com/@ponchegg",
            ),
            # Schemeless URL with www
            (
                "www.Reddit.com/user/nickname/",
                "https://reddit.com/user/nickname",
            ),
            # Schemeless URL without www, preserving path case
            (
                "github.com/UserName",
                "https://github.com/UserName",
            ),
            # Uppercase WWW and domain, path case preserved, trailing slash stripped
            (
                "HTTPS://WWW.EXAMPLE.COM/PathCase/",
                "https://example.com/PathCase",
            ),
            # Standard port 80 stripped
            (
                "http://example.com:80/user/",
                "https://example.com/user",
            ),
            # Standard port 443 stripped
            (
                "https://example.com:443/user/",
                "https://example.com/user",
            ),
            # Non-standard port preserved
            (
                "https://example.com:8080/path/",
                "https://example.com:8080/path",
            ),
            # Multiple trailing slashes stripped
            (
                "https://example.com/user///",
                "https://example.com/user",
            ),
            # Subdomain containing 'www' inside not stripped
            (
                "https://awww.com/user/",
                "https://awww.com/user",
            ),
        ],
    )
    def test_normalize(self, raw: str, expected: str) -> None:
        assert normalize_url(raw) == expected


# ===========================================================================
# ProfileEntry
# ===========================================================================

class TestProfileEntry:
    """Unit tests for the ProfileEntry model."""

    def test_tools_str_single(self) -> None:
        entry = ProfileEntry(
            service="Github",
            url="https://github.com/nick",
            normalized_url="https://github.com/nick",
            tools=["Maigret"],
        )
        assert entry.tools_str == "Maigret"

    def test_tools_str_multiple(self) -> None:
        entry = ProfileEntry(
            service="Reddit",
            url="https://reddit.com/user/nick",
            normalized_url="https://reddit.com/user/nick",
            tools=["Sherlock", "Blackbird"],
        )
        assert entry.tools_str == "Sherlock, Blackbird"

    def test_default_status_is_pending(self) -> None:
        entry = ProfileEntry(
            service="Steam",
            url="https://steamcommunity.com/id/nick",
            normalized_url="https://steamcommunity.com/id/nick",
            tools=["Sherlock"],
        )
        assert entry.status == ValidationStatus.PENDING

    def test_reason_defaults_to_none(self) -> None:
        entry = ProfileEntry(
            service="Twitter",
            url="https://twitter.com/nick",
            normalized_url="https://twitter.com/nick",
            tools=["Sherlock"],
        )
        assert entry.reason is None

    def test_entry_update_tools_and_metadata(self) -> None:
        entry = ProfileEntry(
            service="Reddit",
            url="https://reddit.com/user/nick",
            normalized_url="https://reddit.com/user/nick",
            tools=["Sherlock"],
            metadata={"karma": 50, "fullname": "Nick"},
        )
        entry.update(tools=["Blackbird", "Sherlock"], metadata={"bio": "Bio text", "fullname": "Other"})
        assert entry.tools == ["Sherlock", "Blackbird"]
        assert entry.metadata["karma"] == 50
        assert entry.metadata["fullname"] == "Nick"
        assert entry.metadata["bio"] == "Bio text"

    def test_entry_update_tools_as_single_str(self) -> None:
        entry = ProfileEntry(
            service="Github",
            url="https://github.com/nick",
            normalized_url="https://github.com/nick",
            tools=["Sherlock"],
        )
        entry.update(tools="Maigret")
        assert entry.tools == ["Sherlock", "Maigret"]


# ===========================================================================
# ResultRegistry.add_result — deduplication
# ===========================================================================

class TestResultRegistryDedup:
    """Verifies that the same normalised URL is never stored twice."""

    @pytest.mark.asyncio
    async def test_new_entry_created(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        entry = await reg.add_result("Github", "https://github.com/nick", "Sherlock")

        assert entry.service == "Github"
        assert entry.tools == ["Sherlock"]
        assert len(reg.all_entries()) == 1

    @pytest.mark.asyncio
    async def test_same_url_different_tools_merged(self) -> None:
        """Sherlock + Blackbird both find the same Reddit URL → one entry, two tools."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Blackbird"])

        await reg.add_result("Reddit", "https://reddit.com/user/nick", "Sherlock")
        await reg.add_result("Reddit", "https://reddit.com/user/nick/", "Blackbird")

        entries = reg.all_entries()
        assert len(entries) == 1, "Duplicate URL must not create a second entry"

        entry = entries[0]
        assert entry.tools == ["Sherlock", "Blackbird"]
        assert entry.tools_str == "Sherlock, Blackbird"

    @pytest.mark.asyncio
    async def test_duplicate_tool_not_added_twice(self) -> None:
        """Adding the same tool twice for the same URL should be idempotent."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])

        await reg.add_result("Github", "https://github.com/nick", "Sherlock")
        await reg.add_result("Github", "https://github.com/nick", "Sherlock")

        assert len(reg.all_entries()) == 1
        assert reg.all_entries()[0].tools == ["Sherlock"]

    @pytest.mark.asyncio
    async def test_youtube_about_merged(self) -> None:
        """YouTube channel URL and /about URL must deduplicate into a single entry."""
        reg = ResultRegistry(target="ponchegg", scanners=["Maigret", "Blackbird"])

        await reg.add_result("YouTube", "https://www.youtube.com/@ponchegg", "Maigret")
        await reg.add_result("YouTube", "https://www.youtube.com/@ponchegg/about", "Blackbird")

        entries = reg.all_entries()
        assert len(entries) == 1
        assert entries[0].url == "https://www.youtube.com/@ponchegg"
        assert entries[0].tools == ["Maigret", "Blackbird"]

    @pytest.mark.asyncio
    async def test_normalisation_applied_before_keying(self) -> None:
        """http://www.Reddit.com/... and https://reddit.com/... → same entry."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Maigret"])

        await reg.add_result("Reddit", "http://www.Reddit.com/user/nick/", "Sherlock")
        await reg.add_result("Reddit", "https://reddit.com/user/nick", "Maigret")

        entries = reg.all_entries()
        assert len(entries) == 1
        assert set(entries[0].tools) == {"Sherlock", "Maigret"}

    @pytest.mark.asyncio
    async def test_two_different_urls_create_two_entries(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])

        await reg.add_result("Github", "https://github.com/nick", "Sherlock")
        await reg.add_result("Twitter", "https://twitter.com/nick", "Sherlock")

        assert len(reg.all_entries()) == 2

    @pytest.mark.asyncio
    async def test_metadata_merged_without_overwriting_entry(self) -> None:
        """When the same URL is added by multiple tools with metadata, keys are merged."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Maigret", "Blackbird"])

        e1 = await reg.add_result(
            "Reddit",
            "http://www.Reddit.com/user/nick/",
            "Sherlock",
            metadata={"karma": 100, "fullname": "Nick"},
        )
        e2 = await reg.add_result(
            "Reddit",
            "https://reddit.com/user/nick",
            "Maigret",
            metadata={"bio": "Bio from Maigret", "fullname": "ShouldNotOverwrite"},
        )

        assert e1 is e2
        assert len(reg.all_entries()) == 1
        assert e1.tools == ["Sherlock", "Maigret"]
        # Existing non-empty key preserved
        assert e1.metadata["fullname"] == "Nick"
        assert e1.metadata["karma"] == 100
        # New key merged
        assert e1.metadata["bio"] == "Bio from Maigret"

    @pytest.mark.asyncio
    async def test_tools_list_kwarg_accepted(self) -> None:
        """add_result accepts tools=[...] keyword argument."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Maigret"])

        entry = await reg.add_result(
            "Reddit",
            "https://reddit.com/user/nick",
            tools=["Sherlock", "Maigret"],
        )
        assert entry.tools == ["Sherlock", "Maigret"]

    def test_registry_dict_like_protocol(self) -> None:
        """ResultRegistry supports dict indexing, in-operator, len, get, and items."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        entry = reg.add_result_sync("Github", "https://github.com/nick", "Sherlock")

        assert len(reg) == 1
        assert "https://github.com/nick" in reg
        assert "http://www.github.com/nick/" in reg  # normalization match
        assert reg["https://github.com/nick"] is entry
        assert reg.get("https://github.com/nick") is entry
        assert reg.get("https://nonexistent.com") is None
        assert list(reg.values()) == [entry]

    def test_registry_update_method(self) -> None:
        """registry.update(...) allows merging results."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Maigret"])
        reg.update("Github", "https://github.com/nick", tools=["Sherlock"], metadata={"stars": 5})
        reg.update("Github", "https://github.com/nick/", tools=["Maigret"], metadata={"forks": 2})

        assert len(reg) == 1
        entry = reg["https://github.com/nick"]
        assert entry.tools == ["Sherlock", "Maigret"]
        assert entry.metadata == {"stars": 5, "forks": 2}


# ===========================================================================
# ResultRegistry.get_valid_results / get_filtered_results
# ===========================================================================

class TestResultRegistryFilters:
    """Verifies filtered views return only the correct status entries."""

    @pytest.mark.asyncio
    async def test_get_valid_results(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        entry = await reg.add_result("Github", "https://github.com/nick", "Sherlock")
        entry.status = ValidationStatus.FOUND

        valid = reg.get_valid_results()
        assert len(valid) == 1
        assert valid[0].service == "Github"

    @pytest.mark.asyncio
    async def test_get_filtered_results(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        entry = await reg.add_result("Steam", "https://steamcommunity.com/id/nick", "Sherlock")
        entry.status = ValidationStatus.ERROR
        entry.reason = "404 Not Found"

        filtered = reg.get_filtered_results()
        assert len(filtered) == 1
        assert filtered[0].reason == "404 Not Found"

    @pytest.mark.asyncio
    async def test_pending_entry_not_in_valid_or_filtered(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        await reg.add_result("Twitter", "https://twitter.com/nick", "Sherlock")
        # status stays PENDING (not validated yet)

        assert reg.get_valid_results() == []
        assert reg.get_filtered_results() == []

    @pytest.mark.asyncio
    async def test_valid_results_sorted_by_service(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])

        for service, url in [
            ("Reddit", "https://reddit.com/user/nick"),
            ("Github", "https://github.com/nick"),
            ("Twitter", "https://twitter.com/nick"),
        ]:
            e = await reg.add_result(service, url, "Sherlock")
            e.status = ValidationStatus.FOUND

        names = [e.service for e in reg.get_valid_results()]
        assert names == sorted(names, key=str.lower)


# ===========================================================================
# ResultRegistry.to_raw_json_dict — JSON shape
# ===========================================================================

class TestToRawJsonDict:
    """Ensures the exported dict matches the RAW JSON DATA shape in example.html."""

    @pytest.mark.asyncio
    async def test_top_level_keys(self) -> None:
        reg = ResultRegistry(target="nickname", scanners=["Sherlock", "Maigret", "Blackbird"])
        data = reg.to_raw_json_dict()

        assert data["target"] == "nickname"
        assert data["scanners"] == ["Sherlock", "Maigret", "Blackbird"]
        assert "results" in data

    @pytest.mark.asyncio
    async def test_found_entry_shape(self) -> None:
        reg = ResultRegistry(target="nickname", scanners=["Maigret"])
        entry = await reg.add_result("Github", "https://github.com/nickname", "Maigret")
        entry.status = ValidationStatus.FOUND

        data = reg.to_raw_json_dict()
        github = data["results"]["Github"]

        assert github["url"] == "https://github.com/nickname"
        assert github["status"] == "Found"
        assert github["tools"] == ["Maigret"]
        assert "error_type" not in github

    @pytest.mark.asyncio
    async def test_error_entry_has_error_type(self) -> None:
        reg = ResultRegistry(target="nickname", scanners=["Sherlock"])
        entry = await reg.add_result(
            "Steam", "https://steamcommunity.com/id/nickname", "Sherlock"
        )
        entry.status = ValidationStatus.ERROR
        entry.reason = "404 Not Found"

        data = reg.to_raw_json_dict()
        steam = data["results"]["Steam"]

        assert steam["status"] == "Error"
        assert steam["error_type"] == "404 Not Found"

    @pytest.mark.asyncio
    async def test_full_example_html_shape(self) -> None:
        """Reproduce the exact example from example.html RAW JSON DATA block."""
        reg = ResultRegistry(
            target="nickname",
            scanners=["Sherlock", "Maigret", "Blackbird"],
        )

        e1 = await reg.add_result("Github", "https://github.com/nickname", "Maigret")
        e1.status = ValidationStatus.FOUND

        e2 = await reg.add_result("Reddit", "https://reddit.com/user/nickname", "Sherlock")
        await reg.add_result("Reddit", "https://reddit.com/user/nickname", "Blackbird")
        e2.status = ValidationStatus.FOUND

        e3 = await reg.add_result(
            "Steam", "https://steamcommunity.com/id/nickname", "Sherlock"
        )
        e3.status = ValidationStatus.ERROR
        e3.reason = "404 Not Found"

        data = reg.to_raw_json_dict()

        assert data["results"]["Github"]["tools"] == ["Maigret"]
        assert data["results"]["Reddit"]["tools"] == ["Sherlock", "Blackbird"]
        assert data["results"]["Steam"]["status"] == "Error"
        assert data["results"]["Steam"]["error_type"] == "404 Not Found"

    @pytest.mark.asyncio
    async def test_to_raw_json_str_is_valid_json(self) -> None:
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        entry = await reg.add_result("Github", "https://github.com/nick", "Sherlock")
        entry.status = ValidationStatus.FOUND

        raw = reg.to_raw_json_str()
        parsed = json.loads(raw)
        assert parsed["target"] == "nick"

    @pytest.mark.asyncio
    async def test_duplicate_service_name_gets_suffix(self) -> None:
        """Edge case: two different URLs reported under the same service name."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        # Force two entries under 'Custom' with different URLs
        await reg.add_result("Custom", "https://custom.com/nick", "Sherlock")
        await reg.add_result("Custom", "https://custom.io/nick", "Sherlock")

        data = reg.to_raw_json_dict()
        keys = list(data["results"].keys())

        assert "Custom" in keys
        assert any("(2)" in k for k in keys), f"Expected a '(2)' key, got: {keys}"
