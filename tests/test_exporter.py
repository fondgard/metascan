"""Unit tests for HtmlExporter.

Checks that:
* template renders without errors,
* all three blocks (VALID, FILTERED, RAW JSON) contain correct content,
* rejection reason (404 Not Found) is displayed in FILTERED RESULTS,
* RAW JSON reproduces the data structure,
* file is written to disk at the expected location,
* empty blocks display the placeholder "NO VALID PROFILES CONFIRMED".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from metascan.core.registry import ResultRegistry
from metascan.exporters.html_exporter import HtmlExporter
from metascan.models import ValidationStatus


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def example_registry() -> ResultRegistry:
    """Registry populated with test data:
    - Github  (Found,   Maigret)
    - Reddit  (Found,   Sherlock + Blackbird)
    - Steam   (Error,   Sherlock, reason=404 Not Found)
    """
    return _build_example_registry()


def _build_example_registry() -> ResultRegistry:
    import asyncio

    reg = ResultRegistry(
        target="nickname",
        scanners=["Sherlock", "Maigret", "Blackbird"],
    )

    async def _populate() -> None:
        e_github = await reg.add_result("Github", "https://github.com/nickname", "Maigret")
        e_github.status = ValidationStatus.FOUND

        e_reddit = await reg.add_result("Reddit", "https://reddit.com/user/nickname", "Sherlock")
        await reg.add_result("Reddit", "https://reddit.com/user/nickname", "Blackbird")
        e_reddit.status = ValidationStatus.FOUND

        e_steam = await reg.add_result(
            "Steam", "https://steamcommunity.com/id/nickname", "Sherlock"
        )
        e_steam.status = ValidationStatus.ERROR
        e_steam.reason = "404 Not Found"

    asyncio.run(_populate())
    return reg


@pytest.fixture()
def exporter() -> HtmlExporter:
    return HtmlExporter()


@pytest.fixture()
def rendered_html(example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path) -> str:
    """Renders report and returns the HTML string."""
    out = tmp_path / "metascan_nickname.html"
    exporter.export(example_registry, out)
    return out.read_text(encoding="utf-8")


# ===========================================================================
# HTML Structure Tests
# ===========================================================================

class TestHtmlStructure:

    def test_html_doctype_present(self, rendered_html: str) -> None:
        assert rendered_html.strip().startswith("<!DOCTYPE html>")

    def test_title_contains_target(self, rendered_html: str) -> None:
        assert "<title>MetaScan: nickname</title>" in rendered_html

    def test_footer_text_exact(self, rendered_html: str) -> None:
        assert "METASCAN | MADE BY FONDGARD 2026" in rendered_html

    def test_css_variables_preserved(self, rendered_html: str) -> None:
        """All custom CSS variables must be present in the template."""
        for var in ("--bg-dark", "--card-bg", "--card-border", "--text-color", "--accent", "--error"):
            assert var in rendered_html, f"CSS variable {var!r} is missing"

    def test_boot_animate_class_present(self, rendered_html: str) -> None:
        assert "boot-animate" in rendered_html

    def test_tactical_card_class_present(self, rendered_html: str) -> None:
        assert "tactical-card" in rendered_html

    def test_tactical_text_class_present(self, rendered_html: str) -> None:
        assert "tactical-text" in rendered_html

    def test_custom_scrollbar_css(self, rendered_html: str) -> None:
        assert "::-webkit-scrollbar" in rendered_html

    def test_details_marker_hidden(self, rendered_html: str) -> None:
        assert "::-webkit-details-marker" in rendered_html

    def test_search_bar_present(self, rendered_html: str) -> None:
        assert 'id="searchInput"' in rendered_html
        assert "filterResults()" in rendered_html

    def test_copy_to_clipboard_js_function(self, rendered_html: str) -> None:
        assert "function copyToClipboard" in rendered_html
        assert "navigator.clipboard.writeText" in rendered_html

    def test_filter_results_js_function(self, rendered_html: str) -> None:
        assert "function filterResults" in rendered_html
        assert "getElementsByClassName('result-row')" in rendered_html


# ===========================================================================
# Tests BLOCK 1: VALID RESULTS
# ===========================================================================

class TestValidResultsBlock:

    def test_target_in_header_uppercase(self, rendered_html: str) -> None:
        assert "TARGET: NICKNAME (VALID RESULTS)" in rendered_html

    def test_total_count_correct(self, rendered_html: str) -> None:
        assert "TOTAL: 2" in rendered_html

    def test_github_service_name(self, rendered_html: str) -> None:
        assert "Github" in rendered_html

    def test_github_tool_maigret(self, rendered_html: str) -> None:
        assert "Maigret" in rendered_html

    def test_github_url_present(self, rendered_html: str) -> None:
        assert "https://github.com/nickname" in rendered_html

    def test_reddit_service_name(self, rendered_html: str) -> None:
        assert "Reddit" in rendered_html

    def test_reddit_tools_merged(self, rendered_html: str) -> None:
        """Reddit found by Sherlock and Blackbird — should be 'Sherlock, Blackbird'."""
        assert "Sherlock, Blackbird" in rendered_html

    def test_reddit_url_present(self, rendered_html: str) -> None:
        assert "https://reddit.com/user/nickname" in rendered_html

    def test_github_url_data_url(self, rendered_html: str) -> None:
        assert 'data-url="https://github.com/nickname"' in rendered_html

    def test_reddit_url_data_url(self, rendered_html: str) -> None:
        assert 'data-url="https://reddit.com/user/nickname"' in rendered_html

    def test_result_row_class_present(self, rendered_html: str) -> None:
        assert "result-row" in rendered_html

    def test_grid_cols_12_layout(self, rendered_html: str) -> None:
        assert "grid-cols-12" in rendered_html

    def test_col_span_3_for_service(self, rendered_html: str) -> None:
        assert "col-span-3" in rendered_html

    def test_col_span_6_for_link(self, rendered_html: str) -> None:
        assert "col-span-6" in rendered_html

    def test_header_columns_service_tool_link(self, rendered_html: str) -> None:
        assert "SERVICE" in rendered_html
        assert "TOOL" in rendered_html
        assert "LINK" in rendered_html


# ===========================================================================
# Tests BLOCK 2: FILTERED RESULTS
# ===========================================================================

class TestFilteredResultsBlock:

    def test_filtered_results_header_with_count(self, rendered_html: str) -> None:
        assert "FILTERED RESULTS (1)" in rendered_html

    def test_steam_service_name(self, rendered_html: str) -> None:
        assert "Steam" in rendered_html

    def test_steam_tool_sherlock(self, rendered_html: str) -> None:
        # Sherlock is already tested in valid block (Reddit); verify Steam separately via URL
        assert "https://steamcommunity.com/id/nickname" in rendered_html

    def test_steam_reason_404(self, rendered_html: str) -> None:
        assert "404 Not Found" in rendered_html

    def test_filtered_reason_styled_red(self, rendered_html: str) -> None:
        """Error reason in FILTERED RESULTS block must be styled red."""
        assert "text-[#d73a49]" in rendered_html
        assert "var(--error)" in rendered_html

    def test_steam_url_data_url(self, rendered_html: str) -> None:
        assert 'data-url="https://steamcommunity.com/id/nickname"' in rendered_html

    def test_reason_column_header(self, rendered_html: str) -> None:
        assert "REASON" in rendered_html

    def test_col_span_2_used_in_filtered(self, rendered_html: str) -> None:
        assert "col-span-2" in rendered_html

    def test_details_collapsible_tag(self, rendered_html: str) -> None:
        assert "<details" in rendered_html

    def test_summary_chevron_present(self, rendered_html: str) -> None:
        assert "▼" in rendered_html

    def test_group_open_rotate_class(self, rendered_html: str) -> None:
        assert "group-open:rotate-180" in rendered_html


# ===========================================================================
# Tests BLOCK 3: RAW JSON DATA
# ===========================================================================

class TestRawJsonBlock:

    def test_raw_json_block_header(self, rendered_html: str) -> None:
        assert "RAW JSON DATA" in rendered_html

    def test_pre_tag_with_correct_classes(self, rendered_html: str) -> None:
        assert 'class="text-[10px] sm:text-xs text-gray-400 font-mono"' in rendered_html

    def test_json_target_field(self, rendered_html: str) -> None:
        assert '&#34;target&#34;' in rendered_html
        assert '&#34;nickname&#34;' in rendered_html

    def test_json_scanners_field(self, rendered_html: str) -> None:
        assert '&#34;scanners&#34;' in rendered_html
        assert '&#34;Sherlock&#34;' in rendered_html
        assert '&#34;Maigret&#34;' in rendered_html
        assert '&#34;Blackbird&#34;' in rendered_html

    def test_json_results_field(self, rendered_html: str) -> None:
        assert '&#34;results&#34;' in rendered_html

    def test_json_github_found_status(self, rendered_html: str) -> None:
        assert '&#34;Github&#34;' in rendered_html
        assert '&#34;Found&#34;' in rendered_html

    def test_json_steam_error_type(self, rendered_html: str) -> None:
        assert '&#34;Error&#34;' in rendered_html
        assert '&#34;error_type&#34;' in rendered_html
        assert '&#34;404 Not Found&#34;' in rendered_html

    def test_json_parseable(self, example_registry: ResultRegistry) -> None:
        """to_raw_json_str() must return valid JSON."""
        raw = example_registry.to_raw_json_str()
        data = json.loads(raw)

        assert data["target"] == "nickname"
        assert set(data["scanners"]) == {"Sherlock", "Maigret", "Blackbird"}
        assert data["results"]["Github"]["status"] == "Found"
        assert data["results"]["Github"]["tools"] == ["Maigret"]
        assert data["results"]["Reddit"]["tools"] == ["Sherlock", "Blackbird"]
        assert data["results"]["Steam"]["status"] == "Error"
        assert data["results"]["Steam"]["error_type"] == "404 Not Found"


# ===========================================================================
# File Output Tests
# ===========================================================================

class TestFileOutput:

    def test_file_created_at_output_path(
        self, example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        out = tmp_path / "reports" / "metascan_nickname.html"
        result = exporter.export(example_registry, out)

        assert result.exists()
        assert result.suffix == ".html"

    def test_parent_dirs_created_automatically(
        self, example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        nested = tmp_path / "deep" / "nested" / "dir" / "report.html"
        exporter.export(example_registry, nested)
        assert nested.exists()

    def test_returned_path_equals_output_path(
        self, example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        out = tmp_path / "report.html"
        returned = exporter.export(example_registry, out)
        assert returned == out.resolve()

    def test_file_encoding_utf8(
        self, example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        """File must be readable as UTF-8 without errors."""
        out = tmp_path / "report.html"
        exporter.export(example_registry, out)
        content = out.read_text(encoding="utf-8")
        assert len(content) > 0

    def test_file_content_matches_render(
        self, example_registry: ResultRegistry, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        out = tmp_path / "report.html"
        exporter.export(example_registry, out)
        assert "TARGET: NICKNAME (VALID RESULTS)" in out.read_text(encoding="utf-8")


# ===========================================================================
# Edge Cases Tests
# ===========================================================================

class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_empty_registry_shows_no_valid_placeholder(
        self, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        """Empty registry -> 'NO VALID PROFILES CONFIRMED' placeholder."""
        reg = ResultRegistry(target="ghost", scanners=["Sherlock"])
        out = tmp_path / "empty.html"
        exporter.export(reg, out)
        html = out.read_text(encoding="utf-8")

        assert "NO VALID PROFILES CONFIRMED" in html
        assert "TOTAL: 0" in html

    @pytest.mark.asyncio
    async def test_html_escaped_in_url(
        self, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        """URL with ampersand must be escaped (autoescape=True)."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        e = await reg.add_result(
            "Example",
            "https://example.com/profile?a=1&b=2",
            "Sherlock",
        )
        e.status = ValidationStatus.FOUND

        out = tmp_path / "escaped.html"
        exporter.export(reg, out)
        html = out.read_text(encoding="utf-8")

        # Jinja2 autoescape must convert & -> &amp; in the tag body
        assert "&amp;" in html

    @pytest.mark.asyncio
    async def test_reason_fallback_to_filtered(
        self, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        """If reason=None, REASON column should show 'Filtered'."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock"])
        e = await reg.add_result("NoReason", "https://noreason.com/nick", "Sherlock")
        e.status = ValidationStatus.ERROR
        e.reason = None  # explicitly None

        out = tmp_path / "noreason.html"
        exporter.export(reg, out)
        html = out.read_text(encoding="utf-8")

        assert "Filtered" in html

    @pytest.mark.asyncio
    async def test_multiple_tools_shown_in_tools_str(
        self, exporter: HtmlExporter, tmp_path: Path
    ) -> None:
        """Three tools on one profile should be displayed comma-separated."""
        reg = ResultRegistry(target="nick", scanners=["Sherlock", "Maigret", "Blackbird"])
        e = await reg.add_result("Github", "https://github.com/nick", "Sherlock")
        await reg.add_result("Github", "https://github.com/nick", "Maigret")
        await reg.add_result("Github", "https://github.com/nick", "Blackbird")
        e.status = ValidationStatus.FOUND

        out = tmp_path / "multitools.html"
        exporter.export(reg, out)
        html = out.read_text(encoding="utf-8")

        assert "Sherlock, Maigret, Blackbird" in html
