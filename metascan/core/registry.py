"""Thread-safe and async-safe deduplication store for OSINT hits."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from metascan.models import ProfileEntry, ValidationStatus


def normalize_url(url: str) -> str:
    """Return a canonical URL suitable for deduplication keys.

    Transformations applied:
    - Strip whitespace and bounding quotes.
    - Default schemeless URLs to https://.
    - Force scheme to https.
    - Remove "www." prefix from the host.
    - Lowercase only domain/host (preserve path casing for usernames).
    - Strip trailing slashes from path.
    - Drop query string and fragment.
    - Normalize platform aliases (e.g. YouTube channel /about pages).

    Args:
        url: Raw URL string.

    Returns:
        Canonical URL string.

    Examples:
        >>> normalize_url("http://www.Reddit.com/user/nickname/")
        'https://reddit.com/user/nickname'
        >>> normalize_url("HTTPS://GitHub.com/nickname")
        'https://github.com/nickname'
    """
    if not url:
        return ""

    url = url.strip().strip("'\"")
    if url.startswith("//"):
        url = "https:" + url
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    scheme = "https"

    raw_host = (parsed.hostname or "").strip()
    if raw_host.lower().startswith("www."):
        raw_host = raw_host[4:]
    host = raw_host.lower()

    port = parsed.port
    if port in (80, 443, None):
        netloc = host
    else:
        netloc = f"{host}:{port}"

    path = parsed.path.rstrip("/")
    if path == "/":
        path = ""

    if host in ("youtube.com", "m.youtube.com") and path.endswith("/about"):
        path = path[:-6].rstrip("/")

    return urlunparse((scheme, netloc, path, "", "", ""))


class ResultRegistry:
    """Central store for discovered profiles with built-in deduplication.

    Args:
        target: Target username or handle being queried.
        scanners: Ordered list of scanner names activated for this run.
    """

    def __init__(self, target: str, scanners: list[str]) -> None:
        self.target = target
        self.scanners = scanners
        self._entries_by_url: dict[str, ProfileEntry] = {}
        self._lock = asyncio.Lock()

    def __getitem__(self, key: str) -> ProfileEntry:
        norm = normalize_url(key)
        if norm in self._entries_by_url:
            return self._entries_by_url[norm]
        if key in self._entries_by_url:
            return self._entries_by_url[key]
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        norm = normalize_url(key)
        return norm in self._entries_by_url or key in self._entries_by_url

    def __len__(self) -> int:
        return len(self._entries_by_url)

    def __iter__(self):
        return iter(self._entries_by_url)

    def get(self, key: str, default: Any = None) -> ProfileEntry | None:
        """Get entry by URL key or return default if not found."""
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        """Return registry keys."""
        return self._entries_by_url.keys()

    def values(self):
        """Return registry values."""
        return self._entries_by_url.values()

    def items(self):
        """Return registry items."""
        return self._entries_by_url.items()

    def add_result_sync(
        self,
        service: str,
        url: str,
        tool_name: str | list[str] | set[str] | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        tools: list[str] | set[str] | str | None = None,
        **kwargs: Any,
    ) -> ProfileEntry:
        """Register or update a scanner hit synchronously.

        If the normalized URL already exists, updates the tools list and
        merges new metadata keys without overwriting existing data.

        Args:
            service: Display name of the service (e.g. "Github").
            url: Raw profile URL returned by runner.
            tool_name: Scanner name or collection of scanner names.
            metadata: Optional key-value metadata dict scraped from profile.
            tools: Alternative keyword argument for scanner names.
            **kwargs: Extra arguments for backwards compatibility (e.g. "tool").

        Returns:
            The created or updated ProfileEntry instance.
        """
        raw_tools = tools if tools is not None else tool_name
        if raw_tools is None and "tool" in kwargs:
            raw_tools = kwargs["tool"]

        tool_list: list[str] = []
        if isinstance(raw_tools, str):
            if raw_tools.strip():
                tool_list = [raw_tools.strip()]
        elif isinstance(raw_tools, (list, tuple, set)):
            tool_list = [str(t).strip() for t in raw_tools if str(t).strip()]

        if "youtube.com" in url.lower() and url.rstrip("/").endswith("/about"):
            url = re.sub(r"/about/?$", "", url)

        norm_url = normalize_url(url)
        incoming_meta: dict[str, Any] = metadata or {}

        if norm_url in self._entries_by_url:
            entry = self._entries_by_url[norm_url]
            if entry.url.startswith("http://") and url.startswith("https://"):
                entry.url = url
            entry.update(tools=tool_list, metadata=incoming_meta)
        else:
            entry = ProfileEntry(
                service=service,
                url=url,
                normalized_url=norm_url,
                tools=tool_list,
                metadata=dict(incoming_meta),
            )
            self._entries_by_url[norm_url] = entry

        return entry

    async def add_result(
        self,
        service: str,
        url: str,
        tool_name: str | list[str] | set[str] | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        tools: list[str] | set[str] | str | None = None,
        **kwargs: Any,
    ) -> ProfileEntry:
        """Register a scanner hit asynchronously under an asyncio lock.

        Args:
            service: Display name of the service (e.g. "Github").
            url: Raw URL returned by the runner.
            tool_name: Scanner name or collection of names.
            metadata: Optional key-value metadata scraped from profile page.
            tools: Alternative keyword argument for scanner names.
            **kwargs: Extra arguments for backwards compatibility.

        Returns:
            The created or updated ProfileEntry instance.
        """
        async with self._lock:
            return self.add_result_sync(
                service=service,
                url=url,
                tool_name=tool_name,
                metadata=metadata,
                tools=tools,
                **kwargs,
            )

    def update(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Merge entries into the registry.

        Supports positional signatures:
        - update(service, url, tools=..., metadata=...)
        - update(other_dict_or_registry)
        """
        if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], str):
            service = args[0]
            url = args[1]
            tool_name = args[2] if len(args) > 2 else kwargs.get("tool_name")
            metadata = args[3] if len(args) > 3 else kwargs.get("metadata")
            tools = kwargs.get("tools")
            return self.add_result_sync(
                service=service,
                url=url,
                tool_name=tool_name,
                metadata=metadata,
                tools=tools,
            )

        if args and isinstance(args[0], (dict, ResultRegistry)):
            other = args[0]
            items = other.values() if isinstance(other, (dict, ResultRegistry)) else other
            for item in items:
                if isinstance(item, ProfileEntry):
                    self.add_result_sync(
                        service=item.service,
                        url=item.url,
                        tools=item.tools,
                        metadata=item.metadata,
                    )
                elif isinstance(item, dict):
                    self.add_result_sync(
                        service=item.get("service", "Unknown"),
                        url=item.get("url", ""),
                        tools=item.get("tools", []),
                        metadata=item.get("metadata", {}),
                    )

    def get_valid_results(self) -> list[ProfileEntry]:
        """Return validated (FOUND) entries sorted alphabetically by service."""
        return sorted(
            (e for e in self._entries_by_url.values() if e.status == ValidationStatus.FOUND),
            key=lambda e: e.service.lower(),
        )

    def get_filtered_results(self) -> list[ProfileEntry]:
        """Return rejected (ERROR) entries sorted alphabetically by service."""
        return sorted(
            (e for e in self._entries_by_url.values() if e.status == ValidationStatus.ERROR),
            key=lambda e: e.service.lower(),
        )

    def get_pending_results(self) -> list[ProfileEntry]:
        """Return entries that have not yet undergone validation."""
        return [
            e for e in self._entries_by_url.values()
            if e.status == ValidationStatus.PENDING
        ]

    def all_entries(self) -> list[ProfileEntry]:
        """Return all profile entries regardless of status."""
        return list(self._entries_by_url.values())

    def to_raw_json_dict(self) -> dict[str, Any]:
        """Build canonical report dictionary matching the raw JSON report schema.

        Returns:
            Dictionary with target, scanners list, and results mapping.
        """
        results: dict[str, dict[str, Any]] = {}
        service_counts: dict[str, int] = {}

        for entry in self._entries_by_url.values():
            base_key = entry.service
            count = service_counts.get(base_key, 0) + 1
            service_counts[base_key] = count
            display_key = base_key if count == 1 else f"{base_key} ({count})"

            record: dict[str, Any] = {
                "url": entry.url,
                "status": entry.status.value,
                "tools": list(entry.tools),
            }
            if entry.status == ValidationStatus.ERROR and entry.reason:
                record["error_type"] = entry.reason
            if entry.metadata:
                record["metadata"] = dict(entry.metadata)

            results[display_key] = record

        return {
            "target": self.target,
            "scanners": list(self.scanners),
            "results": results,
        }

    def to_raw_json_str(self, indent: int = 2) -> str:
        """Return the canonical report as a formatted JSON string.

        Args:
            indent: Indentation level for pretty-printing.

        Returns:
            JSON string.
        """
        raw = json.dumps(self.to_raw_json_dict(), indent=indent, ensure_ascii=False)
        return raw.replace("<", "\\u003c")
