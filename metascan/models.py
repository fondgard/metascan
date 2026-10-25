"""Pydantic v2 data models for MetaScan."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class ValidationStatus(str, Enum):
    """Lifecycle status of a discovered profile entry."""

    PENDING = "Pending"
    FOUND = "Found"
    ERROR = "Error"


class ProfileEntry(BaseModel):
    """A single discovered profile, keyed by its normalised URL.

    Attributes:
        service: Display name of the service (e.g. "Github", "Reddit").
        url: Original (or lightly cleaned) URL as returned by the runner.
        normalized_url: Canonical URL used as deduplication key in ResultRegistry.
        tools: Ordered, deduplicated list of scanner names that found this profile.
        status: Validation lifecycle status.
        reason: Human-readable rejection reason when status is ERROR.
        metadata: Key-value metadata scraped from the profile page.
    """

    service: str
    url: str
    normalized_url: str
    tools: list[str]
    status: ValidationStatus = ValidationStatus.PENDING
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def update(
        self,
        tools: list[str] | set[str] | str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Merge additional tools and metadata into this profile entry.

        Args:
            tools: Scanner name or collection of scanner names to add.
            metadata: Additional key-value metadata to merge into existing fields.
        """
        if tools:
            if isinstance(tools, str):
                tool_list = [tools]
            elif isinstance(tools, (list, tuple, set)):
                tool_list = list(tools)
            else:
                tool_list = [str(tools)]

            for t in tool_list:
                t_str = str(t).strip()
                if t_str and t_str not in self.tools:
                    self.tools.append(t_str)

        if metadata:
            for k, v in metadata.items():
                if k not in self.metadata or (
                    self.metadata[k] in (None, "", [], {}) and v not in (None, "", [], {})
                ):
                    self.metadata[k] = v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def tools_str(self) -> str:
        """Comma-separated tool list for display in reports."""
        return ", ".join(self.tools)
