"""HtmlExporter — renders Jinja2 template into polished MetaScan HTML reports."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from metascan.core.registry import ResultRegistry

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class HtmlExporter:
    """Renders the standalone HTML investigation report from registry results."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )

    def export(self, registry: ResultRegistry, output_path: Path) -> Path:
        """Render report and write HTML file to destination path.

        Args:
            registry: Populated and validated ResultRegistry instance.
            output_path: Target path for the generated HTML file.

        Returns:
            Resolved absolute Path to the written report.
        """
        template = self._env.get_template("report.html.j2")

        valid_results = registry.get_valid_results()
        filtered_results = registry.get_filtered_results()
        raw_json = registry.to_raw_json_str()

        html = template.render(
            target=registry.target,
            valid_results=valid_results,
            filtered_results=filtered_results,
            raw_json=raw_json,
        )

        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

        return output_path
