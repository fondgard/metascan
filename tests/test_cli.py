"""Unit tests for MetaScan CLI changes."""

from __future__ import annotations

import re
from typer.testing import CliRunner
import metascan.cli as cli
import typer.rich_utils as ru


def test_demo_option_removed() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    assert "--demo" not in result.output

    fail_result = runner.invoke(cli.app, ["user", "--demo"])
    assert fail_result.exit_code != 0
    assert "No such option: --demo" in fail_result.output or "Error" in fail_result.output


def test_help_palette_colors_only_green_red_white() -> None:
    runner = CliRunner(env={"FORCE_COLOR": "1"})
    result = runner.invoke(cli.app, ["--help"], color=True)
    assert result.exit_code == 0

    # Ensure rich utils configuration restricts colors to green, red, white/dim/bold
    assert "green" in ru.STYLE_OPTIONS_PANEL_BORDER
    assert "green" in ru.STYLE_COMMANDS_PANEL_BORDER
    assert "green" in ru.STYLE_USAGE
    assert "green" in ru.STYLE_OPTION
    assert "green" in ru.STYLE_SWITCH
    assert ru.STYLE_TYPES in ("white", "bold white", "dim")
    assert "red" in ru.STYLE_REQUIRED_SHORT
    assert "red" in ru.STYLE_REQUIRED_LONG
    assert "red" in ru.STYLE_ERRORS_PANEL_BORDER

    # Verify no cyan (36), yellow (33), magenta (35), blue (34) in ANSI escapes
    ansi_escapes = set(re.findall(r"\x1b\[[0-9;]*m", result.stdout))
    for code in ansi_escapes:
        assert "36" not in code, f"Unexpected cyan ANSI code: {code}"
        assert "35" not in code, f"Unexpected magenta ANSI code: {code}"
        assert "33" not in code, f"Unexpected yellow ANSI code: {code}"
        assert "34" not in code, f"Unexpected blue ANSI code: {code}"


def test_validate_username_valid() -> None:
    assert cli.validate_username("testuser") == "testuser"
    assert cli.validate_username("alex.dev_99-x") == "alex.dev_99-x"
    assert cli.validate_username("@target_handle") == "target_handle"


def test_validate_username_invalid() -> None:
    import typer
    import pytest

    invalid_targets = [
        "",
        "   ",
        "-user",
        "--flag",
        "../../etc/passwd",
        r"..\..\windows\system32",
        "user/name",
        "user;id",
        "a" * 65,
    ]
    for target in invalid_targets:
        with pytest.raises(typer.Exit):
            cli.validate_username(target)
