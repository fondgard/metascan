"""BaseRunner — abstract base adapter for OSINT runners."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Awaitable, Callable

from metascan.core.registry import ResultRegistry


async def _terminate_gracefully(proc: asyncio.subprocess.Process) -> None:
    """Terminate a subprocess gracefully, falling back to SIGKILL on timeout.

    Args:
        proc: Subprocess instance to terminate.
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except (ProcessLookupError, OSError):
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except (ProcessLookupError, OSError):
            pass


class BaseRunner(ABC):
    """Abstract base class for external OSINT scanner adapters."""

    name: str

    def is_available(self) -> bool:
        """Check whether the tool binary is in PATH or runnable via Python module.

        Returns:
            True if runner tool can be executed in the current environment.
        """
        if shutil.which(self.name.lower()) is not None:
            return True
        module = self._python_module()
        if module and importlib.util.find_spec(module) is not None:
            return True
        return False

    def _python_module(self) -> str | None:
        """Return the Python module name for this tool if applicable."""
        return None

    @abstractmethod
    async def run(
        self,
        username: str,
        registry: ResultRegistry,
        timeout: int = 120,
    ) -> int:
        """Execute the tool and stream findings into the registry.

        Args:
            username: Target username to investigate.
            registry: Central registry accumulating discovered profiles.
            timeout: Subprocess execution timeout in seconds.

        Returns:
            Count of findings registered by this runner.
        """

    async def _run_subprocess(
        self,
        cmd: list[str],
        registry: ResultRegistry,
        username: str,
        timeout: int,
        line_cb: Callable[[str, ResultRegistry, str], Awaitable[None]],
        cwd: str | Path | None = None,
    ) -> bytes:
        """Run external command, stream stdout in real-time and handle timeouts.

        Args:
            cmd: Command arguments list to execute.
            registry: Shared result registry.
            username: Target username.
            timeout: Timeout in seconds.
            line_cb: Async callback invoked for each line of stdout.
            cwd: Optional working directory for subprocess.

        Returns:
            Accumulated stdout bytes for downstream JSON extraction.
        """
        env = {
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            cwd=str(cwd) if cwd else None,
        )

        stdout_buf: list[bytes] = []

        async def _line_reader() -> None:
            assert proc.stdout is not None
            while True:
                try:
                    raw = await proc.stdout.readline()
                except Exception:
                    break
                if not raw:
                    break
                stdout_buf.append(raw)
                line = raw.decode(errors="replace").strip()
                await line_cb(line, registry, username)

        reader_task = asyncio.create_task(_line_reader())

        try:
            await asyncio.wait_for(proc.wait(), timeout=float(timeout))
        except asyncio.TimeoutError:
            await _terminate_gracefully(proc)

        try:
            await asyncio.wait_for(reader_task, timeout=2.0)
        except asyncio.TimeoutError:
            reader_task.cancel()
            try:
                await reader_task
            except asyncio.CancelledError:
                pass

        return b"".join(stdout_buf)
