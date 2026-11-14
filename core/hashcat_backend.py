"""Pluggable hashcat engine interface.

The GUI talks to this small interface instead of directly creating a hashcat
process.  The bundled implementation is local, but a remote/HTTP engine can be
added later without changing the UI:

    class MyRemoteBackend:
        def start(self, config, outfile): ...
        def stop(self): ...
        def join(self, timeout=None): ...

Events are dictionaries/tuples placed on the supplied queue:
    ("command", list[str])
    ("log", str)
    ("status", StatusSnapshot)
    ("found", password)
    ("done", CrackResult)

The `runtime/` directory and hashcat binaries are intentionally not part of
the Git repository; configure their path in settings or place them under
runtime/hashcat locally.
"""

from __future__ import annotations

import queue
from pathlib import Path
from typing import Protocol, runtime_checkable

from .hashcat_runner import AttackConfig, HashcatRunner


@runtime_checkable
class HashcatBackend(Protocol):
    """Interface implemented by local and future remote hashcat backends."""

    name: str

    def start(self, config: AttackConfig, outfile: Path) -> None:
        ...

    def stop(self) -> None:
        ...

    def join(self, timeout: float | None = None) -> None:
        ...


class LocalHashcatBackend:
    """Runs hashcat.exe on this machine through HashcatRunner."""

    name = "local"

    def __init__(
        self,
        hashcat_dir: Path,
        events: queue.Queue,
        potfile: Path,
    ) -> None:
        self.hashcat_dir = Path(hashcat_dir)
        self.events = events
        self.potfile = Path(potfile)
        self._runner: HashcatRunner | None = None

    @property
    def runner(self) -> HashcatRunner | None:
        return self._runner

    def start(self, config: AttackConfig, outfile: Path) -> None:
        if self._runner and self._runner.is_running:
            raise RuntimeError("已有破解任务正在运行。")
        self._runner = HashcatRunner(
            self.hashcat_dir,
            self.events,
            config,
            self.potfile,
            outfile,
        )
        self._runner.start()

    def stop(self) -> None:
        if self._runner:
            self._runner.stop()

    def join(self, timeout: float | None = None) -> None:
        if self._runner:
            self._runner.join(timeout)
