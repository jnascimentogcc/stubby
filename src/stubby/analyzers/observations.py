"""What a single-file analysis reports, shared by every language."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Observation:
    """One observation; the caller attaches the file path.

    ``package`` is the module's top-level name (None for code the analysis cannot
    attribute to a package); ``kind`` and ``symbol`` follow ``models.Evidence``.
    """

    package: str | None
    line: int
    kind: str
    symbol: str | None = None
    module: str | None = None


@dataclass
class FileAnalysis:
    observations: list[Observation] = field(default_factory=list)
    has_syntax_errors: bool = False
