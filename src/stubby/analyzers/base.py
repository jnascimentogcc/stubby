"""Language adapter interface: one implementation per ecosystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..graph import DependencyGraph
from ..models import Dependency, Evidence


@dataclass
class UsageReport:
    """What project code does with its dependencies."""

    by_package: dict[str, list[Evidence]] = field(default_factory=dict)
    # Code the analysis cannot attribute to a package (dynamic require/import, eval).
    dynamic: list[Evidence] = field(default_factory=list)
    # True when some source could not be read or was too large to analyse.
    incomplete: bool = False


class LanguageAdapter(Protocol):
    ecosystem: str

    def detect(self, project_dir: Path) -> bool:
        """Return True if this adapter applies to the project."""
        ...

    def load_dependencies(self, project_dir: Path) -> tuple[str, str, list[Dependency]]:
        """Return ``(project_name, project_version, dependencies)``."""
        ...

    def analyze(self, project_dir: Path) -> UsageReport:
        """Report imports, call sites and dynamic code, grouped by package name."""
        ...

    def dependency_graph(self, project_dir: Path) -> DependencyGraph | None:
        """Who requires whom, or ``None`` when the lockfile does not say."""
        ...

    def analyze_package(self, project_dir: Path, location: str) -> UsageReport:
        """Like ``analyze`` for the installed package at ``location`` (relative to the project)."""
        ...

    def is_installed(self, project_dir: Path, location: str) -> bool:
        """Whether the package at ``location`` is installed, so its code can be inspected."""
        ...

    def warnings(self, project_dir: Path) -> list[str]:
        """Things the user should know that limit the analysis."""
        ...
