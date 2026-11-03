"""Core data models shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote


class Verdict(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # OSV ecosystem name, e.g. "npm"
    name: str
    version: str
    direct: bool = False

    @property
    def purl(self) -> str:
        purl_type = {"npm": "npm", "PyPI": "pypi", "Maven": "maven"}.get(
            self.ecosystem, self.ecosystem.lower()
        )
        return f"pkg:{purl_type}/{quote(self.name, safe='/')}@{self.version}"


@dataclass(frozen=True)
class Evidence:
    """A place in the project source that relates to a package.

    ``kind`` is ``"import"`` (the package is loaded), ``"call"`` (a binding from
    the package is called), ``"ref"`` (a binding is used without being called) or
    ``"dynamic"`` (code the analysis cannot resolve, e.g. ``require(name)``).
    ``symbol`` is the imported or used member (``"*"`` for the whole module,
    ``"default"`` for a default import) and ``module`` the full specifier.
    """

    file: str
    line: int
    snippet: str
    kind: str = "import"
    symbol: str | None = None
    module: str | None = None


@dataclass
class Vulnerability:
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    references: list[str] = field(default_factory=list)
    fix_urls: list[str] = field(default_factory=list)  # references OSV types as FIX

    @property
    def display_id(self) -> str:
        """Prefer a CVE identifier when one exists."""
        for ident in [self.id, *self.aliases]:
            if ident.startswith("CVE-"):
                return ident
        return self.id


@dataclass
class Finding:
    dependency: Dependency
    vulnerability: Vulnerability
    verdict: Verdict = Verdict.INCONCLUSIVE
    notes: str = ""
    evidence: list[Evidence] = field(default_factory=list)
