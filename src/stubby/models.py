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
        name = self.name.replace(":", "/") if self.ecosystem == "Maven" else self.name  # group:artifact
        return f"pkg:{purl_type}/{quote(name, safe='/')}@{self.version}"


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

    @property
    def url(self) -> str:
        """A public page describing the vulnerability: NVD for CVEs, else the GitHub or OSV page."""
        name = self.display_id
        if name.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{name}"
        if name.startswith("GHSA-"):
            return f"https://github.com/advisories/{name}"
        return f"https://osv.dev/vulnerability/{name}"

    @property
    def description(self) -> str:
        """The advisory title, or the start of its details when it has none."""
        text = self.summary.strip() or " ".join(self.details.split())
        return text if len(text) <= 400 else text[:397].rstrip() + "..."


@dataclass
class Finding:
    dependency: Dependency
    vulnerability: Vulnerability
    verdict: Verdict = Verdict.INCONCLUSIVE
    notes: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    # Machine-readable causes of an inconclusive verdict (see REASONS in scan.py).
    reasons: list[str] = field(default_factory=list)
    dev_only: bool = False  # only reachable through development dependencies (not shipped)
