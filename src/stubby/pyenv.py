"""Index of an installed Python environment (a ``site-packages`` directory)."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

_VENV_NAMES = (".venv", "venv", "env")
_REQUIRES = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    """PEP 503 normalisation, also the form OSV and purls use."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Distribution:
    name: str  # normalised
    version: str
    root: Path  # site-packages directory
    files: list[str] = field(default_factory=list)  # RECORD paths, relative to root
    requires: list[str] = field(default_factory=list)  # normalised names of required distributions

    @property
    def modules(self) -> set[str]:
        """Importable top-level module names this distribution installs."""
        mods: set[str] = set()
        for rel in self.files:
            first = rel.replace("\\", "/").split("/")[0]
            if first.startswith("..") or first.endswith((".dist-info", ".data")) or first == "__pycache__":
                continue
            stem = first[:-3] if first.endswith(".py") else first.split(".")[0]
            if stem and stem.isidentifier():
                mods.add(stem)
        return mods

    def python_files(self) -> list[Path]:
        return [
            self.root / rel
            for rel in self.files
            if rel.endswith(".py") and not rel.startswith("..") and ".dist-info/" not in rel.replace("\\", "/")
        ]


@dataclass
class PythonEnvironment:
    site_packages: Path
    dists: dict[str, Distribution] = field(default_factory=dict)
    _module_index: dict[str, set[str]] | None = None
    _all_modules: set[str] | None = None

    @classmethod
    def load(cls, site_packages: Path) -> "PythonEnvironment":
        env = cls(site_packages)
        for info in sorted(site_packages.glob("*.dist-info")):
            dist = _read_dist(site_packages, info)
            if dist:
                env.dists[dist.name] = dist
        return env

    def dists_for_module(self, module: str) -> set[str]:
        if self._module_index is None:
            self._module_index = {}
            for dist in self.dists.values():
                for mod in dist.modules:
                    self._module_index.setdefault(mod, set()).add(dist.name)
        return self._module_index.get(module, set())

    def is_module(self, dotted: str) -> bool:
        """True if ``dotted`` (e.g. ``PIL.ImageMath``) is an installed module or package."""
        if self._all_modules is None:
            self._all_modules = set()
            for dist in self.dists.values():
                for rel in dist.files:
                    parts = rel.replace("\\", "/").split("/")
                    if parts[0].startswith("..") or parts[0].endswith((".dist-info", ".data")):
                        continue
                    if parts[-1] == "__init__.py":
                        parts = parts[:-1]
                    elif parts[-1].endswith(".py"):
                        parts[-1] = parts[-1][:-3]
                    elif "." in parts[-1]:  # compiled extension: name.cpython-312-x86_64.so
                        parts[-1] = parts[-1].split(".")[0]
                    else:
                        continue
                    # every prefix is a package
                    for i in range(1, len(parts) + 1):
                        self._all_modules.add(".".join(parts[:i]))
        return dotted in self._all_modules


def find_site_packages(project_dir: Path) -> Path | None:
    """A virtual environment inside the project (``.venv``, ``venv`` or ``env``)."""
    for name in _VENV_NAMES:
        venv = project_dir / name
        if not venv.is_dir():
            continue
        candidates = [venv / "Lib" / "site-packages", *sorted(venv.glob("lib/python*/site-packages"))]
        for candidate in candidates:
            if candidate.is_dir():
                return candidate
    return None


def _read_dist(root: Path, info: Path) -> Distribution | None:
    metadata = info / "METADATA"
    name = version = None
    requires: list[str] = []
    if metadata.is_file():
        for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line:
                break  # headers end at the first blank line
            if line.startswith("Name:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("Requires-Dist:"):
                spec = line.split(":", 1)[1].strip()
                if "extra ==" in spec or "extra==" in spec:
                    continue  # optional extras are not installed by default
                match = _REQUIRES.match(spec)
                if match:
                    requires.append(normalize(match.group(1)))
    if not name:
        stem = info.name[: -len(".dist-info")]
        name, _, version = stem.rpartition("-")
        if not name:
            return None
    files: list[str] = []
    record = info / "RECORD"
    if record.is_file():
        with record.open(encoding="utf-8", errors="replace", newline="") as handle:
            files = [row[0] for row in csv.reader(handle) if row]
    return Distribution(normalize(name), version or "", root, files, requires)
