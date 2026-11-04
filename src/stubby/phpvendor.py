"""Index of a Composer ``vendor/`` directory: which package provides a class.

PHP code names classes by namespace, not by package, so a name like
``Symfony\\Component\\HttpFoundation\\Request`` is mapped to ``symfony/http-foundation``
through the PSR-4/PSR-0 prefixes of ``composer.lock`` and the class map Composer
writes to ``vendor/composer/autoload_classmap.php``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .lockfiles.php import ComposerLock

SKIP_DIRS = {".git", "vendor", "node_modules", "tests", "Tests", "test", "Test", "docs", "doc", "examples", "example", "bin"}
MAX_FILES = 20000
_CLASSMAP = re.compile(r"'((?:[^'\\]|\\.)*)'\s*=>\s*\$vendorDir\s*\.\s*'/([^/']+/[^/']+)/")


def php_files(root: Path):
    """PHP source files of a directory, without tests, docs and nested vendor trees."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".php"):
                yield Path(dirpath) / name


def _key(name: str) -> str:
    return name.strip("\\").lower()


@dataclass
class PhpVendor:
    vendor: Path
    packages: set[str] = field(default_factory=set)  # installed package names
    prefixes: list[tuple[str, str]] = field(default_factory=list)  # (lowercase prefix with trailing \, package)
    classes: dict[str, str] = field(default_factory=dict)  # lowercase class name -> package

    @classmethod
    def load(cls, project_dir: Path, lock: ComposerLock) -> "PhpVendor":
        vendor = project_dir / "vendor"
        index = cls(vendor)
        for name in lock.graph.nodes:
            if (vendor / name).is_dir():
                index.packages.add(name)
        for name, entries in lock.autoload.items():
            for prefix, _ in entries:
                if prefix:
                    index.prefixes.append((prefix.lstrip("\\").lower(), name))
        index.prefixes.sort(key=lambda item: -len(item[0]))
        classmap = vendor / "composer" / "autoload_classmap.php"
        try:
            text = classmap.read_text(encoding="utf-8", errors="replace") if classmap.is_file() else ""
        except OSError:
            text = ""
        for match in _CLASSMAP.finditer(text):
            package = match.group(2).lower()
            if package in lock.graph.nodes:
                index.classes[_key(match.group(1).replace("\\\\", "\\"))] = package
        return index

    def package_of(self, fqn: str) -> str | None:
        """The package that provides ``fqn`` (a class, function or namespace), if any."""
        key = _key(fqn)
        if key in self.classes:
            return self.classes[key]
        probe = key + "\\"
        for prefix, package in self.prefixes:
            if prefix.endswith("\\"):  # PSR-4 (and namespaced PSR-0): a namespace prefix
                if probe.startswith(prefix):
                    return package
            elif prefix and key.startswith(prefix):  # PSR-0 without namespaces: Twig_Environment
                return package
        return None

    def own_prefixes(self, package: str) -> list[str]:
        return [prefix for prefix, name in self.prefixes if name == package]

    def files_of(self, package: str) -> list[Path]:
        root = self.vendor / package
        found = []
        for path in php_files(root):
            found.append(path)
            if len(found) >= MAX_FILES:
                break
        return found
