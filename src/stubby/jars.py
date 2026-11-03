"""Locate dependency jars and read what their bytecode references.

Source code names classes, not artifacts, so jars map classes to artifacts
(like ``RECORD`` does for Python) and the compiled code of dependents is read
from the constant pool of their ``.class`` files: every method and class a
dependent refers to is listed there, without needing its sources.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# Constant pool entry sizes (payload bytes after the tag byte); 1 (Utf8) is variable.
_FIXED = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}

JDK_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.", "org.w3c.", "org.xml.", "org.ietf.", "org.omg.")
REFLECTION = {("java/lang/Class", "forName"), ("java/lang/ClassLoader", "loadClass"), ("java/util/ServiceLoader", "load")}


@dataclass
class ClassRefs:
    name: str = ""  # internal name of the class itself
    classes: set[str] = field(default_factory=set)  # internal names of referenced classes
    methods: set[tuple[str, str]] = field(default_factory=set)  # (owner internal name, method name)


def read_class(data: bytes) -> ClassRefs | None:
    """Parse a class file's constant pool; ``None`` if it is not a class file."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    count = struct.unpack_from(">H", data, 8)[0]
    offset = 10
    utf8: dict[int, str] = {}
    class_ref: dict[int, int] = {}
    name_and_type: dict[int, int] = {}
    member_refs: list[tuple[int, int]] = []  # (class index, name-and-type index)
    index = 1
    try:
        while index < count:
            tag = data[offset]
            offset += 1
            if tag == 1:
                length = struct.unpack_from(">H", data, offset)[0]
                utf8[index] = data[offset + 2 : offset + 2 + length].decode("utf-8", errors="replace")
                offset += 2 + length
            else:
                size = _FIXED[tag]
                if tag == 7:
                    class_ref[index] = struct.unpack_from(">H", data, offset)[0]
                elif tag == 12:
                    name_and_type[index] = struct.unpack_from(">H", data, offset)[0]
                elif tag in (10, 11):
                    member_refs.append(struct.unpack_from(">HH", data, offset))
                offset += size
            index += 2 if tag in (5, 6) else 1
        this_class = struct.unpack_from(">H", data, offset + 2)[0]
    except (KeyError, struct.error, IndexError):
        return None

    refs = ClassRefs(name=utf8.get(class_ref.get(this_class, 0), ""))
    refs.classes = {utf8[i] for i in class_ref.values() if i in utf8}
    for cls_idx, nat_idx in member_refs:
        owner = utf8.get(class_ref.get(cls_idx, 0))
        name = utf8.get(name_and_type.get(nat_idx, 0))
        if owner and name:
            refs.methods.add((owner, name))
    return refs


def dotted(internal: str) -> str:
    return internal.replace("/", ".")


def candidate_repositories(project_dir: Path, extra: Path | None) -> list[Path]:
    """Places where Maven or Gradle keep downloaded jars."""
    home = Path.home()
    roots = [extra] if extra else []
    roots += [
        project_dir / ".m2" / "repository",
        home / ".m2" / "repository",
        home / ".gradle" / "caches" / "modules-2" / "files-2.1",
    ]
    return [r for r in roots if r and r.is_dir()]


def locate_jar(repositories: list[Path], group: str, artifact: str, version: str) -> Path | None:
    name = f"{artifact}-{version}.jar"
    for root in repositories:
        maven = root / Path(*group.split(".")) / artifact / version / name
        if maven.is_file():
            return maven
        gradle = sorted((root / group / artifact / version).glob(f"*/{name}"))
        if gradle:
            return gradle[0]
    return None


@dataclass
class JarInfo:
    path: Path
    classes: set[str] = field(default_factory=set)  # dotted class names

    @property
    def packages(self) -> set[str]:
        return {c.rsplit(".", 1)[0] for c in self.classes if "." in c}


def read_jar_classes(path: Path) -> JarInfo:
    info = JarInfo(path)
    try:
        with zipfile.ZipFile(path) as jar:
            for entry in jar.namelist():
                if entry.endswith(".class") and not entry.startswith("META-INF/") and "module-info" not in entry:
                    info.classes.add(dotted(entry[:-6]))
    except (OSError, zipfile.BadZipFile):
        pass
    return info


def read_jar_references(path: Path, max_bytes: int = 5_000_000) -> tuple[list[ClassRefs], bool]:
    """Class references of every class in a jar; the flag is True if anything was skipped."""
    out: list[ClassRefs] = []
    skipped = False
    try:
        with zipfile.ZipFile(path) as jar:
            for entry in jar.infolist():
                if not entry.filename.endswith(".class") or entry.filename.startswith("META-INF/"):
                    continue
                if entry.file_size > max_bytes:
                    skipped = True
                    continue
                refs = read_class(jar.read(entry))
                if refs is None:
                    skipped = True
                else:
                    out.append(refs)
    except (OSError, zipfile.BadZipFile):
        return out, True
    return out, skipped
