"""Java support: lockfile readers, jar/bytecode reading, source analysis and the adapter."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from stubby.analyzers.java import JavaAdapter
from stubby.analyzers.java_ast import analyze_source
from stubby.jars import locate_jar, read_class, read_jar_classes
from stubby.lockfiles.java import parse_gradle_lockfile, parse_maven_tree, parse_pom
from stubby.models import Dependency


def class_file(name: str, calls=()) -> bytes:
    """Minimal class file whose constant pool holds the given Methodref entries."""
    pool: list[bytes] = []
    index: dict[tuple, int] = {}

    def add(entry: bytes, key: tuple) -> int:
        if key not in index:
            pool.append(entry)
            index[key] = len(pool)
        return index[key]

    def utf8(text: str) -> int:
        raw = text.encode()
        return add(b"\x01" + struct.pack(">H", len(raw)) + raw, ("u", text))

    def cls(text: str) -> int:
        return add(b"\x07" + struct.pack(">H", utf8(text)), ("c", text))

    this = cls(name)
    cls("java/lang/Object")
    for owner, method in calls:
        nat = add(b"\x0c" + struct.pack(">HH", utf8(method), utf8("()V")), ("n", method))
        add(b"\x0a" + struct.pack(">HH", cls(owner), nat), ("m", owner, method))
    head = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(pool) + 1)
    return head + b"".join(pool) + struct.pack(">HHH", 0x21, this, 2) + b"\x00" * 8


def make_jar(path: Path, classes: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as jar:
        for name, data in classes.items():
            jar.writestr(name + ".class", data)


def test_pom_resolves_properties_and_warns_on_unknown(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>g</groupId><artifactId>a</artifactId><version>1</version>
  <properties><yaml.version>1.33</yaml.version></properties>
  <dependencies>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${yaml.version}</version></dependency>
    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${missing}</version></dependency>
    <dependency><groupId>t</groupId><artifactId>u</artifactId><version>2</version><scope>test</scope></dependency>
  </dependencies>
</project>"""
    )
    parsed = parse_pom(pom)
    assert ("org.yaml", "snakeyaml", "1.33", "compile") in parsed.deps
    assert any("x:y" in w for w in parsed.warnings)
    assert all(d[1] != "y" for d in parsed.deps)


def test_maven_tree_builds_graph_and_marks_test_scope_dev(tmp_path):
    tree = tmp_path / "dependency-tree.txt"
    tree.write_text(
        "com.acme:app:jar:1.0\n"
        "+- com.acme:lib:jar:1.0:compile\n"
        "|  \\- org.yaml:snakeyaml:jar:1.33:compile\n"
        "\\- junit:junit:jar:4.13:test\n"
    )
    parsed = parse_maven_tree(tree)
    assert parsed.graph.edges["com.acme:lib"] == ["org.yaml:snakeyaml"]
    by_name = {d.name: d for d in parsed.deps}
    assert by_name["com.acme:lib"].direct and not by_name["org.yaml:snakeyaml"].direct
    assert parsed.graph.nodes["junit:junit"].dev


def test_gradle_lockfile(tmp_path):
    lock = tmp_path / "gradle.lockfile"
    lock.write_text("# comment\norg.yaml:snakeyaml:1.33=compileClasspath\nempty=\n")
    deps = parse_gradle_lockfile(lock, "implementation 'org.yaml:snakeyaml:1.33'")
    assert [(d.name, d.version, d.direct) for d in deps] == [("org.yaml:snakeyaml", "1.33", True)]


def test_purl_of_maven_dependency():
    assert Dependency("Maven", "org.yaml:snakeyaml", "1.33").purl == "pkg:maven/org.yaml/snakeyaml@1.33"


def test_read_class_lists_methods_and_classes():
    refs = read_class(class_file("a/B", [("c/D", "run"), ("c/D", "<init>")]))
    assert refs.name == "a/B"
    assert refs.methods == {("c/D", "run"), ("c/D", "<init>")}
    assert "c/D" in refs.classes
    assert read_class(b"not a class") is None


def test_locate_jar_in_maven_and_gradle_layouts(tmp_path):
    maven = tmp_path / "m"
    make_jar(maven / "org/yaml/snakeyaml/1.33/snakeyaml-1.33.jar", {"org/yaml/snakeyaml/Yaml": class_file("org/yaml/snakeyaml/Yaml")})
    gradle = tmp_path / "g"
    make_jar(gradle / "org.yaml/snakeyaml/1.33/abc123/snakeyaml-1.33.jar", {})
    assert locate_jar([maven], "org.yaml", "snakeyaml", "1.33") is not None
    assert locate_jar([gradle], "org.yaml", "snakeyaml", "1.33") is not None
    assert locate_jar([maven], "org.yaml", "snakeyaml", "9.9") is None
    assert read_jar_classes(locate_jar([maven], "org.yaml", "snakeyaml", "1.33")).classes == {"org.yaml.snakeyaml.Yaml"}


def observed(source: str):
    return [(o.kind, o.symbol, o.package) for o in analyze_source(source.encode()).observations]


def test_typed_receiver_call_is_attributed_to_its_class():
    obs = observed(
        "import org.yaml.snakeyaml.Yaml;\nclass A { void f(Yaml y) { y.load(\"x\"); } }\n"
    )
    assert ("call", "load", "org.yaml.snakeyaml.Yaml") in obs


def test_untyped_receiver_is_reported_by_name():
    obs = observed("class A { void f() { foo().bar(); var x = foo(); x.baz(); } }\n")
    assert ("maybe", "bar", None) in obs
    assert ("maybe", "baz", None) in obs


def test_wildcard_import_and_class_for_name_are_opaque():
    obs = observed("import a.b.*;\nclass A { void f(String n) throws Exception { Class.forName(n); } }\n")
    assert ("escape", "*", "a.b") in obs
    assert ("dynamic", "Class.forName", None) in obs


def make_project(tmp_path: Path, java: str, *, tree: str, libs: dict[str, dict[str, bytes]]) -> Path:
    project = tmp_path / "p"
    (project / "src").mkdir(parents=True)
    (project / "src" / "App.java").write_text(java)
    (project / "pom.xml").write_text(
        "<project><groupId>c</groupId><artifactId>app</artifactId><version>1</version></project>"
    )
    (project / "dependency-tree.txt").write_text(tree)
    for coords, classes in libs.items():
        group, artifact, version = coords.split(":")
        make_jar(project / ".m2/repository" / Path(*group.split(".")) / artifact / version / f"{artifact}-{version}.jar", classes)
    return project


YAML = {"org/yaml/snakeyaml/Yaml": class_file("org/yaml/snakeyaml/Yaml")}


def test_adapter_attributes_classes_through_jars(tmp_path):
    project = make_project(
        tmp_path,
        "package c;\nimport org.yaml.snakeyaml.Yaml;\nclass App { Object f(Yaml y) { return y.load(\"\"); } }\n",
        tree="c:app:jar:1\n\\- org.yaml:snakeyaml:jar:1.33:compile\n",
        libs={"org.yaml:snakeyaml:1.33": YAML},
    )
    adapter = JavaAdapter()
    report = adapter.analyze(project)
    assert {(e.kind, e.symbol) for e in report.by_package["org.yaml:snakeyaml"]} >= {("import", "Yaml"), ("call", "load")}
    assert not report.incomplete and not report.dynamic


def test_adapter_without_jars_is_incomplete(tmp_path):
    project = make_project(
        tmp_path,
        "package c;\nimport org.yaml.snakeyaml.Yaml;\nclass App { Yaml y; }\n",
        tree="c:app:jar:1\n\\- org.yaml:snakeyaml:jar:1.33:compile\n",
        libs={},
    )
    adapter = JavaAdapter(repository=tmp_path / "nowhere")
    assert adapter.analyze(project).incomplete
    assert any("no downloaded jars" in w for w in adapter.warnings(project))


def test_adapter_reads_dependent_bytecode(tmp_path):
    project = make_project(
        tmp_path,
        "package c;\nclass App { Object f() { return new l.Loader(); } }\n",
        tree="c:app:jar:1\n\\- l:lib:jar:1:compile\n   \\- org.yaml:snakeyaml:jar:1.33:compile\n",
        libs={
            "org.yaml:snakeyaml:1.33": YAML,
            "l:lib:1": {"l/Loader": class_file("l/Loader", [("org/yaml/snakeyaml/Yaml", "load"), ("java/lang/Class", "forName")])},
        },
    )
    adapter = JavaAdapter()
    report = adapter.analyze_package(project, "l:lib")
    assert ("call", "load") in {(e.kind, e.symbol) for e in report.by_package["org.yaml:snakeyaml"]}
    assert report.dynamic  # Class.forName inside the dependent
    assert adapter.is_installed(project, "l:lib")
    assert not adapter.is_installed(project, "x:missing")


def test_project_package_sharing_a_group_prefix_does_not_hide_a_dependency(tmp_path):
    project = make_project(
        tmp_path,
        "package com.acme;\nclass App { Object f() { return new com.acme.config.Loader(); } }\n",
        tree="com.acme:app:jar:1\n\\- com.acme:lib:jar:1:compile\n",
        libs={"com.acme:lib:1": {"com/acme/config/Loader": class_file("com/acme/config/Loader")}},
    )
    report = JavaAdapter().analyze(project)
    assert "com.acme:lib" in report.by_package
