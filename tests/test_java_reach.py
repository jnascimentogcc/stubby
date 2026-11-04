"""Name graph of a Java dependency, built from class files."""

from __future__ import annotations

import struct

from stubby.analyzers.java_reach import build_graph
from stubby.jars import ClassRefs, read_class


def cls(name, calls=(), classes=(), defined=(), super_name="java/lang/Object") -> ClassRefs:
    return ClassRefs(name, set(classes), set(calls), super_name, set(defined))


CTOR = "org/x/constructor/Constructor"


def test_class_reaches_what_its_constant_pool_mentions():
    g = build_graph([cls("org/x/Yaml", [(CTOR, "<init>")]), cls(CTOR), cls("org/x/Other")])
    assert "Constructor" in g.reachable({"Yaml"}) and "Constructor" not in g.reachable({"Other"})


def test_method_names_reach_the_classes_that_declare_them():
    g = build_graph([cls("org/x/Yaml", defined=["dump"]), cls("org/x/Composer", [(CTOR, "<init>")], defined=["load"]), cls(CTOR)])
    assert "Constructor" in g.reachable({"load"}) and "Constructor" not in g.reachable({"dump"})


def test_inner_classes_are_known_by_their_own_name():
    g = build_graph([cls("org/x/Outer$Inner"), cls("org/x/Yaml", classes=["org/x/Outer$Inner"])])
    assert "Inner" in g.defined and "Inner" in g.reachable({"Yaml"})


def test_reflection_matters_only_when_reached():
    g = build_graph([cls("org/x/Loader", [("java/lang/Class", "forName")]), cls("org/x/Yaml")])
    assert g.uses_dynamic_code(g.reachable({"Loader"})) and not g.uses_dynamic_code(g.reachable({"Yaml"}))


def test_skipped_or_empty_jars_are_untrusted():
    assert not build_graph([cls("a/B")], skipped=True).trusted()
    assert not build_graph([]).trusted()
    assert build_graph([cls("a/B")]).trusted()


def test_read_class_reads_the_method_table_and_superclass():
    utf = lambda s: b"\x01" + struct.pack(">H", len(s)) + s.encode()  # noqa: E731
    pool = [utf("a/B"), b"\x07\x00\x01", utf("a/Base"), b"\x07\x00\x03", utf("run"), utf("()V")]
    data = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(pool) + 1) + b"".join(pool)
    data += struct.pack(">HHHHHH", 0x21, 2, 4, 0, 0, 1) + struct.pack(">HHHH", 1, 5, 6, 0) + b"\x00\x00"
    refs = read_class(data)
    assert refs is not None and refs.name == "a/B" and refs.super_name == "a/Base"
    assert refs.defined == {"run"} and refs.complete
