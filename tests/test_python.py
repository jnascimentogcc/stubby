from pathlib import Path

import pytest

from stubby import cli
from stubby.analyzers.py_ast import analyze_source
from stubby.analyzers.python import PythonAdapter
from stubby.lockfiles.python import parse_poetry_lock, parse_requirements, read_pyproject, requirement_is_direct
from stubby.models import Verdict
from stubby.pyenv import PythonEnvironment, find_site_packages, normalize
from stubby.scan import scan_project

CASES = Path(__file__).parent.parent / "benchmarks" / "cases"


def obs(code: str):
    return [(o.package, o.kind, o.symbol, o.module, o.line) for o in analyze_source(code.encode()).observations]


# -- py_ast ---------------------------------------------------------------


def test_plain_import_and_member_call():
    assert obs("import yaml\nyaml.full_load(x)\n") == [
        ("yaml", "import", "*", "yaml", 1),
        ("yaml", "call", "full_load", "yaml", 2),
    ]


def test_dotted_import_skips_the_import_path_to_find_the_member():
    result = obs("import os.path\nos.path.join('a')\n")
    assert ("os", "call", "join", "os", 2) in result


def test_aliased_dotted_import_binds_the_submodule():
    result = obs("import PIL.ImageMath as im\nim.eval('x')\n")
    assert ("PIL", "call", "eval", "PIL.ImageMath", 2) in result


def test_from_import_reports_name_and_member_of_it():
    result = obs("from PIL import ImageMath\nImageMath.eval('x')\n")
    assert ("PIL", "call", "ImageMath", "PIL", 2) in result
    assert ("PIL", "call", "eval", "PIL", 2) in result


def test_from_import_alias_and_keyword_use():
    result = obs("from yaml import load as ld, FullLoader\nld(x, Loader=FullLoader)\n")
    assert ("yaml", "call", "load", "yaml", 2) in result
    assert ("yaml", "ref", "FullLoader", "yaml", 2) in result


def test_bare_reference_of_a_from_import_is_a_possible_module():
    result = obs("from PIL import ImageMath\nregister(ImageMath)\n")
    assert ("PIL", "ref", "*", "PIL.ImageMath", 2) in result


def test_relative_imports_and_type_checking_imports_are_ignored():
    code = "from . import a\nfrom .b import c\nif TYPE_CHECKING:\n    import d\nelse:\n    import e\n"
    assert obs(code) == [("e", "import", "*", "e", 6)]


def test_star_import_and_dynamic_imports():
    code = "from q import *\n__import__('m')\n__import__(n)\nimportlib.import_module(n)\nexec(s)\n"
    assert obs(code) == [
        ("q", "escape", "*", "q", 1),
        ("m", "escape", "*", "m", 2),
        (None, "dynamic", None, None, 3),
        (None, "dynamic", None, None, 4),
        (None, "dynamic", "exec", None, 5),
    ]


def test_attribute_names_keywords_and_parameters_are_not_references():
    code = "import requests\nobj.requests\nf(requests=1)\ndef g(requests): pass\nclass requests: pass\n"
    assert obs(code) == [("requests", "import", "*", "requests", 1)]


def test_syntax_errors_are_flagged():
    assert analyze_source(b"print 'x' +\nimport yaml\n").has_syntax_errors


# -- lockfiles ------------------------------------------------------------


def test_requirements_pinned_via_includes_and_warnings(tmp_path):
    (tmp_path / "base.txt").write_text("pytz==2023.3\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        "# comment\n-r base.txt\nDjango[argon2]==4.2.0 ; python_version > '3.8'\n"
        "    # via\n    #   -r requirements.in\n    #   some-lib\n"
        "asgiref==3.7.2\n    # via django\nrequests>=2\n--index-url https://x\n",
        encoding="utf-8",
    )
    reqs = parse_requirements(tmp_path / "requirements.txt")
    by_name = {r.name: r for r in reqs.pinned}

    assert set(by_name) == {"pytz", "django", "asgiref"}
    assert by_name["django"].version == "4.2.0"
    assert requirement_is_direct(by_name["django"]) and requirement_is_direct(by_name["pytz"])
    assert not requirement_is_direct(by_name["asgiref"])
    assert len(reqs.warnings) == 1 and "requests>=2" in reqs.warnings[0]


def test_poetry_lock_graph_dev_flag_and_direct_names(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "Django"\nversion = "4.2.0"\n\n[package.dependencies]\nasgiref = ">=3"\n\n'
        '[[package]]\nname = "asgiref"\nversion = "3.7.2"\n\n'
        '[[package]]\nname = "pytest"\nversion = "8.0.0"\ncategory = "dev"\n',
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "demo"\nversion = "2.0.0"\n[tool.poetry.dependencies]\npython = "^3.9"\nDjango = "^4"\n'
        '[tool.poetry.group.dev.dependencies]\npytest = "*"\n',
        encoding="utf-8",
    )
    project = read_pyproject(tmp_path)
    deps, graph = parse_poetry_lock(tmp_path / "poetry.lock", project.direct)

    assert (project.name, project.version) == ("demo", "2.0.0")
    assert {d.name: d.direct for d in deps} == {"asgiref": False, "django": True, "pytest": True}
    assert graph.edges["django"] == ["asgiref"]
    assert graph.nodes["pytest"].dev and not graph.nodes["django"].dev
    assert [n.name for n in graph.shortest_path("asgiref")] == ["django", "asgiref"]


def test_pep621_dependencies_are_direct(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "p"\nversion = "1"\ndependencies = ["Requests>=2", "flask[async]"]\n', encoding="utf-8"
    )
    assert read_pyproject(tmp_path).direct == {"requests", "flask"}


def test_normalize_follows_pep_503():
    assert normalize("Typing_Extensions.Foo") == "typing-extensions-foo"


# -- environment ----------------------------------------------------------


def make_env(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    site = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    info = site / "Pillow-8.4.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        "Name: Pillow\nVersion: 8.4.0\nRequires-Dist: numpy\nRequires-Dist: pytest ; extra == 'tests'\n\nbody\n",
        encoding="utf-8",
    )
    (info / "RECORD").write_text(
        "PIL/__init__.py,,\nPIL/ImageMath.py,,\nPIL/_imaging.cpython-312-x86_64-linux-gnu.so,,\n"
        "Pillow-8.4.0.dist-info/METADATA,,\n../../../bin/pil,,\n__pycache__/x.pyc,,\n",
        encoding="utf-8",
    )
    for rel, text in (files or {"PIL/__init__.py": "", "PIL/ImageMath.py": ""}).items():
        (site / rel).parent.mkdir(parents=True, exist_ok=True)
        (site / rel).write_text(text, encoding="utf-8")
    return site


def test_environment_index(tmp_path):
    site = make_env(tmp_path)
    assert find_site_packages(tmp_path) == site
    env = PythonEnvironment.load(site)

    dist = env.dists["pillow"]
    assert dist.version == "8.4.0" and dist.requires == ["numpy"]  # extras are not installed
    assert dist.modules == {"PIL"}
    assert env.dists_for_module("PIL") == {"pillow"}
    assert env.is_module("PIL.ImageMath") and env.is_module("PIL") and env.is_module("PIL._imaging")
    assert not env.is_module("PIL.SafeLoader")


# -- adapter and scan -----------------------------------------------------


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_adapter_detection_and_dependencies(tmp_path):
    adapter = PythonAdapter()
    assert not adapter.detect(tmp_path)
    write(tmp_path / "requirements.txt", "pillow==8.4.0\n")
    assert adapter.detect(tmp_path)

    name, version, deps = adapter.load_dependencies(tmp_path)
    assert (name, version) == (tmp_path.name, "0.0.0")
    assert [(d.ecosystem, d.name, d.version, d.direct) for d in deps] == [("PyPI", "pillow", "8.4.0", True)]
    assert deps[0].purl == "pkg:pypi/pillow@8.4.0"
    assert any("no installed Python environment" in w for w in adapter.warnings(tmp_path))
    assert adapter.dependency_graph(tmp_path) is None  # a requirements file lists no edges


def test_adapter_maps_modules_to_distributions_and_reports_unresolved(tmp_path):
    write(tmp_path / "requirements.txt", "pillow==8.4.0\n")
    make_env(tmp_path)
    write(
        tmp_path / "app.py",
        "import os\nimport helper\nfrom PIL import ImageMath\nimport mystery\nImageMath.eval('x')\n",
    )
    write(tmp_path / "helper.py", "")

    report = PythonAdapter().analyze(tmp_path)

    assert set(report.by_package) == {"pillow"}  # stdlib `os` and local `helper` are ignored
    assert {(e.kind, e.symbol) for e in report.by_package["pillow"]} >= {("call", "eval")}
    assert [e.symbol for e in report.dynamic] == ["unresolved module mystery"]
    assert PythonAdapter().warnings(tmp_path) == []


def test_without_environment_names_are_guessed_and_the_rest_is_unresolved(tmp_path):
    write(tmp_path / "requirements.txt", "pyyaml==5.3.1\nflask==3.0.0\n")
    write(tmp_path / "app.py", "import yaml\nimport flask\nimport google.cloud\n")
    report = PythonAdapter().analyze(tmp_path)
    assert set(report.by_package) == {"pyyaml", "flask"}  # alias table and same-name match
    assert [e.symbol for e in report.dynamic] == ["unresolved module google"]


def test_analyze_package_reads_installed_code_with_site_packages_paths(tmp_path):
    write(tmp_path / "requirements.txt", "pillow==8.4.0\nnumpy==1.0\n")
    make_env(tmp_path, {"PIL/__init__.py": "import numpy\nfrom PIL import ImageMath\n", "PIL/ImageMath.py": ""})
    adapter = PythonAdapter()

    report = adapter.analyze_package(tmp_path, "pillow")

    assert adapter.is_installed(tmp_path, "pillow") and not adapter.is_installed(tmp_path, "numpy")
    assert "numpy" in report.by_package
    assert report.by_package["numpy"][0].file.endswith("site-packages/PIL/__init__.py")
    assert adapter.analyze_package(tmp_path, "numpy").incomplete  # not installed


def test_scan_site_packages_option_points_at_another_environment(tmp_path):
    project = tmp_path / "proj"
    write(project / "requirements.txt", "pillow==8.4.0\n")
    write(project / "app.py", "from PIL import Image\n")
    other = make_env(tmp_path / "elsewhere")

    class OSV:
        def vulnerabilities_for(self, deps):
            from stubby.models import Vulnerability

            return {d: [Vulnerability(id="X")] for d in deps}

    without = scan_project(project, osv=OSV())
    with_env = scan_project(project, osv=OSV(), site_packages=other)
    assert any("no installed Python environment" in w for w in without.warnings)
    assert with_env.warnings == []
    assert with_env.ecosystem == "PyPI" and with_env.findings[0].verdict is Verdict.INCONCLUSIVE


def test_cli_prints_scan_warnings(monkeypatch, tmp_path, capsys):
    from stubby.scan import ScanResult

    monkeypatch.setattr(
        cli, "scan_project", lambda path, extractor=None, site_packages=None: ScanResult("a", "1", "PyPI", [], ["be careful"])
    )
    assert cli.main(["scan", str(tmp_path)]) == 0
    assert "warning: be careful" in capsys.readouterr().err


@pytest.mark.parametrize("case_id", ["pyyaml-full-load", "django-strip-tags"])
def test_benchmark_python_cases_have_an_installed_environment(case_id):
    assert find_site_packages(CASES / case_id / "project") is not None
