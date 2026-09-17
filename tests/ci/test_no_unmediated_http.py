"""Layer L3: there is no second way out of this process.

The read-only claim would be worth little if any module could quietly ``import
requests`` and go straight to a backend. This test walks the package with the AST and
fails the build if anything but the constrained client reaches for a network or
process primitive.

It is deliberately a *structural* test rather than a behavioural one. Behaviour tests
show that the paths you thought of are guarded; this shows there are no other paths.

If you are adding a connector and this test fails, the fix is to go through
``auditglass.policy.http.ConstrainedHTTPClient``, not to add your module to the
allowlist below. See ``docs/writing-a-connector.md``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "auditglass"

#: Modules permitted to touch the network. Exactly one, and adding to this list is a
#: change a reviewer should question.
NETWORK_MODULES = {"policy/http.py"}

FORBIDDEN_IMPORTS = {
    "httpx", "requests", "urllib3", "aiohttp", "http", "socket", "ftplib",
    "telnetlib", "smtplib", "paramiko", "pycurl", "websockets", "websocket",
    "subprocess", "multiprocessing",
}

#: ``urllib.request`` opens URLs; ``urllib.parse`` is string handling and is fine.
FORBIDDEN_SUBMODULES = {"urllib.request", "urllib.error", "http.client", "os.system"}

DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}


def _modules() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "_demo" not in p.parts)


def _relative(path: Path) -> str:
    return path.relative_to(PACKAGE).as_posix()


@pytest.mark.parametrize("path", _modules(), ids=_relative)
def test_module_does_not_import_a_network_client(path: Path):
    rel = _relative(path)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue

        for name in names:
            root = name.split(".")[0]
            offending = root in FORBIDDEN_IMPORTS or any(
                name == sub or name.startswith(sub + ".") for sub in FORBIDDEN_SUBMODULES
            )
            if not offending:
                continue
            assert rel in NETWORK_MODULES, (
                f"{rel} imports {name!r}. Only {sorted(NETWORK_MODULES)} may reach the "
                f"network; everything else must go through ConstrainedHTTPClient so "
                f"that PolicyGuard sees the request."
            )


@pytest.mark.parametrize("path", _modules(), ids=_relative)
def test_module_does_not_use_dynamic_execution(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in DANGEROUS_CALLS, (
                f"{_relative(path)} calls {node.func.id}() at line {node.lineno}"
            )


def test_the_constrained_client_refuses_redirects():
    """A 302 from an allowlisted host would otherwise carry credentials elsewhere."""
    source = (PACKAGE / "policy" / "http.py").read_text(encoding="utf-8")
    assert "follow_redirects=False" in source


def test_exactly_one_module_is_allowed_to_speak_http():
    assert len(NETWORK_MODULES) == 1


def test_the_package_contains_no_write_verbs_in_request_construction():
    """No module should be able to name a write method in an outbound request."""
    for path in _modules():
        if _relative(path) in NETWORK_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in {"DELETE", "PUT", "PATCH"}, (
                    f"{_relative(path)} line {node.lineno} contains the literal "
                    f"{node.value!r}"
                )
