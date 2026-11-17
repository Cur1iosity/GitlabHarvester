"""
The layer rule of the glh package (docs/architecture.md, Part I).

Dependencies point one way::

    cli -> limits -> engine -> {gitlab, output} -> domain
    postprocess -> output

``ui``, ``exceptions`` and ``version`` may be used by every layer and import
nothing else from glh. A layer imports only from itself and from the layers
listed for it below; every import counts, also those inside functions and
under ``TYPE_CHECKING``. A new subpackage must be added to the table.
"""

from __future__ import annotations

import ast
from pathlib import Path

GLH = Path(__file__).resolve().parents[2] / "glh"

# Usable by every layer.
BASE = {"ui", "exceptions", "version"}

ALLOWED: dict[str, set[str]] = {
    "version": set(),
    "exceptions": set(),
    "ui": set(),
    "domain": {"exceptions"},
    "output": BASE | {"domain"},
    "gitlab": BASE | {"domain"},
    "postprocess": BASE | {"output"},
    "engine": BASE | {"domain", "gitlab", "output"},
    "limits": BASE | {"domain", "gitlab", "engine"},
    "cli": BASE | {"domain", "gitlab", "output", "postprocess", "engine", "limits"},
}
# glh/__init__.py and glh/__main__.py assemble the public API and the entry point.
ROOT_MODULES = {"__init__", "__main__"}


def layer_of(path: Path) -> str | None:
    """The layer of a module file (None for the package root modules)."""
    parts = path.relative_to(GLH).with_suffix("").parts
    if len(parts) == 1:
        return None if parts[0] in ROOT_MODULES else parts[0]
    return parts[0]


def glh_imports(path: Path) -> list[tuple[int, str]]:
    """(line, imported glh layer) of every absolute import of glh in a module."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            # `from glh import ui` names the layer in the imported name.
            names = [f"{node.module}.{alias.name}" if node.module == "glh" else node.module for alias in node.names]
        else:
            continue
        for name in names:
            parts = name.split(".")
            if parts[0] == "glh" and len(parts) > 1:
                found.append((node.lineno, parts[1]))
    return found


def modules() -> list[Path]:
    return sorted(p for p in GLH.rglob("*.py") if "__pycache__" not in p.parts)


def test_every_layer_has_a_rule():
    layers = {layer_of(path) for path in modules()} - {None}
    assert not layers - ALLOWED.keys(), f"add the new layer(s) to ALLOWED: {sorted(layers - ALLOWED.keys())}"


def test_no_relative_imports():
    # Relative imports would slip past the layer check below.
    relative = [f"{path.relative_to(GLH.parent)}:{node.lineno}"
                for path in modules()
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                if isinstance(node, ast.ImportFrom) and node.level]
    assert not relative, f"use absolute glh imports: {relative}"


def test_layers_depend_only_on_lower_layers():
    violations = []
    for path in modules():
        layer = layer_of(path)
        if layer is None:
            continue
        allowed = ALLOWED.get(layer, set()) | {layer}
        for line, imported in glh_imports(path):
            if imported not in allowed:
                violations.append(f"{path.relative_to(GLH.parent)}:{line}: {layer} -> {imported}")
    assert not violations, "imports against the layer rule:\n" + "\n".join(violations)
