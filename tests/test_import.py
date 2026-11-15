"""Import every plugin module under plugins/ and check that none fails."""

import importlib
import os

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins")


def _modules():
    root = os.path.abspath(PLUGINS_DIR)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in sorted(filenames):
            if name.endswith(".py") and name != "__init__.py":
                rel = os.path.relpath(os.path.join(dirpath, name[:-3]), root)
                yield "volatility3.plugins." + rel.replace(os.sep, ".")


def test_all_plugins_import():
    names = list(_modules())
    assert names
    failures = {}
    for name in names:
        try:
            importlib.import_module(name)
        except Exception as exc:  # report every failure, not just the first
            failures[name] = repr(exc)
    assert not failures, failures
