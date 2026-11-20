"""Python wrapper for the MaldocTrace command-line analyzer.

The wheel ships the static MaldocTrace binary for its platform and installs it
as the ``maldoctrace`` command. This module finds that binary and runs it:

    import maldoctrace

    report = maldoctrace.analyze("sample.one")
    print(report["verdict"], report["risk_score"])

Nothing in the sample is executed; MaldocTrace only parses and emulates it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from typing import Any, Dict, Iterable, Optional

__all__ = ["__version__", "find_binary", "analyze", "analyze_bytes", "run"]

__version__ = "0.0.0"  # replaced with the release version when the wheel is built

_EXE = "maldoctrace.exe" if os.name == "nt" else "maldoctrace"


def find_binary() -> str:
    """Return the path of the MaldocTrace binary installed with this package."""
    candidates = []
    for scheme in (None, f"{os.name}_user", "posix_user", "nt_user", "osx_framework_user"):
        try:
            path = sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")
        except KeyError:
            continue
        if path:
            candidates.append(os.path.join(path, _EXE))
    # Next to the interpreter (virtual environments, pipx, uv tool).
    candidates.append(os.path.join(os.path.dirname(sys.executable), _EXE))
    for path in candidates:
        if os.path.isfile(path):
            return path
    found = shutil.which(_EXE)
    if found:
        return found
    raise FileNotFoundError(
        "MaldocTrace binary not found; reinstall the package with "
        "'pip install --force-reinstall maldoctrace'"
    )


def run(args: Iterable[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run the MaldocTrace binary with ``args`` and return the completed process."""
    return subprocess.run([find_binary(), *args], **kwargs)


def analyze(
    path: str,
    *,
    timeout: Optional[str] = None,
    passwords: Iterable[str] = (),
    extra_args: Iterable[str] = (),
) -> Dict[str, Any]:
    """Analyze the file at ``path`` and return the JSON report as a dict.

    ``timeout`` is passed as ``--timeout`` (for example ``"30s"``), each entry of
    ``passwords`` as ``--password``. A malicious verdict is not an error.
    """
    args = ["analyze", os.fspath(path), "--format", "json"]
    if timeout:
        args += ["--timeout", timeout]
    for pw in passwords:
        args += ["--password", pw]
    args += list(extra_args)
    proc = run(args, capture_output=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"maldoctrace exited with status {proc.returncode}: {msg}")
    return json.loads(proc.stdout)


def analyze_bytes(data: bytes, name: str = "sample.bin", **kwargs: Any) -> Dict[str, Any]:
    """Analyze an in-memory file. ``name`` is used as the file name in the report."""
    base = os.path.basename(name) or "sample.bin"
    with tempfile.TemporaryDirectory(prefix="maldoctrace-") as tmp:
        path = os.path.join(tmp, base)
        with open(path, "wb") as f:
            f.write(data)
        return analyze(path, **kwargs)
