"""Discover LLVM executables without hiding runner configuration errors."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil


_TOOL_ENV = {
    "llvm-pdbutil": "KPHTOOLS_LLVM_PDBUTIL",
    "llvm-readobj": "KPHTOOLS_LLVM_READOBJ",
}


class LlvmToolNotFoundError(RuntimeError):
    def __init__(self, tool: str, detail: str):
        super().__init__(
            f"LLVM tool {tool} is unavailable: {detail}. "
            f"Install LLVM (Ubuntu: apt install llvm-18), add the tool to PATH, "
            f"or set {_TOOL_ENV[tool]} to its executable path."
        )


def resolve_llvm_tool(tool: str, explicit_path: str | None = None) -> str:
    """Resolve an explicit override, a bare name, or the highest version on PATH."""
    env_name = _TOOL_ENV[tool]
    override = explicit_path if explicit_path is not None else os.environ.get(env_name)
    if override is not None:
        resolved = shutil.which(override) if override else None
        if resolved:
            return str(Path(resolved).absolute())
        source = "explicit argument" if explicit_path is not None else env_name
        raise LlvmToolNotFoundError(tool, f"{source}={override!r} is not executable")

    resolved = shutil.which(tool)
    if resolved:
        return str(Path(resolved).absolute())

    suffix = r"(?:\.exe)?" if os.name == "nt" else ""
    pattern = re.compile(re.escape(tool) + r"-(\d+)" + suffix, re.IGNORECASE if os.name == "nt" else 0)
    candidates: list[tuple[int, str]] = []
    for directory in os.get_exec_path():
        try:
            with os.scandir(directory or os.curdir) as entries:
                for entry in entries:
                    match = pattern.fullmatch(entry.name)
                    if match and entry.is_file():
                        candidates.append((int(match[1]), entry.path))
        except OSError:
            continue
    # Stable sorting retains PATH precedence for equal versions.
    for _, candidate in sorted(candidates, key=lambda item: item[0], reverse=True):
        resolved = shutil.which(os.path.abspath(candidate))
        if resolved:
            return str(Path(resolved).absolute())
    raise LlvmToolNotFoundError(tool, "no bare or numeric-version executable found on PATH")
