# Requirements

[Back to README](../../README.md)

## Required tools

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. Claude, Codex, or OpenCode
3. IDA Pro 9.0+
4. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
5. [idalib](https://docs.hex-rays.com/user-guide/idalib), mandatory for `ida_analyze_bin.py`
6. Clang/LLVM: `clang`, `llvm-pdbutil` (PDB types/public symbols), and `llvm-readobj` (PE exports)

LLVM lookup uses an explicit resolver argument first, then `KPHTOOLS_LLVM_PDBUTIL`
or `KPHTOOLS_LLVM_READOBJ`, then the bare executable name on `PATH`, then the
highest numeric version suffix on `PATH` (for example, `llvm-pdbutil-18`).
Overrides must name an executable or its path, without shell arguments. Invalid
overrides and missing tools stop analysis with an error even without `-debug`;
they do not trigger Agent fallback. A genuine symbol miss retains the existing
fallback behavior.

On Ubuntu 24.04, install the tools with:

```bash
sudo apt-get install clang-18 llvm-18
# Optional: select a specific LLVM installation.
export KPHTOOLS_LLVM_PDBUTIL=/usr/bin/llvm-pdbutil-18
export KPHTOOLS_LLVM_READOBJ=/usr/bin/llvm-readobj-18
```

Keep `clang` available on `PATH` for workflows that invoke it directly; automatic
version-suffix lookup applies only to the two resolvers above.

## Linux support boundary

Linux is **partially supported**. The unittest suite, real POSIX worker cleanup,
and LLVM 18 PE/PDB parsing have been exercised on Ubuntu 24.04 under WSL2.
The workflows accept Windows or Linux self-hosted runners, but a complete Linux
IDA/Hex-Rays/idalib analysis and actual Linux CI publication have not been verified.
Linux analysis requires a licensed Linux IDA/Hex-Rays installation and a working
Linux `idalib-mcp` executable on `PATH`; a Windows installation is not sufficient.
See the [Linux/WSL and runner guide](linux.md) before assigning the shared runner label.

Install the Python dependencies with:

```bash
uv sync
```
