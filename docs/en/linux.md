# Linux, WSL2, and cross-platform runners

[Back to README](../../README.md) · [Requirements and support boundary](requirements.md)

## Local validation

Use a Linux checkout or access the Windows checkout through `/mnt/d/kphtools`.
When sharing a checkout, keep the Linux virtual environment outside its Windows
`.venv`. Install the frozen dependencies in Linux; do not reuse Windows executables.

```bash
cd /mnt/d/kphtools
export UV_PROJECT_ENVIRONMENT="$HOME/.cache/kphtools-linux-venv"
uv sync --group ci --frozen
uv run --group ci --frozen python -m unittest discover -s tests -v
uv run --group ci --frozen python -c 'from llvm_tools import resolve_llvm_tool; print(resolve_llvm_tool("llvm-pdbutil")); print(resolve_llvm_tool("llvm-readobj"))'
```

The POSIX process tests create their own Python supervisor and listening worker.
They exercise normal shutdown, ignored SIGTERM, and an exited supervisor without
requiring IDA. They do not establish that a particular idalib-mcp installation is
working. Only processes started by kphtools receive an owned process group;
cleanup sends SIGTERM and then SIGKILL if necessary. Workers must remain in that
group; deliberately detached sessions are outside this cleanup contract.

## Analysis pipeline

Before analysis, configure the Linux IDA/Hex-Rays license, idalib, `idalib-mcp`,
and the Agent/LLM configuration required by your selected symbols. Verify that
`command -v idalib-mcp` resolves a Linux executable in the runner's environment.
The project's `uv sync` does not install or license IDA.

For an isolated working directory, run from the repository root:

```bash
export KPHTOOLS_SYMBOLDIR="$HOME/kphtools-linux-data/symbols"
mkdir -p "$HOME/kphtools-linux-data"
curl --fail --location --output "$HOME/kphtools-linux-data/kphdyn.xml" \
  https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv run --frozen python download_symbols.py "-xml=$HOME/kphtools-linux-data/kphdyn.xml" -arch=amd64
uv run --frozen python dump_symbols.py -arch=amd64 -debug
uv run --frozen python update_symbols.py "-xml=$HOME/kphtools-linux-data/kphdyn.xml"
```

Use the existing script guides for version filters and expected outputs. A real
Linux IDA run must additionally confirm fresh YAML generation, valid exported
XML, and released MCP ports after success, startup failure, and recovery.

## Self-hosted runner setup

Both workflows use `runs-on: [self-hosted, cross-platform]`. Assign the custom
`cross-platform` label only to prepared Windows/Linux runners. Each job selects
one eligible runner; this is not a two-OS test matrix. Windows steps use `pwsh`,
Linux steps use Bash. Linux does not need PowerShell.

Provision Git, uv, LLVM, curl (Linux), and the Linux or Windows IDA/Agent tooling
appropriate for that runner. Retain the existing `win64` GitHub environment:
its name is historical and both operating systems use its secrets and policies.
Shared symbol caches remain separated by `RUNNER_OS`; Linux does not automatically
reuse the Windows catalog. For Linux cache seeding, use the documented
`ci_symbol_cache.py seed` procedure with `--platform Linux` and an authoritative
input store. Preserve the fixed PR kernel input because Microsoft may no longer
serve that version. Do not enable a Linux production runner before its real
IDA analysis and required cache inputs have been checked.

PR runs retain isolated inputs, fresh YAML requirements, diagnostic uploads,
and cleanup on ordinary failure. Release jobs retain tag/nightly publication
behavior. Local tests do not validate remote S3/OSS credentials or release
permissions. Actual workflow dispatch, publication, and runner label changes
are separate operational steps.
