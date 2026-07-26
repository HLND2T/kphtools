# Toolkits for KPH Dynamic Data

Several scripts are included to generate offsets for [SystemInformer](https://github.com/winsiderss/systeminformer)'s [kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml), adding your own `struct_offset` or `func_offset` entries. The symbol inventory and analysis workflow can be customized through `config.yaml`.

## Quick start

Install the [requirements](docs/requirements.md), then run the main symbol pipeline:

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv sync
uv run download_symbols.py -fast
uv run dump_symbols.py
uv run update_symbols.py
```

The first download may take hours. Later runs can reuse the PE, PDB, and YAML artifacts already stored under `symbols/`.

## Workflow

1. [`download_symbols.py`](docs/download_symbols.md) downloads PE files and matching PDB symbols from Microsoft Symbol Server.
2. [`dump_symbols.py`](docs/dump_symbols.md) analyzes each binary and writes per-symbol YAML artifacts next to it.
3. [`update_symbols.py`](docs/update_symbols.md) exports those YAML artifacts back into `kphdyn.xml`.

The default symbol layout is:

```text
symbols/<arch>/<file>.<version>/<sha256>/
```

## Documentation

- [Requirements and environment setup](docs/requirements.md)
- [Download PE and PDB symbols](docs/download_symbols.md)
- [Dump YAML artifacts](docs/dump_symbols.md)
- [Generate reference YAML for `LLM_DECOMPILE`](docs/reference_yaml.md)
- [Export YAML artifacts to `kphdyn.xml`](docs/update_symbols.md)
- [Run the upload server](docs/upload_server.md)
- [Run the reference Jenkins workflow on Windows](docs/jenkins_windows.md)
