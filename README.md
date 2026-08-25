# Toolkits for KPH Dynamic Data

[简体中文](README.zh-CN.md)

Several scripts are included to generate offsets for [SystemInformer](https://github.com/winsiderss/systeminformer)'s [kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml), adding your own `struct_offset` or `func_offset` entries. The symbol inventory and analysis workflow can be customized through `config.yaml`.

## Quick start

Install the [requirements](docs/en/requirements.md), then run the full pipeline:

```bash
curl -O https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml
uv run download_symbols.py -fast
uv run dump_symbols.py
uv run update_symbols.py
```

The first download may take hours. Later runs can reuse the PE, PDB, and YAML artifacts already stored under `symbols/`.

## Workflow

1. [`download_symbols.py`](docs/en/download_symbols.md) downloads PE files and matching PDB symbols from Microsoft Symbol Server.
2. [`dump_symbols.py`](docs/en/dump_symbols.md) analyzes each binary and writes per-symbol YAML artifacts plus an `artifacts.yaml` manifest next to it.
3. [`update_symbols.py`](docs/en/update_symbols.md) exports those YAML artifacts back into `kphdyn.xml`.

The default symbol layout is:

```text
symbols/<arch>/<file>.<version>/<sha256>/
```

All four scripts use `symbols` under the current working directory by default. Set `KPHTOOLS_SYMBOLDIR` to override that directory; the environment variable takes precedence over `-symboldir`.

## Documentation

- [Requirements and environment setup](docs/en/requirements.md)
- [Download PE and PDB symbols](docs/en/download_symbols.md)
- [Dump YAML artifacts](docs/en/dump_symbols.md)
- [Generate reference YAML for `LLM_DECOMPILE`](docs/en/reference_yaml.md)
- [Export YAML artifacts to `kphdyn.xml`](docs/en/update_symbols.md)
- [Synchronize symbol files with OSS](docs/en/oss_sync.md)
- [Run the upload server](docs/en/upload_server.md)
- [Run the reference Jenkins workflow on Windows](docs/en/jenkins_windows.md)
