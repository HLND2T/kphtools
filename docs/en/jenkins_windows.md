# Jenkins Workflow on Windows

[Back to README](../../README.md)

This reference workflow runs every step through Windows Command Prompt.

- The first run may take hours while PE and PDB files are downloaded.
- A typical later run takes about 20 minutes.
- The output file is `kphdyn.xml`.

## Download the latest upstream XML

```bat
@echo Download latest kphdyn.xml from upstream

powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/master/kphlib/kphdyn.xml' -OutFile kphdyn.official.xml"

copy kphdyn.official.xml kphdyn.xml /y
```

## Synchronize unmanaged binaries

```bat
@echo Sync unmanaged ntoskrnl to kphdyn.xml

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -syncfile
```

## Download PE and PDB files

```bat
@echo Download ntoskrnl exe and pdb, this may take hours for the first run

uv sync

uv run download_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -fast
```

See the [`download_symbols.py` guide](download_symbols.md) for download options and the symbol directory layout.

## Analyze symbols

```bat
@echo Analyze symbols and dump YAML artifacts

uv run dump_symbols.py -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

See the [`dump_symbols.py` guide](dump_symbols.md) for analysis and agent options.

## Export `kphdyn.xml`

```bat
@echo Update kphdyn.xml with offsets from YAML artifacts

uv run update_symbols.py -xml="%WORKSPACE%\kphdyn.xml" -symboldir="%WORKSPACE%\symbols" -configyaml="%WORKSPACE%\config.yaml"
```

See the [`update_symbols.py` guide](update_symbols.md) for exporter behavior.
