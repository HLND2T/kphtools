# Download PE and PDB Symbols

[Back to README](../../README.md)

`download_symbols.py` downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server based on entries in `kphdyn.xml`.

## Usage

Arguments in brackets are optional:

```bash
uv run download_symbols.py [-xml="path/to/kphdyn.xml"] [-symboldir="path/to/symbols"] [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https://msdl.microsoft.com/download/symbols"] [-fast]
```

## Environment variables

On Linux or macOS:

```bash
export KPHTOOLS_XML="path/to/kphdyn.xml"
export KPHTOOLS_SYMBOLDIR="path/to/symbols"
```

On Windows Command Prompt:

```bat
set KPHTOOLS_XML=path/to/kphdyn.xml
set KPHTOOLS_SYMBOLDIR=path/to/symbols
```

## Example

```bash
uv run download_symbols.py -fast -symboldir="C:\\Symbols"
```

The downloaded files use this layout:

```text
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\{sha256}\ntkrnlmp.pdb
...others
```

`{sha256}` is the lowercase SHA256 hash of the PE file, for example `68d5867b5e66fce486c863c11cf69020658cadbbacbbda1e167766f236fefe78`.

Continue with [`dump_symbols.py`](dump_symbols.md) after the required PE and PDB files have been downloaded.
