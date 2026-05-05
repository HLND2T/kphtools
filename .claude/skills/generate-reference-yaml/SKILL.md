---
name: generate-reference-yaml
description: Use when generating kphtools LLM_DECOMPILE reference YAML for a specific ntoskrnl version and target function or code artifact, especially when the user provides a Windows binary version plus func_name or code_name.
disable-model-invocation: true
---

# Generate Reference YAML

## Overview

Generate `ida_preprocessor_scripts/references/<module>/<name>.<arch>.yaml` for a specific `ntoskrnl.exe` version by first producing the target artifact next to the binary, then auto-starting IDA MCP for that exact binary.

## Required Inputs

Require:

- `version`: exact directory suffix, for example `10.0.26100.8246`.
- Exactly one target:
  - `func_name`: function artifact name, for example `ExReferenceCallBackBlock`.
  - `code_name`: code-region artifact name, for example `PgInitContext`.

If any required input is missing, ask for it before running commands. Do not guess `version`, `func_name`, or `code_name`.

## Workflow

### 1. Dump the target version

Run the dump for amd64 and the exact version:

```bash
uv run dump_symbols.py -arch=amd64 -version="{version}" -skill="find-{func_name}/{code_name}" -force -debug
```

The expected symbol root is:

```text
symbols/amd64/ntoskrnl.exe.{version}/<sha256>/
```

For example:

```bash
uv run dump_symbols.py -arch=amd64 -version="10.0.22621.3640" -skill="find-PgInitContext" -force -debug
```

The expected output is:

```text
symbols/amd64/ntoskrnl.exe.10.0.22621.3640/5f2daf71acf4fe543809d1e5a329a5513e49074b5772d92b194045f48fbf2b9e/PgInitContext.yaml
```

### 2. Resolve the binary directory and sha256

Find the SHA directory that contains both:

- `ntoskrnl.exe`
- `{func_name}.yaml` or `{code_name}.yaml`

PowerShell example:

```powershell
Get-ChildItem "symbols/amd64/ntoskrnl.exe.{version}" -Directory |
  Where-Object {
    (Test-Path (Join-Path $_.FullName "ntoskrnl.exe")) -and
    (Test-Path (Join-Path $_.FullName "{name}.yaml"))
  } |
  Select-Object -ExpandProperty Name
```

Use the returned directory name as `{sha256}`. If zero directories match, stop and report that `dump_symbols.py` did not produce the required `{name}.yaml`. If multiple directories match, ask the user which SHA256 to use.

### 3. Generate the reference YAML

Run:

```bash
uv run python generate_reference_yaml.py -func_name="{func_name}/{code_name}" -auto_start_mcp -binary="symbols/amd64/ntoskrnl.exe.{version}/{sha256}/ntoskrnl.exe"
```

Example:


```bash
uv run python generate_reference_yaml.py -func_name="PgInitContext" -auto_start_mcp -binary="symbols/amd64/ntoskrnl.exe.10.0.22621.3640/5f2daf71acf4fe543809d1e5a329a5513e49074b5772d92b194045f48fbf2b9e/ntoskrnl.exe"
```


### 4. Verify the output

Confirm that the reference file was created under:

```text
ida_preprocessor_scripts/references/ntoskrnl/<name>.amd64.yaml
```

Read the generated YAML enough to confirm it matches the requested target:

- Function references should include a credible `func_name`, `func_rva` or `func_va`, and non-empty disassembly/procedure where available.
- Code-region references should include the requested `code_name`, a credible code RVA/VA range, and non-empty disassembly.

## Common Mistakes

- Running `generate_reference_yaml.py` before `dump_symbols.py` has produced `{name}.yaml`.
- Guessing `{sha256}` from the version path instead of resolving the actual SHA directory.
- Using a SHA directory that contains `ntoskrnl.exe` but not the requested artifact YAML.
- Using a non-amd64 binary path for this workflow.
