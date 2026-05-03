---
name: find-AlpcpInitSystem
description: Locate ntoskrnl AlpcpInitSystem with FUNC_XREFS using the UTF-16 string L"ALPC Port" and signature byte patterns.
disable-model-invocation: true
---

# find-AlpcpInitSystem

This kphtools fallback skill corresponds to `ida_preprocessor_scripts/find-AlpcpInitSystem.py`.

It produces `AlpcpInitSystem.yaml` for the current ntoskrnl binary with:

- `category: func`
- `func_name: AlpcpInitSystem`
- `func_rva`

The primary automated path is `FUNC_XREFS` in the preprocessor script:

- UTF-16 exact string reference: `FULLMATCH:ALPC Port`
- Signature references: `41 B8 41 6C 49 6E` and `41 6C 4D 73`
