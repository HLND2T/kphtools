---
name: rename-preprocsesor-scripts
description: Rename an IDA preprocessor finder skill in kphtools by changing its finder filename and matching config.yaml modules[].skills[].name entry. Use when a find-*.py preprocessor skill name changes, including grouped -AND- finders or names with suffixes such as -decompiles; do not use for symbol, YAML-output, or reference-artifact renames unless those are explicitly requested.
---

# Rename Preprocessor Skills

Rename a preprocessor *skill* while preserving its existing symbol targets, YAML
outputs, and dependency artifacts. In this repository, a skill name is the
`find-*.py` basename without `.py` and must exactly match the associated
`config.yaml` `modules[].skills[].name` value.

## Required Inputs

- Old skill name, without `.py`
- New skill name, without `.py`
- Whether any generated YAML artifacts or symbols should also be renamed

If only a skill rename was requested, keep `expected_output`, `expected_input`,
`symbols`, reference YAML names, and all target-symbol constants unchanged.

## Workflow

### 1. Discover the rename scope

Search the repository for the exact old skill name. Inspect the matching finder
and its `config.yaml` skill entry before editing. Also look for exact references
in tests, scripts, and documentation.

Use FastCtx `glob` to locate the finder and FastCtx `grep` to search its name;
read the exact files that will change. Stop and ask for direction if more than
one finder or `config.yaml` skill entry matches unexpectedly.

### 2. Rename the finder

Use `git mv` so Git preserves file history:

```powershell
git mv -- ida_preprocessor_scripts/find-OldSkill.py `
  ida_preprocessor_scripts/find-NewSkill.py
```

For grouped names, change only the requested part of an `-AND-` filename. Keep
unrelated target names and suffixes intact.

Do not mechanically replace symbol names inside the Python file. Usually its
content remains unchanged: `TARGET_*`, `LLM_DECOMPILE`, metadata, desired YAML
fields, and dependency policies describe produced symbols, not the finder name.
Update only an explicit embedded `find-OldSkill` reference, if present.

### 3. Synchronize config.yaml

Search `config.yaml` before editing. In the matching `modules[].skills` item,
change only the `name` value:

```yaml
# Before
- name: find-OldSkill

# After
- name: find-NewSkill
```

Keep its `expected_output` and `expected_input` lists unchanged for a
skill-only rename. Do not alter `modules[].symbols` unless the user separately
requested a produced-symbol rename.

### 4. Update real finder-name references

Update any exact `find-OldSkill` references identified in tests, commands, or
documentation. Do not change an `OldSymbol` occurrence merely because it is
produced by the renamed finder.

If the task includes artifact or symbol renames, stop treating it as a
skill-only rename and use the `create-preprocessor-scripts` workflow for the
additional `expected_output`, `expected_input`, `symbols`, reference YAML, and
LLM-dependency changes.

### 5. Verify when requested

Unless the user explicitly waives validation, perform these checks:

```powershell
uv run python -c "from pathlib import Path; import yaml; yaml.safe_load(Path('config.yaml').read_text(encoding='utf-8'))"
git diff --check
```

Confirm the new file exists, `config.yaml` has the new skill name, and an exact
repository search finds no stale old skill name. When the IDA preprocessing
environment is available, also run:

```powershell
uv run python dump_symbols.py -debug
```

Accept `success` or `absent_ok` for `find-NewSkill`; report an unavailable or
timed-out runtime validation accurately.

### 6. Commit when requested

When the user asks to deliver on `dev`, ensure the current branch is `dev`;
create it from `main` only when it does not exist. Stage only the renamed finder,
`config.yaml`, and any directly updated references. Never use `git add -A`.

```powershell
git add -- <task-related-paths>
git diff --cached --name-only
git commit -m "refactor(preprocessor): rename OldSkill to NewSkill" -m "Co-Authored-By: Codex <codex@openai.com>"
```

Do not push or open a pull request unless the user asks.

## Checklist

- [ ] Finder was renamed with `git mv`.
- [ ] New finder basename and `config.yaml` skill `name` match exactly.
- [ ] Outputs, inputs, symbols, and reference artifacts were preserved for a skill-only rename.
- [ ] Exact finder-name references were updated where applicable.
- [ ] Requested validation was completed or explicitly waived.
- [ ] Only task-related files were staged and committed to the requested branch.
