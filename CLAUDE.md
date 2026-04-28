# CLAUDE.md

This file provides guidance for Agent Coding in this repository, using progressive disclosure.

## Serena Memories (Keep Context Compact)

1. Prefer `list_memories` to inspect the memories available for the current project. Do not read all memories by default.
2. Use `read_memory` to read a specific memory file only when needed. Load memories on demand.
3. If the memory information is insufficient or outdated, fall back to repository files or targeted lookup through ContextEngine, symbol tools, or search tools. Use `write_memory`, `edit_memory`, or `delete_memory` to maintain memory content.

## High-Level Repository Information (Prefer Relevant Memories)

The following information was summarized into Serena memories during onboarding and is not repeated here:

- Project purpose, technology stack, and key external tools: `project_overview.md`
- Directory structure and module organization: `codebase_structure.md`
- Common development commands: `suggested_commands.md`
- Code style and conventions: `style_conventions.md`
- Recommended checklist after completing a task: `task_completion.md`

## Source File Entry Points When Memories Are Insufficient (Query and Read on Demand)

- Quick overview: `README.md`
- Dependency information: `pyproject.toml`
- Main script entry points: `download_symbols.py`, `update_symbols.py`, `reverse_symbols.py`, `upload_server.py`, `migrate_symboldir.py`
- Reverse engineering related scripts: `ida/generate_mapping.py`, `ida/ida.py`
- Configuration and data: `kphdyn.xml`, `kphdyn.yaml`, `kphdyn2.yaml`, `kphdyn.official.xml`
- Large directories. Avoid reading them in full: `symbols/`, `output/`, `uploads/`

## Progressive Disclosure Guidelines

- Read memories first, then locate individual files or symbols. Do not read the entire repository at once.
- For symbol-related or binary-related directories, prefer targeted lookup on demand and avoid full scans.
- When external tools are involved, such as IDA, `llvm-pdbutil`, or symbol servers, confirm the environment and path or variable configuration first.

## Misc rules

- Always `activate_project` on agent startup.
