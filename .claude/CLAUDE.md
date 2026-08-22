# CLAUDE.md

This file provides guidance for Agent Coding in this repository, using progressive disclosure.

## Basic Memory Knowledge Base (Keep Context Compact)

1. Prefer `search_notes` to inspect notes available in `memory/`. Do not read all notes by default.
2. Use `read_note` to read a specific note only when needed. Load notes on demand.
3. If note information is insufficient or outdated, fall back to repository files or targeted lookup through ContextEngine, symbol tools, or search tools. Use `write_note`, `edit_note`, or `delete_note` to maintain notes.

## High-Level Repository Information (Prefer Relevant Notes)

The following information was summarized into Basic Memory notes during onboarding and is not repeated here:

- Project purpose, technology stack, and key external tools: `project_overview`
- Directory structure and module organization: `codebase_structure`
- Common development commands: `suggested_commands`
- Code style and conventions: `style_conventions`
- Recommended checklist after completing a task: `task_completion`

## Source File Entry Points When Memories Are Insufficient (Query and Read on Demand)

- Quick overview: `README.md`
- Dependency information: `pyproject.toml`
- Main script entry points: `download_symbols.py`, `dump_symbols.py`, `update_symbols.py`, `upload_server.py`
- Configuration and data: `kphdyn.xml`, `config.yaml`
- Large directories. Avoid reading them in full: `symbols/`, `output/`, `uploads/`

## Progressive Disclosure Guidelines

- Read Basic Memory notes first, then locate individual files or symbols. Do not read the entire repository at once.
- For symbol-related or binary-related directories, prefer targeted lookup on demand and avoid full scans.
- When external tools are involved, such as IDA, `llvm-pdbutil`, or symbol servers, confirm the environment and path or variable configuration first.

## Explore SKILLs

- Project-level SKILLs should be explored from `.claude/skills` even when using Codex.
