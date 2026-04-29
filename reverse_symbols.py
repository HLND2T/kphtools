#!/usr/bin/env python3
from __future__ import annotations


def main() -> int:
    print(
        "reverse_symbols.py is deprecated.\n"
        "Use:\n"
        "  1. uv run python dump_symbols.py -symboldir <dir> -arch <amd64|arm64>\n"
        "  2. uv run python update_symbols.py -xml <kphdyn.xml> -symboldir <dir> -syncfile\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
