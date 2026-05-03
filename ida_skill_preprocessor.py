from __future__ import annotations

import importlib.util
import re
from pathlib import Path


PREPROCESS_STATUS_SUCCESS = "success"
PREPROCESS_STATUS_FAILED = "failed"
PREPROCESS_STATUS_ABSENT_OK = "absent_ok"

_SCRIPT_DIR = Path(__file__).resolve().parent / "ida_preprocessor_scripts"
_PREPROCESS_EXPORT_NAME = "preprocess_skill"
_SCRIPT_ENTRY_CACHE: dict[str, object | None] = {}


def _get_preprocess_entry(skill_name: str, debug: bool = False):
    if skill_name in _SCRIPT_ENTRY_CACHE:
        return _SCRIPT_ENTRY_CACHE[skill_name]

    script_path = _SCRIPT_DIR / f"{skill_name}.py"
    if not script_path.exists():
        if debug:
            print(f"preprocess script missing for {skill_name}: {script_path}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    module_name = "ida_preprocessor_script_" + re.sub(r"[^0-9a-zA-Z_]", "_", skill_name)
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        if debug:
            print(f"failed to load preprocess script spec: {script_path}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        if debug:
            print(f"failed to import preprocess script {script_path}: {exc}")
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    preprocess_func = getattr(module, _PREPROCESS_EXPORT_NAME, None)
    if not callable(preprocess_func):
        if debug:
            print(
                f"preprocess script {script_path} does not export "
                f"{_PREPROCESS_EXPORT_NAME}"
            )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None

    _SCRIPT_ENTRY_CACHE[skill_name] = preprocess_func
    return preprocess_func


async def preprocess_single_skill_via_mcp(
    session,
    skill,
    symbol,
    binary_dir,
    pdb_path,
    debug: bool,
    llm_config,
):
    preprocess_func = _get_preprocess_entry(skill.name, debug=debug)
    if preprocess_func is None:
        return PREPROCESS_STATUS_FAILED

    return await preprocess_func(
        session=session,
        skill=skill,
        symbol=symbol,
        binary_dir=binary_dir,
        pdb_path=pdb_path,
        debug=debug,
        llm_config=llm_config,
    )
