import importlib.util
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

import ida_preprocessor_common


def _load_finder_module():
    module_path = Path("ida_preprocessor_scripts/find-MmPurgeSection.py")
    module_spec = importlib.util.spec_from_file_location(
        "test_find_mm_purge_section_module", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise RuntimeError(f"Unable to load finder module: {module_path}")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


class TestFindMmPurgeSection(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.finder = _load_finder_module()

    async def _preprocess(self):
        return await self.finder.preprocess_skill(
            session=object(),
            skill=object(),
            symbol={"name": "MmPurgeSection", "category": "func"},
            binary_dir=Path("/symbols/amd64/ntoskrnl"),
            pdb_path=None,
            debug=True,
            llm_config=None,
        )

    async def test_primary_xrefs_success_skips_alternative(self) -> None:
        preprocess_mock = AsyncMock(
            return_value=ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS
        )

        with patch.object(
            self.finder.preprocessor_common,
            "preprocess_common_skill",
            new=preprocess_mock,
        ):
            status = await self._preprocess()

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(1, preprocess_mock.await_count)
        self.assertIs(
            self.finder.FUNC_XREFS,
            preprocess_mock.await_args.kwargs["func_xrefs"],
        )

    async def test_primary_xrefs_failure_uses_successful_alternative(self) -> None:
        preprocess_mock = AsyncMock(
            side_effect=[
                ida_preprocessor_common.PREPROCESS_STATUS_FAILED,
                ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS,
            ]
        )

        with patch.object(
            self.finder.preprocessor_common,
            "preprocess_common_skill",
            new=preprocess_mock,
        ):
            status = await self._preprocess()

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_SUCCESS, status)
        self.assertEqual(2, preprocess_mock.await_count)
        self.assertIs(
            self.finder.FUNC_XREFS,
            preprocess_mock.await_args_list[0].kwargs["func_xrefs"],
        )
        self.assertIs(
            self.finder.FUNC_XREFS_ALTERNATIVE,
            preprocess_mock.await_args_list[1].kwargs["func_xrefs"],
        )

    async def test_all_xref_strategies_failure_returns_failure(self) -> None:
        preprocess_mock = AsyncMock(
            return_value=ida_preprocessor_common.PREPROCESS_STATUS_FAILED
        )

        with patch.object(
            self.finder.preprocessor_common,
            "preprocess_common_skill",
            new=preprocess_mock,
        ):
            status = await self._preprocess()

        self.assertEqual(ida_preprocessor_common.PREPROCESS_STATUS_FAILED, status)
        self.assertEqual(2, preprocess_mock.await_count)


if __name__ == "__main__":
    unittest.main()
