import subprocess
import unittest
from unittest import mock

import pdb_resolver


TYPES_OUTPUT = """
1000 | LF_STRUCTURE [size = 32] `_EPROCESS`
    field list: <fieldlist 0x2000>
2000 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x570, member name = `ObjectTable`

1001 | LF_STRUCTURE [size = 24] `_HANDLE_TABLE_ENTRY`
    field list: <fieldlist 0x2001>
2001 | LF_FIELDLIST
    list[0] = LF_BITFIELD, type = T_UINT8, length = 44, position = 20
    list[1] = LF_MEMBER, public, type = 0x3001, offset = 0x8, member name = `ObjectPointerBits`
"""

TYPES_OUTPUT_WITH_MULTIPLE_BITFIELDS = """
1100 | LF_STRUCTURE [size = 16] `_FLAGS`
    field list: <fieldlist 0x2100>
2100 | LF_FIELDLIST
    list[0] = LF_BITFIELD, type = T_UINT4, length = 1, position = 3
    list[1] = LF_MEMBER, public, type = 0x3100, offset = 0x4, member name = `FlagA`
    list[2] = LF_BITFIELD, type = T_UINT4, length = 2, position = 6
    list[3] = LF_MEMBER, public, type = 0x3101, offset = 0x4, member name = `FlagB`
"""

TYPES_OUTPUT_WITH_DOTTED_MEMBER = """
1200 | LF_STRUCTURE [size = 56] `_ALPC_PORT`
    field list: <fieldlist 0x2200>
2200 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = 0x3200, offset = 0x30, member name = `u1`

3200 | LF_UNION [size = 8] `_ALPC_PORT_U1`
    field list: <fieldlist 0x2201>
2201 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_UINT4, offset = 0x0, member name = `State`
"""

TYPES_OUTPUT_WITH_REAL_CANDIDATES = """
1300 | LF_STRUCTURE [size = 64] `_SECTION`
    field list: <fieldlist 0x2300>
2300 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = 0x3300, offset = 0x10, member name = `u1`

3300 | LF_UNION [size = 8] `_SECTION_U1`
    field list: <fieldlist 0x2301>
2301 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x0, member name = `OtherField`

1301 | LF_STRUCTURE [size = 32] `_SECTION_OBJECT`
    field list: <fieldlist 0x2302>
2302 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x20, member name = `Segment`
"""

TYPES_OUTPUT_WITH_DOTTED_FALLBACK_TRAP = """
1400 | LF_STRUCTURE [size = 64] `_SECTION`
    field list: <fieldlist 0x2400>
2400 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = 0x3400, offset = 0x10, member name = `u1`
    list[1] = LF_MEMBER, public, type = T_64PVOID, offset = 0x18, member name = `ControlArea`

3400 | LF_UNION [size = 8] `_SECTION_U1`
    field list: <fieldlist 0x2401>
2401 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x0, member name = `OtherField`

1401 | LF_STRUCTURE [size = 32] `_SECTION_OBJECT`
    field list: <fieldlist 0x2402>
2402 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x20, member name = `Segment`
"""

TYPES_OUTPUT_WITH_FORWARD_REF = """
1500 | LF_STRUCTURE [size = 0, forward ref] `_TOKEN`
    field list: <fieldlist 0x0>

1501 | LF_STRUCTURE [size = 48] `_TOKEN`
    field list: <fieldlist 0x2500>
2500 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_64PVOID, offset = 0x40, member name = `Privileges`
"""

TYPES_OUTPUT_WITH_BITS_FALLBACK = """
1600 | LF_STRUCTURE [size = 24] `_FIRST`
    field list: <fieldlist 0x2600>
2600 | LF_FIELDLIST
    list[0] = LF_MEMBER, public, type = T_UINT4, offset = 0x8, member name = `Flags`

1601 | LF_STRUCTURE [size = 24] `_SECOND`
    field list: <fieldlist 0x2601>
2601 | LF_FIELDLIST
    list[0] = LF_BITFIELD, type = T_UINT8, length = 2, position = 5
    list[1] = LF_MEMBER, public, type = 0x3601, offset = 0x10, member name = `Flags`
"""

PUBLICS_OUTPUT = """
Public Symbols:
0001:00045678 PspCreateProcessNotifyRoutine
0001:00012340 ExReferenceCallBackBlock
"""

PUBLICS_OUTPUT_S_PUB32 = """
Public Symbols:
     4 | S_PUB32 [size = 36] `PspCreateProcessNotifyRoutine`
           flags = none, addr = 0026:1068896
     5 | S_PUB32 [size = 44] `ExReferenceCallBackBlock`
           flags = function, addr = 0008:123456
"""

SECTIONS_OUTPUT = """
SECTION HEADER #1
  Name: .text
  VirtualSize: 0x00080000
  VirtualAddress: 0x00001000
  SizeOfRawData: 0x00080000
"""

SECTIONS_OUTPUT_S_PUB32 = """
SECTION HEADER #8
  Name: .text
  00001000 virtual address
SECTION HEADER #26
  Name: .data
  00100000 virtual address
"""


class TestPdbResolver(unittest.TestCase):
    def setUp(self) -> None:
        pdb_resolver._LLVM_PDBUTIL_CACHE.clear()

    def test_run_llvm_pdbutil_reuses_cached_dump(self) -> None:
        completed_process = subprocess.CompletedProcess(
            args=["llvm-pdbutil", "dump", "-types", "dummy.pdb"],
            returncode=0,
            stdout="cached output",
            stderr="",
        )

        with mock.patch(
            "pdb_resolver.subprocess.run",
            return_value=completed_process,
        ) as run_mock:
            first = pdb_resolver.run_llvm_pdbutil("dummy.pdb", "-types")
            second = pdb_resolver.run_llvm_pdbutil("dummy.pdb", "-types")

        self.assertEqual("cached output", first)
        self.assertEqual("cached output", second)
        self.assertEqual(1, run_mock.call_count)

    def test_run_llvm_pdbutil_decodes_section_headers_with_replace(self) -> None:
        def fake_run(*args, **kwargs):
            if kwargs.get("text"):
                raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=b"SECTION HEADER #1\n\xff\n",
                stderr=b"\xfe",
            )

        with mock.patch("pdb_resolver.subprocess.run", side_effect=fake_run):
            result = pdb_resolver.run_llvm_pdbutil(
                "dummy.pdb",
                "-section-headers",
            )

        self.assertEqual("SECTION HEADER #1\n\ufffd\n", result)

    def test_resolve_struct_offset_returns_member_offset(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_EPROCESS->ObjectTable",
            bits=False,
        )
        self.assertEqual(0x570, result["offset"])
        self.assertEqual("_EPROCESS", result["struct_name"])
        self.assertEqual("ObjectTable", result["member_name"])

    def test_resolve_struct_offset_returns_bit_offset(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_HANDLE_TABLE_ENTRY->ObjectPointerBits",
            bits=True,
        )
        self.assertEqual(0x8, result["offset"])
        self.assertEqual(20, result["bit_offset"])

    def test_resolve_struct_offset_scopes_bitfield_to_matching_member(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_MULTIPLE_BITFIELDS,
            "_FLAGS->FlagB",
            bits=True,
        )
        self.assertEqual(0x4, result["offset"])
        self.assertEqual(6, result["bit_offset"])

    def test_resolve_struct_offset_bits_falls_back_to_later_candidate(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_BITS_FALLBACK,
            "_FIRST->Flags,_SECOND->Flags",
            bits=True,
        )
        self.assertEqual("_SECOND", result["struct_name"])
        self.assertEqual("Flags", result["member_name"])
        self.assertEqual(0x10, result["offset"])
        self.assertEqual(5, result["bit_offset"])

    def test_resolve_struct_offset_supports_dotted_member(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_DOTTED_MEMBER,
            "_ALPC_PORT->u1.State",
            bits=False,
        )
        self.assertEqual("_ALPC_PORT", result["struct_name"])
        self.assertEqual("u1.State", result["member_name"])
        self.assertEqual(0x30, result["offset"])

    def test_resolve_struct_offset_uses_first_matching_candidate(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_MISSING->Field, _EPROCESS->ObjectTable",
            bits=False,
        )
        self.assertEqual("_EPROCESS", result["struct_name"])
        self.assertEqual("ObjectTable", result["member_name"])

    def test_resolve_struct_offset_supports_real_style_multi_candidate(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_REAL_CANDIDATES,
            "_SECTION->u1.ControlArea,_SECTION_OBJECT->Segment",
            bits=False,
        )
        self.assertEqual("_SECTION_OBJECT", result["struct_name"])
        self.assertEqual("Segment", result["member_name"])
        self.assertEqual(0x20, result["offset"])

    def test_resolve_struct_offset_skips_bad_dotted_candidate_with_parent_direct_match(
        self,
    ) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_DOTTED_FALLBACK_TRAP,
            "_SECTION->u1.ControlArea,_SECTION_OBJECT->Segment",
            bits=False,
        )
        self.assertEqual("_SECTION_OBJECT", result["struct_name"])
        self.assertEqual("Segment", result["member_name"])
        self.assertEqual(0x20, result["offset"])

    def test_resolve_struct_offset_skips_forward_ref_and_uses_real_definition(
        self,
    ) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT_WITH_FORWARD_REF,
            "_TOKEN->Privileges",
            bits=False,
        )
        self.assertEqual("_TOKEN", result["struct_name"])
        self.assertEqual("Privileges", result["member_name"])
        self.assertEqual(0x40, result["offset"])

    def test_resolve_gv_rva_returns_expected_value(self) -> None:
        result = pdb_resolver.resolve_public_symbol_from_text(
            PUBLICS_OUTPUT,
            SECTIONS_OUTPUT,
            "PspCreateProcessNotifyRoutine",
        )
        self.assertEqual(0x45678, result["rva"])

    def test_resolve_func_rva_returns_expected_value(self) -> None:
        result = pdb_resolver.resolve_public_symbol_from_text(
            PUBLICS_OUTPUT,
            SECTIONS_OUTPUT,
            "ExReferenceCallBackBlock",
        )
        self.assertEqual(0x12340, result["rva"])

    def test_resolve_public_symbol_supports_spub32_with_section_headers(self) -> None:
        result = pdb_resolver.resolve_public_symbol_from_text(
            PUBLICS_OUTPUT_S_PUB32,
            SECTIONS_OUTPUT_S_PUB32,
            "ExReferenceCallBackBlock",
        )
        self.assertEqual("ExReferenceCallBackBlock", result["name"])
        self.assertEqual(0x1000 + 123456, result["rva"])

    def test_resolve_public_symbol_converts_tool_failure_to_keyerror(self) -> None:
        with mock.patch(
            "pdb_resolver.run_llvm_pdbutil",
            side_effect=subprocess.CalledProcessError(
                1,
                ["llvm-pdbutil", "dump", "-publics", "dummy.pdb"],
            ),
        ):
            with self.assertRaises(KeyError):
                pdb_resolver.resolve_public_symbol("dummy.pdb", "MissingSymbol")

    def test_resolve_public_symbol_converts_timeout_to_keyerror(self) -> None:
        def fake_run(*args, **kwargs):
            self.assertEqual(300, kwargs.get("timeout"))
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        with mock.patch("pdb_resolver.subprocess.run", side_effect=fake_run):
            with self.assertRaises(KeyError):
                pdb_resolver.resolve_public_symbol("dummy.pdb", "MissingSymbol")
