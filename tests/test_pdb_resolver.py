import unittest

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

PUBLICS_OUTPUT = """
Public Symbols:
0001:00045678 PspCreateProcessNotifyRoutine
0001:00012340 ExReferenceCallBackBlock
"""

SECTIONS_OUTPUT = """
SECTION HEADER #1
  Name: .text
  VirtualSize: 0x00080000
  VirtualAddress: 0x00001000
  SizeOfRawData: 0x00080000
"""


class TestPdbResolver(unittest.TestCase):
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

    def test_resolve_struct_offset_uses_first_matching_candidate(self) -> None:
        result = pdb_resolver.resolve_struct_symbol_from_text(
            TYPES_OUTPUT,
            "_MISSING->Field,_EPROCESS->ObjectTable",
            bits=False,
        )
        self.assertEqual("_EPROCESS", result["struct_name"])
        self.assertEqual("ObjectTable", result["member_name"])

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
