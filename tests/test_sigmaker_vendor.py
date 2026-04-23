"""Tests for the vendored sigmaker core (pure-Python paths only).

The full sigmaker module depends on IDA for everything that touches segments,
instructions, or xrefs. We stub idaapi with enough shape to import the module
and then exercise the pure-Python logic: formatters, SigText normalization,
SignatureParser round-trips, and the new segment-map / cross-boundary helpers
introduced to fix the concatenated-buffer EA mapping bug.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
from unittest.mock import MagicMock

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR_PATH = REPO_ROOT / "src" / "ida_multi_mcp" / "ida_mcp" / "vendor" / "sigmaker.py"


class _IdaapiStub(MagicMock):
    # WildcardPolicy IntEnum members need real ints at class-build time.
    o_void = 0
    o_reg = 1
    o_mem = 2
    o_phrase = 3
    o_displ = 4
    o_imm = 5
    o_far = 6
    o_near = 7
    o_idpspec0 = 8
    o_idpspec1 = 9
    o_idpspec2 = 10
    o_idpspec3 = 11
    o_idpspec4 = 12
    o_idpspec5 = 13
    PLFM_386 = 1
    PLFM_ARM = 2
    PLFM_MIPS = 3
    PLFM_PPC = 4
    BADADDR = 0xFFFFFFFFFFFFFFFF
    IDA_SDK_VERSION = 900


def _load_module(monkeypatch, *, strip_user_cancelled: bool = False):
    """Import a fresh copy of vendor/sigmaker.py under a unique module name
    so each test gets an isolated WildcardPolicy/ContextVar state.
    """
    idaapi = _IdaapiStub()
    idaapi.get_kernel_version = lambda: "9.0"
    if strip_user_cancelled:
        # Simulate an IDA build where neither spelling exists.
        idaapi.user_cancelled = "not-callable"
        idaapi.user_canceled = None
    else:
        idaapi.user_cancelled = lambda: False
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    mod_name = f"_vsig_test_{id(monkeypatch)}"
    spec = importlib.util.spec_from_file_location(mod_name, VENDOR_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        monkeypatch, "_vsig_module_name", mod_name, raising=False
    )
    return module


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class TestFormatters:
    def test_all_four_formats(self, monkeypatch):
        sm = _load_module(monkeypatch)
        sig = sm.Signature(
            [
                sm.SignatureByte(0xE8, False),
                sm.SignatureByte(0x00, True),
                sm.SignatureByte(0x45, False),
            ]
        )
        assert format(sig, "ida") == "E8 ? 45"
        assert format(sig, "x64dbg") == "E8 ?? 45"
        assert format(sig, "mask") == r"\xE8\x00\x45 x?x"
        assert format(sig, "bitmask") == "0xE8, 0x00, 0x45 0b101"

    def test_unknown_format_raises(self, monkeypatch):
        sm = _load_module(monkeypatch)
        sig = sm.Signature([sm.SignatureByte(0x90, False)])
        with pytest.raises(ValueError):
            format(sig, "nonsense")


# ---------------------------------------------------------------------------
# SigText.normalize
# ---------------------------------------------------------------------------


class TestSigTextNormalize:
    def test_canonical_ida_roundtrip(self, monkeypatch):
        sm = _load_module(monkeypatch)
        canonical, pattern = sm.SigText.normalize("E8 ? ? 45")
        assert canonical == "E8 ?? ?? 45"
        assert [(v, w) for v, w in pattern] == [
            (0xE8, False),
            (0x00, True),
            (0x00, True),
            (0x45, False),
        ]

    def test_odd_length_hex_padded(self, monkeypatch):
        sm = _load_module(monkeypatch)
        canonical, _ = sm.SigText.normalize("E")
        # single hex nibble -> 'E?'
        assert canonical == "E?"

    def test_mixed_nibble_wildcards(self, monkeypatch):
        sm = _load_module(monkeypatch)
        canonical, _ = sm.SigText.normalize("?A B?")
        assert canonical == "?A B?"

    def test_rejects_garbage(self, monkeypatch):
        sm = _load_module(monkeypatch)
        with pytest.raises(ValueError):
            sm.SigText.normalize("xyz")


# ---------------------------------------------------------------------------
# SignatureParser — all four input formats reduce to IDA-style
# ---------------------------------------------------------------------------


class TestSignatureParser:
    def test_ida_format(self, monkeypatch):
        sm = _load_module(monkeypatch)
        assert sm.SignatureParser.parse("E8 ? ? 45") == "E8 ? ? 45"

    def test_x64dbg_format(self, monkeypatch):
        sm = _load_module(monkeypatch)
        assert sm.SignatureParser.parse("E8 ?? ?? 45") == "E8 ? ? 45"

    def test_masked_bytes_format(self, monkeypatch):
        sm = _load_module(monkeypatch)
        assert sm.SignatureParser.parse(r"\xE8\x00\x00\x45 x??x") == "E8 ? ? 45"

    def test_bitmask_format(self, monkeypatch):
        sm = _load_module(monkeypatch)
        # 0b1001 (LSB-first) → x??x mask → wildcards at positions 1, 2
        assert (
            sm.SignatureParser.parse("0xE8, 0x00, 0x00, 0x45 0b1001")
            == "E8 ? ? 45"
        )

    def test_loose_hex_with_questionmarks(self, monkeypatch):
        sm = _load_module(monkeypatch)
        assert sm.SignatureParser.parse("48 8B 05 ? ? 00") == "48 8B 05 ? ? 00"


# ---------------------------------------------------------------------------
# InMemoryBuffer.concat_offset_to_ida_addr / match_crosses_segment_boundary
# This is the bug-fix we care about most: segments with gaps must not
# produce false EAs in the SIMD path.
# ---------------------------------------------------------------------------


@pytest.fixture
def buffer_with_two_segments(monkeypatch):
    sm = _load_module(monkeypatch)
    buf = sm.InMemoryBuffer(
        file_path=pathlib.Path("x"), mode=sm.InMemoryBuffer.LoadMode.SEGMENTS
    )
    # Seg1 @ 0x401000, size 0x100 — concat offsets 0x000..0x0FF
    # (gap 0x1000 bytes in EA space)
    # Seg2 @ 0x500000, size 0x050 — concat offsets 0x100..0x14F
    buf._seg_map = [(0, 0x401000, 0x100), (0x100, 0x500000, 0x50)]
    buf._buffer = bytearray(b"\x00" * (0x100 + 0x50))
    return buf


class TestSegmentMap:
    def test_offset_in_first_segment_maps_to_first_segment_ea(
        self, buffer_with_two_segments
    ):
        assert buffer_with_two_segments.concat_offset_to_ida_addr(0) == 0x401000
        assert buffer_with_two_segments.concat_offset_to_ida_addr(0xFF) == 0x4010FF

    def test_offset_at_segment_boundary_maps_to_second_segment_start(
        self, buffer_with_two_segments
    ):
        # This is the specific case the old code broke:
        # old: imagebase + 0x100 would give 0x401100 (inside the GAP).
        # new: 0x500000, the actual start of segment 2.
        assert (
            buffer_with_two_segments.concat_offset_to_ida_addr(0x100) == 0x500000
        )

    def test_offset_in_second_segment(self, buffer_with_two_segments):
        assert (
            buffer_with_two_segments.concat_offset_to_ida_addr(0x14F) == 0x50004F
        )

    def test_offset_past_end_returns_none(self, buffer_with_two_segments):
        assert buffer_with_two_segments.concat_offset_to_ida_addr(0x150) is None

    def test_match_fully_in_one_segment_does_not_cross(
        self, buffer_with_two_segments
    ):
        assert (
            buffer_with_two_segments.match_crosses_segment_boundary(0, 0x100)
            is False
        )
        assert (
            buffer_with_two_segments.match_crosses_segment_boundary(0x100, 0x50)
            is False
        )

    def test_match_spanning_gap_is_rejected(self, buffer_with_two_segments):
        # Match starting inside seg1, needing 1 byte more than seg1 has left:
        # byte 0x50 + length 0xB1 -> would require byte at concat offset 0x101,
        # which in reality is in seg2 — the "AA" at seg1 end + "BB" at seg2
        # start would look like a match in the concatenated buffer but doesn't
        # exist in memory.
        assert (
            buffer_with_two_segments.match_crosses_segment_boundary(0x50, 0xB1)
            is True
        )

    def test_match_exceeding_last_segment_is_rejected(
        self, buffer_with_two_segments
    ):
        assert (
            buffer_with_two_segments.match_crosses_segment_boundary(0x100, 0x51)
            is True
        )


# ---------------------------------------------------------------------------
# user_cancelled fallback — the module must load cleanly even on IDA builds
# that expose neither spelling of the function.
# ---------------------------------------------------------------------------


class TestUserCancelledResolution:
    def test_missing_callable_falls_back_to_no_op(self, monkeypatch):
        sm = _load_module(monkeypatch, strip_user_cancelled=True)
        # Should import without AttributeError, and the resolved helper
        # returns False rather than crashing.
        assert sm.idaapi_user_canceled() is False
