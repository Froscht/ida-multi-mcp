"""Vendored sigmaker core (non-UI portion).

Source: https://github.com/mahmoudimus/ida-sigmaker (MIT, v1.6.0)
Author: Mahmoud Abdelkader (@mahmoudimus)

This copy has been stripped of the Qt/IDA GUI layer (forms, popup hook,
action handler, plugin shell, clipboard helper, wait-box dialog). Only the
signature generation / searching core is kept, so ida-multi-mcp can expose
it as MCP tools without bringing in a GUI-only plugin.

Notable changes vs upstream:
- Removed: QMessageBox loader, PyQt/PySide imports, ConfigureOperandWildcardBitmaskForm,
  ConfigureOptionsForm, SignatureMakerForm, _ActionHandler, _PopupHook, SigMakerPlugin,
  PLUGIN_ENTRY, Clipboard.
- ProgressDialog replaced by a no-op context manager (no wait box, no cancel button).
  MCP calls run under idasync's own cancellation mechanism instead.
- .display() methods on result containers removed (MCP returns structured data,
  it does not print to IDA's output window or touch the clipboard).
- CheckContinuePrompt kept intact but effectively disabled by MCP callers
  (enable_continue_prompt=False), so _ask_to_continue is never reached.
"""

from __future__ import annotations

import bisect
import contextlib
import contextvars
import dataclasses
import enum
import functools
import logging
import pathlib
import re
import string
import time
import typing

import idaapi

__upstream_version__ = "1.6.0"


WILDCARD_POLICY_CTX: contextvars.ContextVar["WildcardPolicy"] = contextvars.ContextVar(
    "wildcard_policy"
)


# Optional SIMD speedup — transparently used if the upstream ``sigmaker``
# package is also installed in IDA's Python (``pip install sigmaker``).
SIMD_SPEEDUP_AVAILABLE = False
_SimdSignature = None
_simd_scan_bytes = None
with contextlib.suppress(ImportError):
    from sigmaker._speedups import simd_scan  # type: ignore

    _SimdSignature = simd_scan.Signature
    _simd_scan_bytes = simd_scan.scan_bytes
    SIMD_SPEEDUP_AVAILABLE = True


LOGGER = logging.getLogger("ida_multi_mcp.sigmaker")
DEBUGGING_MODE = False

# Wrapper for IDA's British English spelling. Some IDA builds expose
# ``user_canceled`` (American) instead; fall back to a no-op if neither is
# available so importing the whole ida_mcp package doesn't explode.
def _resolve_user_cancelled() -> typing.Callable[[], bool]:
    for name in ("user_cancelled", "user_canceled"):
        fn = getattr(idaapi, name, None)
        if callable(fn):
            return fn
    return lambda: False


idaapi_user_canceled = _resolve_user_cancelled()


# ---------------------------------------------------------------------------
# Progress / cancellation plumbing
# ---------------------------------------------------------------------------


class UserCanceledError(Exception):
    """Raised when a long-running operation is canceled."""


class ProgressReporter(typing.Protocol):
    @property
    def elapsed_time(self) -> float: ...

    def report_progress(
        self,
        *,
        message: typing.Optional[str] = None,
        metadata: typing.Optional[dict[str, typing.Any]] = None,
        **metadata_kwargs,
    ) -> None: ...

    def should_cancel(self) -> bool: ...

    def enabled(self) -> bool: ...


@dataclasses.dataclass
class ExponentialBackoffTimer:
    """Exponential-backoff schedule for periodic continue prompts."""

    initial_interval: float
    _current_interval: float = dataclasses.field(init=False)
    _next_prompt_at: float = dataclasses.field(init=False)

    def __post_init__(self):
        self._current_interval = self.initial_interval
        self._next_prompt_at = self.initial_interval

    def should_prompt(self, elapsed_time: float) -> bool:
        return elapsed_time >= self._next_prompt_at

    def acknowledge_prompt(self, current_elapsed_time: float) -> None:
        self._current_interval *= 2
        self._next_prompt_at = current_elapsed_time + self._current_interval

    @property
    def current_interval(self) -> float:
        return self._current_interval

    @property
    def next_prompt_at(self) -> float:
        return self._next_prompt_at


@dataclasses.dataclass
class CheckContinuePrompt:
    """Progress reporter with exponential-backoff prompting.

    Kept for API compatibility with the upstream SignatureMaker, but MCP
    callers disable it (enable_prompt=False) so ``_ask_to_continue`` is
    never reached on a headless/MCP run.
    """

    metadata: typing.Optional[dict[str, typing.Any]] = None
    cancel_func: typing.Optional[typing.Callable[[], typing.Any]] = None
    enable_prompt: bool = True
    prompt_interval: int = 120
    logger: typing.Optional[logging.Logger] = None

    start_time: float = dataclasses.field(init=False)
    _timer: ExponentialBackoffTimer = dataclasses.field(init=False)
    _dynamic_metadata: dict[str, typing.Any] = dataclasses.field(
        default_factory=dict, init=False, repr=False
    )
    _progress_message: typing.Optional[str] = dataclasses.field(
        default=None, init=False, repr=False
    )
    _user_canceled: bool = dataclasses.field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.start_time = time.time()
        self._timer = ExponentialBackoffTimer(initial_interval=float(self.prompt_interval))

    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time

    def report_progress(
        self,
        *,
        message: typing.Optional[str] = None,
        metadata: typing.Optional[dict[str, typing.Any]] = None,
        **metadata_kwargs,
    ) -> None:
        combined = metadata.copy() if metadata else {}
        if metadata_kwargs:
            combined.update(metadata_kwargs)
        if combined:
            self._dynamic_metadata.update(combined)
        if message is not None:
            self._progress_message = message

    def should_cancel(self) -> bool:
        if self._user_canceled:
            return True
        if self._should_prompt() and self._timer.should_prompt(self.elapsed_time):
            message = self._format_message()
            if not self._ask_to_continue(message):
                self._user_canceled = True
                if self.cancel_func is None:
                    raise UserCanceledError("User canceled")
                return True
            self._timer.acknowledge_prompt(self.elapsed_time)
        return False

    def _format_message(self, func_name: str = "Operation") -> str:
        minutes = int(self.elapsed_time // 60)
        seconds = int(self.elapsed_time % 60)
        time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
        message_lines = [f"{func_name} has been running for {time_str}.", ""]
        combined_metadata: dict[str, typing.Any] = {}
        if self.metadata:
            combined_metadata.update(self.metadata)
        if self._dynamic_metadata:
            combined_metadata.update(self._dynamic_metadata)
        if combined_metadata:
            for key, value in combined_metadata.items():
                message_lines.append(f"{key}: {value}")
            message_lines.append("")
        if self._progress_message:
            message_lines.append(self._progress_message)
            message_lines.append("")
        message_lines.append("Continue?")
        return "\n".join(message_lines)

    def _ask_to_continue(self, message: str) -> bool:
        # MCP / headless context: no interactive dialog available.
        # Fall back to IDA's built-in ask_yn which degrades gracefully.
        reply = idaapi.ask_yn(idaapi.ASKBTN_NO, message)
        return reply == idaapi.ASKBTN_YES

    def _should_prompt(self) -> bool:
        return self.enable_prompt and self.prompt_interval > 0

    def enabled(self) -> bool:
        return self.enable_prompt


class Unexpected(Exception):
    """Signature-generation failure (non-unique, data in code range, etc.)."""


@functools.total_ordering
@dataclasses.dataclass(frozen=True)
class IDAVersionInfo:
    major: int
    minor: int
    sdk_version: int

    def __eq__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) == (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) == tuple(other[:2])
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) < (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) < tuple(other[:2])
        return NotImplemented

    @staticmethod
    @functools.cache
    def ida_version() -> "IDAVersionInfo":
        version_str: str = idaapi.get_kernel_version()
        sdk_version: int = idaapi.IDA_SDK_VERSION
        major, minor = map(int, version_str.split("."))
        return IDAVersionInfo(major, minor, sdk_version)


ida_version = IDAVersionInfo.ida_version


def is_address_marked_as_code(ea: int) -> bool:
    return idaapi.is_code(idaapi.get_flags(ea))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class InMemoryBuffer:
    """Contiguous buffer over IDA segments or the input file (for SIMD scan)."""

    class LoadMode(enum.Enum):
        SEGMENTS = "segments"
        FILE = "file"

    file_path: pathlib.Path
    mode: LoadMode = dataclasses.field(default=LoadMode.SEGMENTS)
    _buffer: bytearray = dataclasses.field(
        default_factory=bytearray, init=False, repr=False
    )
    # Sorted list of (concat_offset, seg_start_ea, seg_size). Only populated in
    # SEGMENTS mode. Needed because segments can have gaps in the address space
    # (typical for PE/ELF), so `concat_offset + imagebase` does NOT equal the
    # real EA after the first segment. Downstream code must translate via
    # ``concat_offset_to_ida_addr`` and reject matches that span a gap via
    # ``match_crosses_segment_boundary``.
    _seg_map: list[tuple[int, int, int]] = dataclasses.field(
        default_factory=list, init=False, repr=False
    )

    @property
    def file_size(self) -> int:
        return idaapi.retrieve_input_file_size()

    @property
    def imagebase(self) -> int:
        return idaapi.get_imagebase()

    def _load_segments(self):
        buf = self._buffer
        seg_map = self._seg_map
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = idaapi.get_bytes(seg.start_ea, size)
            if data:
                seg_map.append((len(buf), int(seg.start_ea), len(data)))
                buf.extend(data)
            seg = idaapi.get_next_seg(seg.start_ea)

    def concat_offset_to_ida_addr(self, offset: int) -> int | None:
        """Convert a concatenated-buffer offset back to an IDA EA.

        Returns None when ``offset`` falls outside every registered segment
        (should not happen for in-buffer offsets, but guards against misuse).
        """
        if not self._seg_map:
            return None
        # Rightmost segment whose concat start is <= offset.
        keys = [entry[0] for entry in self._seg_map]
        idx = bisect.bisect_right(keys, offset) - 1
        if idx < 0:
            return None
        concat_start, seg_ea, seg_size = self._seg_map[idx]
        rel = offset - concat_start
        if rel >= seg_size:
            return None
        return seg_ea + rel

    def match_crosses_segment_boundary(self, offset: int, length: int) -> bool:
        """Return True if [offset, offset+length) spans a segment gap.

        Needed because ``_buffer`` concatenates segments without padding;
        a SIMD hit at a segment-end would otherwise report a match that does
        not actually exist in the loaded image.
        """
        if length <= 0 or not self._seg_map:
            return False
        keys = [entry[0] for entry in self._seg_map]
        idx = bisect.bisect_right(keys, offset) - 1
        if idx < 0:
            return True
        concat_start, _, seg_size = self._seg_map[idx]
        return (offset - concat_start) + length > seg_size

    def _load_input_file(self):
        if not self.file_path.exists():
            raise RuntimeError(f"Input file {self.file_path} does not exist.")
        with self.file_path.open("rb") as f:
            self._buffer = bytearray(f.read())

    @classmethod
    def load(
        cls,
        file_path: str | pathlib.Path | None = None,
        mode: "InMemoryBuffer.LoadMode" = LoadMode.SEGMENTS,
    ) -> "InMemoryBuffer":
        if file_path is None:
            file_path = idaapi.get_input_file_path()
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)
        instance = cls(file_path=file_path, mode=mode)
        if mode == cls.LoadMode.FILE:
            instance._load_input_file()
        else:
            instance._load_segments()
        return instance

    def data(self) -> memoryview:
        return memoryview(self._buffer)

    def clear(self):
        self._buffer.clear()

    def file_offset_to_ida_addr(self, file_offset: int) -> int:
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("file_offset_to_ida_addr is only valid in 'file' mode.")
        return self.imagebase + file_offset

    def ida_addr_to_file_offset(self, ida_addr: int) -> int:
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("ida_addr_to_file_offset is only valid in 'file' mode.")
        return ida_addr - self.imagebase

    def segment_offset_to_ida_addr(self, seg_offset: int) -> int:
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "segment_offset_to_ida_addr is only valid in 'segments' mode."
            )
        return self.imagebase + seg_offset

    def ida_addr_to_segment_offset(self, ida_addr: int) -> int:
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "ida_addr_to_segment_offset is only valid in 'segments' mode."
            )
        return ida_addr - self.imagebase


@dataclasses.dataclass
class SigMakerConfig:
    output_format: "SignatureType"
    wildcard_operands: bool
    continue_outside_of_function: bool
    wildcard_optimized: bool
    enable_continue_prompt: bool = True
    ask_longer_signature: bool = True
    print_top_x: int = 5
    max_single_signature_length: int = 100
    max_xref_signature_length: int = 250
    prompt_interval: int = 10


@dataclasses.dataclass(slots=True, frozen=True, repr=False)
class Match:
    address: int

    def __repr__(self) -> str:
        return f"Match(address={hex(self.address)})"

    def __str__(self) -> str:
        return hex(self.address)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__


class SignatureType(enum.Enum):
    IDA = "ida"
    x64Dbg = "x64dbg"
    Mask = "mask"
    BitMask = "bitmask"

    @classmethod
    def at(cls, index: int) -> "SignatureType":
        return list(cls.__members__.values())[index]


class SignatureByte(typing.NamedTuple):
    value: int
    is_wildcard: bool


class Signature(list[SignatureByte]):
    def add_byte_to_signature(self, address: int, is_wildcard: bool) -> None:
        byte_value = idaapi.get_byte(address)
        self.append(SignatureByte(byte_value, is_wildcard))

    def add_bytes_to_signature(
        self, address: int, count: int, is_wildcard: bool
    ) -> None:
        bytes_data = idaapi.get_bytes(address, count)
        if bytes_data:
            self.extend(SignatureByte(b, is_wildcard) for b in bytes_data)

    def trim_signature(self) -> None:
        n = len(self)
        while n > 0 and self[n - 1].is_wildcard:
            n -= 1
        del self[n:]

    def __str__(self) -> str:
        return self.__format__("")

    def __format__(self, format_spec: str) -> str:
        spec = format_spec.lower()
        try:
            formatter = FORMATTER_MAP[SignatureType(spec)]
        except KeyError:
            raise ValueError(
                f"Unknown format code '{format_spec}' for object of type 'Signature'"
            )
        return formatter.format(self)


class SignatureFormatter(typing.Protocol):
    def format(self, signature: "Signature") -> str: ...


@dataclasses.dataclass(frozen=True, slots=True)
class IdaFormatter:
    wildcard_byte: str = "?"

    def format(self, signature: "Signature") -> str:
        parts = []
        for byte in signature:
            if byte.is_wildcard:
                parts.append(self.wildcard_byte)
            else:
                parts.append(f"{byte.value:02X}")
        return " ".join(parts)


@dataclasses.dataclass(frozen=True, slots=True)
class X64DbgFormatter(IdaFormatter):
    wildcard_byte: str = "??"


@dataclasses.dataclass(frozen=True, slots=True)
class MaskedBytesFormatter:
    wildcard_byte: str = "\\x00"
    mask: str = "x"
    wildcard_mask: str = "?"

    @staticmethod
    def build_signature_parts(
        signature: "Signature",
        byte_format: str,
        wildcard_byte: str,
        mask_char: str,
        wildcard_mask_char: str,
    ) -> tuple[list[str], list[str]]:
        pattern_parts = []
        mask_parts = []
        for byte in signature:
            if byte.is_wildcard:
                pattern_parts.append(wildcard_byte)
                mask_parts.append(wildcard_mask_char)
            else:
                pattern_parts.append(byte_format.format(byte.value))
                mask_parts.append(mask_char)
        return pattern_parts, mask_parts

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = self.build_signature_parts(
            signature,
            "\\x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        return "".join(pattern_parts) + " " + "".join(mask_parts)


@dataclasses.dataclass(frozen=True, slots=True)
class ByteArrayBitmaskFormatter:
    wildcard_byte: str = "0x00"
    mask: str = "1"
    wildcard_mask: str = "0"

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = MaskedBytesFormatter.build_signature_parts(
            signature,
            "0x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        pattern_str = ", ".join(pattern_parts)
        mask_str = "".join(mask_parts)[::-1]
        return f"{pattern_str} 0b{mask_str}"


FORMATTER_MAP: typing.Dict[SignatureType, SignatureFormatter] = {
    SignatureType.IDA: IdaFormatter(),
    SignatureType.x64Dbg: X64DbgFormatter(),
    SignatureType.Mask: MaskedBytesFormatter(),
    SignatureType.BitMask: ByteArrayBitmaskFormatter(),
}


@dataclasses.dataclass(slots=True, frozen=True)
class WildcardPolicy:
    """Policy for which operand types are wildcardable (per arch)."""

    allowed_types: frozenset[int]
    _ctx = WILDCARD_POLICY_CTX

    class RarelyWildcardable(enum.IntEnum):
        VOID = idaapi.o_void
        REG = idaapi.o_reg

    class BaseKind(enum.IntEnum):
        MEM = idaapi.o_mem
        PHRASE = idaapi.o_phrase
        DISPL = idaapi.o_displ
        IMM = idaapi.o_imm
        FAR = idaapi.o_far
        NEAR = idaapi.o_near

    class X86Kind(enum.IntEnum):
        TRREG = idaapi.o_idpspec0
        DBREG = idaapi.o_idpspec1
        CRREG = idaapi.o_idpspec2
        FPREG = idaapi.o_idpspec3
        MMX = idaapi.o_idpspec4
        XMM = idaapi.o_idpspec5
        YMM = idaapi.o_idpspec5 + 1
        ZMM = idaapi.o_idpspec5 + 2
        KREG = idaapi.o_idpspec5 + 3

    class ARMKind(enum.IntEnum):
        REGLIST = idaapi.o_idpspec1
        CREGLIST = idaapi.o_idpspec2
        CREG = idaapi.o_idpspec3
        FPREGLIST = idaapi.o_idpspec4
        TEXT = idaapi.o_idpspec5
        COND = idaapi.o_idpspec5 + 1

    class MIPSKind(enum.IntEnum):
        pass

    class PPCKind(enum.IntEnum):
        SPR = idaapi.o_idpspec0
        TWOFPR = idaapi.o_idpspec1
        SHMBME = idaapi.o_idpspec2
        CRF = idaapi.o_idpspec3
        CRB = idaapi.o_idpspec4
        DCR = idaapi.o_idpspec5

    @dataclasses.dataclass(slots=True)
    class _Use:
        policy: "WildcardPolicy"
        policy_class: type["WildcardPolicy"]
        token: contextvars.Token | None = None

        def __enter__(self):
            self.token = self.policy_class.set_current(self.policy)
            return self.policy

        def __exit__(self, exc_type, exc, tb):
            if self.token is not None:
                self.policy_class.reset_current(self.token)

    @classmethod
    def for_x86(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.X86Kind))

    @classmethod
    def for_arm(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.ARMKind))

    @classmethod
    def for_mips(cls) -> "WildcardPolicy":
        return cls(frozenset({cls.BaseKind.MEM, cls.BaseKind.FAR, cls.BaseKind.NEAR}))

    @classmethod
    def for_ppc(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.PPCKind))

    @classmethod
    def default_generic(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind))

    @classmethod
    def detect_from_processor(cls) -> "WildcardPolicy":
        arch = idaapi.ph_get_id()
        if arch == idaapi.PLFM_386:
            return cls.for_x86()
        if arch == idaapi.PLFM_ARM:
            return cls.for_arm()
        if arch == idaapi.PLFM_MIPS:
            return cls.for_mips()
        if arch == idaapi.PLFM_PPC:
            return cls.for_ppc()
        return cls.default_generic()

    def allows_type(self, op_type: int) -> bool:
        return op_type in self.allowed_types

    def to_mask(self) -> int:
        return sum(1 << int(t) for t in self.allowed_types)

    @classmethod
    def from_mask(cls, mask: int) -> "WildcardPolicy":
        types = {t for t in range(0, 64) if (mask >> t) & 1}
        return cls(frozenset(types))

    @classmethod
    def current(cls) -> "WildcardPolicy":
        policy = cls._ctx.get(cls.detect_from_processor())
        cls._ctx.set(policy)
        return policy

    @classmethod
    def set_current(cls, policy: "WildcardPolicy") -> contextvars.Token:
        return cls._ctx.set(policy)

    @classmethod
    def reset_current(cls, token: contextvars.Token) -> None:
        cls._ctx.reset(token)

    @classmethod
    def use(cls, policy: "WildcardPolicy") -> "WildcardPolicy._Use":
        return cls._Use(policy, cls)


@dataclasses.dataclass(slots=True, frozen=True)
class GeneratedSignature:
    signature: Signature
    address: Match | None = None

    def __lt__(self, other) -> bool:
        if not isinstance(other, GeneratedSignature):
            return NotImplemented
        return len(self.signature) < len(other.signature)


@dataclasses.dataclass(slots=True)
class XrefGeneratedSignature:
    signatures: list[GeneratedSignature]


class SigText:
    """Signature normalizer with wildcard support ('?' per nibble)."""

    _HEX_SET = frozenset(string.hexdigits)
    _TRANS = str.maketrans(
        {
            ",": " ",
            ";": " ",
            ":": " ",
            "|": " ",
            "_": " ",
            "-": " ",
            "\t": " ",
            "\n": " ",
            "\r": " ",
            ".": "?",
        }
    )

    @staticmethod
    def _tok_is_hex(s: str) -> bool:
        return len(s) > 0 and all(c in SigText._HEX_SET for c in s)

    @staticmethod
    def _split_hex_pairs(s: str) -> list[str]:
        return [s[i : i + 2].upper() for i in range(0, len(s), 2)]

    @staticmethod
    def normalize(sig_str: str) -> tuple[str, list[tuple[int, bool]]]:
        if not sig_str:
            return "", []
        s = sig_str.translate(SigText._TRANS)
        raw = [t for t in s.split() if t]
        toks: list[str] = []
        for t in raw:
            t = t.strip()
            if t.startswith(("0x", "0X")):
                t = t[2:]
            if not t:
                continue
            toks.append(t)

        out: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]

            if t == "??":
                out.append("??")
                i += 1
                continue

            if len(t) == 2 and SigText._tok_is_hex(t):
                out.append(t.upper())
                i += 1
                continue

            if len(t) == 1 and t in SigText._HEX_SET:
                out.append((t + "?").upper())
                i += 1
                continue

            if t == "?":
                out.append("??")
                i += 1
                continue

            if SigText._tok_is_hex(t):
                if (len(t) & 1) != 0:
                    pairs = SigText._split_hex_pairs(t)
                    pairs_len = len(pairs)
                    if pairs and len(pairs[pairs_len - 1]) == 1:
                        pairs[pairs_len - 1] = "?" + pairs[pairs_len - 1]
                    out.extend(pairs)
                    i += 1
                    continue
                else:
                    out.extend(SigText._split_hex_pairs(t))
                    i += 1
                    continue

            if len(t) == 2:
                hi, lo = t[0], t[1]
                if (hi in SigText._HEX_SET or hi == "?") and (
                    lo in SigText._HEX_SET or lo == "?"
                ):
                    out.append((hi + lo).upper())
                    i += 1
                    continue

            raise ValueError(f"invalid signature token: {t!r}")

        pattern: list[tuple[int, bool]] = []
        for tok in out:
            hi, lo = tok[0], tok[1]
            wild = (hi == "?") or (lo == "?")
            hv = 0 if hi == "?" else int(hi, 16)
            lv = 0 if lo == "?" else int(lo, 16)
            pattern.append(((hv << 4) | lv, wild))

        return " ".join(out), pattern


# ---------------------------------------------------------------------------
# Signature generation
# ---------------------------------------------------------------------------


class OperandProcessor:
    """Handles operand processing for signature generation (policy-driven)."""

    def __init__(self):
        self._is_arm = self._check_is_arm()

    @staticmethod
    def _check_is_arm() -> bool:
        return idaapi.ph_get_id() == idaapi.PLFM_ARM

    def _get_operand_offset_arm(
        self, ins: idaapi.insn_t, off: typing.List[int], length: typing.List[int]
    ) -> bool:
        policy = WildcardPolicy.current()
        for op in ins:
            if op.type in policy.allowed_types:
                off[0] = op.offb
                length[0] = 3 if ins.size == 4 else (7 if ins.size == 8 else 0)
                return True
        return False

    def get_operand(
        self,
        ins: idaapi.insn_t,
        off: typing.List[int],
        length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        policy = WildcardPolicy.current()
        if self._is_arm:
            return self._get_operand_offset_arm(ins, off, length)
        for op in ins:
            if op.type == idaapi.o_void:
                continue
            if not policy.allows_type(op.type):
                continue
            if op.offb == 0 and not wildcard_optimized:
                continue
            off[0] = op.offb
            length[0] = ins.size - op.offb
            return True
        return False


class InstructionProcessor:
    def __init__(self, operand_processor: OperandProcessor):
        self.operand_processor = operand_processor

    def append_instruction_to_sig(
        self,
        sig: Signature,
        ea: int,
        ins: idaapi.insn_t,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> None:
        if not wildcard_operands:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        off, length = [0], [0]
        has_operand = self.operand_processor.get_operand(
            ins, off, length, wildcard_optimized
        )
        if not has_operand or length[0] <= 0:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        if off[0] > 0:
            sig.add_bytes_to_signature(ea, off[0], is_wildcard=False)
        sig.add_bytes_to_signature(ea + off[0], length[0], is_wildcard=True)
        remaining_len = ins.size - (off[0] + length[0])
        if remaining_len > 0:
            sig.add_bytes_to_signature(
                ea + off[0] + length[0], remaining_len, is_wildcard=False
            )


@dataclasses.dataclass(slots=True)
class InstructionWalker:
    start_ea: int
    end_ea: int = idaapi.BADADDR
    cursor: int = dataclasses.field(init=False)
    _instruction: idaapi.insn_t = dataclasses.field(
        init=False, repr=False, default_factory=idaapi.insn_t
    )

    def __post_init__(self):
        if self.start_ea == idaapi.BADADDR:
            raise ValueError("Invalid start address for InstructionWalker")
        self.cursor = self.start_ea

    def __iter__(self):
        self.cursor = self.start_ea
        return self

    def __next__(self) -> tuple[int, idaapi.insn_t, int]:
        if self.end_ea != idaapi.BADADDR and self.cursor >= self.end_ea:
            raise StopIteration

        if idaapi_user_canceled():
            raise StopIteration("Aborted by user")

        current_instruction_ea = self.cursor
        ins_len = idaapi.decode_insn(self._instruction, current_instruction_ea)

        if ins_len <= 0:
            raise StopIteration

        self.cursor += ins_len
        return current_instruction_ea, self._instruction, ins_len


class UniqueSignatureGenerator:
    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(self, ea: int, cfg: SigMakerConfig) -> Signature:
        if not is_address_marked_as_code(ea):
            raise Unexpected("Cannot create code signature for data")

        sig = Signature()
        start_fn = idaapi.get_func(ea)
        bytes_since_last_check = 0
        instruction_count = 0

        for cur_ea, ins, ins_len in InstructionWalker(ea):
            if self.progress_reporter is not None and self.progress_reporter.should_cancel():
                raise UserCanceledError("Signature generation canceled by user")

            instruction_count += 1
            progress_reporting = (
                self.progress_reporter is not None and self.progress_reporter.enabled()
            )
            if progress_reporting and instruction_count % 100 == 0:
                self.progress_reporter.report_progress(
                    message=f"Generating signature at {hex(cur_ea)}",
                    signature_length=len(sig),
                    instructions_processed=instruction_count,
                )

            if bytes_since_last_check > cfg.max_single_signature_length:
                if (
                    not cfg.ask_longer_signature
                    or idaapi.ask_yn(
                        idaapi.ASKBTN_NO,
                        f"Signature is already {len(sig)} bytes. Continue?",
                    )
                    != idaapi.ASKBTN_YES
                ):
                    raise Unexpected("Signature not unique within length constraints")
                bytes_since_last_check = 0

            if (
                not cfg.continue_outside_of_function
                and start_fn
                and cur_ea >= start_fn.end_ea
            ):
                raise Unexpected("Signature left function scope without being unique")

            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )
            bytes_since_last_check += ins_len

            if SignatureSearcher.is_unique(f"{sig:ida}"):
                sig.trim_signature()
                return sig

        raise Unexpected("Signature not unique (reached end of analysis)")


class RangeSignatureGenerator:
    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(
        self,
        start_ea: int,
        end_ea: int,
        cfg: SigMakerConfig,
    ) -> Signature:
        sig = Signature()

        if not is_address_marked_as_code(start_ea):
            sig.add_bytes_to_signature(start_ea, end_ea - start_ea, is_wildcard=False)
            return sig

        walker = InstructionWalker(start_ea, end_ea)
        instruction_count = 0

        for cur_ea, ins, _ in walker:
            if self.progress_reporter is not None and self.progress_reporter.should_cancel():
                raise UserCanceledError("Signature generation canceled by user")

            instruction_count += 1
            progress_reporting = (
                self.progress_reporter is not None and self.progress_reporter.enabled()
            )
            if progress_reporting and instruction_count % 50 == 0:
                range_size = end_ea - start_ea
                bytes_processed = cur_ea - start_ea
                progress_pct = (
                    (bytes_processed / range_size * 100) if range_size > 0 else 0
                )
                self.progress_reporter.report_progress(
                    message=f"Processing range at {hex(cur_ea)}",
                    signature_length=len(sig),
                    instructions_processed=instruction_count,
                    progress_percent=f"{progress_pct:.1f}%",
                )

            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )

        if walker.cursor < end_ea:
            remaining_bytes = end_ea - walker.cursor
            sig.add_bytes_to_signature(
                walker.cursor, remaining_bytes, is_wildcard=False
            )

        sig.trim_signature()
        return sig


@dataclasses.dataclass(slots=True)
class SignatureMaker:
    _operand_processor: OperandProcessor = dataclasses.field(
        default_factory=OperandProcessor
    )
    _instruction_processor: InstructionProcessor = dataclasses.field(init=False)

    def __post_init__(self):
        self._instruction_processor = InstructionProcessor(self._operand_processor)

    def _create_generator(
        self,
        for_range: bool,
        progress_reporter: typing.Optional[ProgressReporter],
    ) -> UniqueSignatureGenerator | RangeSignatureGenerator:
        if for_range:
            return RangeSignatureGenerator(
                self._instruction_processor, progress_reporter
            )
        return UniqueSignatureGenerator(
            self._instruction_processor, progress_reporter
        )

    def make_signature(
        self,
        ea: int | Match,
        cfg: SigMakerConfig,
        end: int | None = None,
        *,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ) -> GeneratedSignature:
        start_ea = int(ea)
        if start_ea == idaapi.BADADDR:
            raise Unexpected("Invalid start address")

        if not progress_reporter:
            progress_reporter = CheckContinuePrompt(
                prompt_interval=cfg.prompt_interval,
                metadata={
                    "operation": "Signature generation",
                    "start_address": hex(start_ea),
                },
                logger=LOGGER,
                enable_prompt=cfg.enable_continue_prompt,
            )

        if end is None:
            generator = self._create_generator(
                for_range=False, progress_reporter=progress_reporter
            )
            sig = generator.generate(start_ea, cfg)
            return GeneratedSignature(sig, Match(start_ea))

        if end <= start_ea:
            raise Unexpected("End address must be after start address")

        generator = self._create_generator(
            for_range=True, progress_reporter=progress_reporter
        )
        sig = generator.generate(start_ea, end, cfg)
        return GeneratedSignature(sig)


class XrefFinder:
    """Generates signatures for each code xref that points to an address."""

    def __init__(self):
        self.signature_maker = SignatureMaker()

    @classmethod
    def iter_code_xrefs_to(cls, ea: int) -> typing.Iterable[int]:
        xb = idaapi.xrefblk_t()
        if not xb.first_to(ea, idaapi.XREF_ALL):
            return
        while True:
            if is_address_marked_as_code(xb.frm):
                yield xb.frm
            if not xb.next_to():
                break

    @classmethod
    def count_code_xrefs_to(cls, ea: int) -> int:
        return sum(1 for _ in cls.iter_code_xrefs_to(ea))

    def find_xrefs(self, ea: int, cfg: SigMakerConfig) -> XrefGeneratedSignature:
        xref_signatures: list[GeneratedSignature] = []
        total = self.count_code_xrefs_to(ea)
        if total == 0:
            return XrefGeneratedSignature([])

        cfg_no_prompt = dataclasses.replace(cfg, ask_longer_signature=False)

        for frm_ea in self.iter_code_xrefs_to(ea):
            if idaapi_user_canceled():
                break

            try:
                result = self.signature_maker.make_signature(frm_ea, cfg_no_prompt)
                sig: typing.Optional[Signature] = result.signature
            except Exception:
                sig = None

            if sig is None:
                continue

            xref_signatures.append(GeneratedSignature(sig, Match(frm_ea)))

        xref_signatures.sort()
        return XrefGeneratedSignature(xref_signatures)


# ---------------------------------------------------------------------------
# Signature search
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class SearchResults:
    matches: list[Match]
    signature_str: str


class SignatureParser:
    """Accepts any of the supported input formats and returns an IDA-style string."""

    _HEX_PAIR = re.compile(r"^[0-9A-Fa-f]{2}$")
    _ESCAPED_HEX = re.compile(r"\\x[0-9A-Fa-f]{2}")
    _RUN_0X = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")
    _MASK_REGEX = re.compile(r"x(?:x|\?)+")
    _BINARY_MASK_REGEX = re.compile(r"0b[01]+")

    @classmethod
    def parse(cls, input_str: str) -> str:
        mask = cls._extract_mask(input_str)
        parsed = ""
        if mask:
            if (bytestr := cls._ESCAPED_HEX.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)
            elif (bytestr := cls._RUN_0X.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)
        else:
            parsed = cls._normalize_loose_hex(input_str)
        return parsed.strip()

    @classmethod
    def _extract_mask(cls, s: str) -> str:
        m = cls._MASK_REGEX.search(s)
        if m:
            return m.group(0)
        m = cls._BINARY_MASK_REGEX.search(s)
        if not m:
            return ""
        bits = m.group(0)[2:]
        return "".join("x" if b == "1" else "?" for b in bits[::-1])

    @staticmethod
    def _masked_bytes_to_ida(
        byte_tokens: list[str], mask: str, *, slice_from: int
    ) -> str:
        sig = Signature(
            [
                SignatureByte(int(tok[slice_from:], 16), mask[i] == "?")
                for i, tok in enumerate(byte_tokens)
            ]
        )
        return f"{sig:ida}"

    @classmethod
    def _normalize_loose_hex(cls, input_str: str) -> str:
        s = input_str
        s = re.sub(r"[\)\(\[\]]+", "", s)
        s = re.sub(r"^\s+", "", s)
        s = re.sub(r"[? ]+$", "", s) + " "
        s = re.sub(r"\\?\\x", "", s)
        s = re.sub(r"\s+", " ", s)

        tokens = [t.strip() for t in s.split() if t.strip()]
        out: list[str] = []
        for t in tokens:
            if t == "?" or t == "??":
                out.append("?")
                continue
            if t.lower().startswith("0x"):
                t = t[2:]
            if not cls._HEX_PAIR.match(t):
                out.append("?")
                continue
            out.append(t.upper())

        return (" ".join(out) + " ") if out else ""


@dataclasses.dataclass(slots=True)
class SignatureSearcher:
    input_signature: str = ""

    @classmethod
    def from_signature(cls, input_signature: str) -> "SignatureSearcher":
        return cls(input_signature=input_signature)

    def search(self) -> SearchResults:
        sig_str = SignatureParser.parse(self.input_signature)
        if not sig_str:
            return SearchResults([], "")
        matches = self.find_all(sig_str)
        return SearchResults(matches, sig_str)

    @staticmethod
    def _find_all_simd(
        ida_signature: str, skip_more_than_one: bool = False
    ) -> list[Match]:
        simd_signature, _ = SigText.normalize(ida_signature)
        sig = _SimdSignature(simd_signature)
        if (k := sig.size_bytes) == 0:
            # Empty / all-wildcard patterns have no semantic meaning — refuse
            # instead of pretending "matches everywhere starting at min_ea".
            return []

        buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()

        results: list[Match] = []
        n = len(data_mv)
        off = 0
        while off <= n - k:
            if idaapi_user_canceled():
                break
            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            abs_off = off + idx
            # Skip hits that straddle a segment gap (the concatenated buffer
            # has no gap bytes, so such a hit does not exist in memory).
            if not buf.match_crosses_segment_boundary(abs_off, k):
                ea = buf.concat_offset_to_ida_addr(abs_off)
                if ea is not None:
                    results.append(Match(ea))
                    if skip_more_than_one and len(results) > 1:
                        break
            off = abs_off + 1
        return results

    @staticmethod
    def find_all(ida_signature: str) -> list[Match]:
        if SIMD_SPEEDUP_AVAILABLE:
            return SignatureSearcher._find_all_simd(ida_signature)
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = idaapi.inf_get_min_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        while True:
            if idaapi_user_canceled():
                break
            # BIN_SEARCH_NOCASE collides A-Z with a-z on plain byte searches
            # (0x41 matches 0x61 etc.), producing false positives and breaking
            # `is_unique` during signature generation. We only want forward
            # binary-exact matching.
            hit, _ = _bin_search(
                ea,
                idaapi.inf_get_max_ea(),
                binary,
                idaapi.BIN_SEARCH_FORWARD,
            )
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            ea = hit + 1
        return out

    @classmethod
    def is_unique(cls, ida_signature: str) -> bool:
        return len(cls.find_all(ida_signature)) == 1
