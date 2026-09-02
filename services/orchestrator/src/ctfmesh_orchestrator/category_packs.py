"""Reviewed, local-only category guidance for Power racers.

The loader intentionally reads resources shipped with the orchestrator wheel,
not files supplied by a challenge.  Selection is deterministic and uses only
typed action names plus compact category signals derived in memory from an
AutoPrompter observation; raw observation text never enters a returned pack or
the coordinator's progress read model.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files

_MAX_PACK_CHARS = 4_000
_MAX_OBSERVATION_SCAN_CHARS = 16_384


class CategoryPackId(StrEnum):
    """Fixed IDs for the five reviewed Power prompt packs."""

    WEB = "web.v1"
    PWN = "pwn.v1"
    REV = "rev.v1"
    CRYPTO = "crypto.v1"
    FORENSICS = "forensics.v1"


@dataclass(frozen=True, slots=True)
class CategoryPack:
    """Immutable, versioned local checklist supplied to a racer context."""

    id: CategoryPackId
    filename: str
    digest: str
    text: str


_PACK_FILENAMES: dict[CategoryPackId, str] = {
    CategoryPackId.WEB: "web.md",
    CategoryPackId.PWN: "pwn.md",
    CategoryPackId.REV: "rev.md",
    CategoryPackId.CRYPTO: "crypto.md",
    CategoryPackId.FORENSICS: "forensics.md",
}
_SIGNAL_MARKERS: dict[CategoryPackId, tuple[str, ...]] = {
    CategoryPackId.WEB: (".php", ".html", ".js", "http", "sql", "flask", "django"),
    CategoryPackId.PWN: ("rop", "libc", "stack", "format string", "pwn", "overflow"),
    CategoryPackId.REV: (".wasm", ".apk", "bytecode", "disassembly", "decompile"),
    CategoryPackId.CRYPTO: ("rsa", "aes", "cipher", "ciphertext", "modulus", "ecdsa"),
    CategoryPackId.FORENSICS: (
        ".pcap",
        ".pcapng",
        "volatility",
        "memory dump",
        "exif",
        "disk image",
    ),
}
_TIE_BREAK_ORDER = (
    CategoryPackId.PWN,
    CategoryPackId.REV,
    CategoryPackId.CRYPTO,
    CategoryPackId.FORENSICS,
    CategoryPackId.WEB,
)


@lru_cache(maxsize=1)
def reviewed_category_packs() -> tuple[CategoryPack, ...]:
    """Load every checked-in pack and calculate its content digest once."""

    resource_root = files("ctfmesh_orchestrator").joinpath("reviewed_packs")
    packs: list[CategoryPack] = []
    for pack_id, filename in _PACK_FILENAMES.items():
        text = resource_root.joinpath(filename).read_text(encoding="utf-8")
        if not text.startswith("# ") or "\x00" in text or len(text) > _MAX_PACK_CHARS:
            raise RuntimeError("reviewed_category_pack_invalid")
        packs.append(
            CategoryPack(
                id=pack_id,
                filename=filename,
                digest=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                text=text,
            )
        )
    return tuple(packs)


def reviewed_category_pack(pack_id: CategoryPackId) -> CategoryPack:
    """Return exactly one shipped pack; callers cannot supply a filesystem path."""

    return next(pack for pack in reviewed_category_packs() if pack.id is pack_id)


def category_signals_from_observations(
    observation_texts: Iterable[str],
) -> tuple[CategoryPackId, ...]:
    """Classify bounded in-memory evidence into coarse labels without retaining it."""

    bounded_text = "\n".join(
        text[:_MAX_OBSERVATION_SCAN_CHARS] for text in observation_texts
    ).lower()
    return tuple(
        pack_id
        for pack_id, markers in _SIGNAL_MARKERS.items()
        if any(marker in bounded_text for marker in markers)
    )


def select_category_pack(
    *,
    action_types: tuple[str, ...],
    category_signals: tuple[CategoryPackId, ...],
) -> CategoryPack:
    """Choose one checklist after reconnaissance without granting any authority.

    Explicit evidence-derived signals score higher than action names. ``gdb`` or
    ``tube`` activity is a strong pwn indicator, while no trustworthy signal
    intentionally falls back to the broadly useful web checklist.
    """

    if any(not isinstance(signal, CategoryPackId) for signal in category_signals):
        raise ValueError("category_pack_signal_invalid")
    scores = {pack_id: 0 for pack_id in CategoryPackId}
    for signal in category_signals:
        scores[signal] += 4
    for action_type in action_types:
        if action_type.startswith(("gdb.", "tube.")):
            scores[CategoryPackId.PWN] += 3
        elif action_type.startswith("shell.pty"):
            scores[CategoryPackId.CRYPTO] += 1
    if not any(scores.values()):
        return reviewed_category_pack(CategoryPackId.WEB)
    selected_id = max(
        _TIE_BREAK_ORDER,
        key=lambda pack_id: (scores[pack_id], -_TIE_BREAK_ORDER.index(pack_id)),
    )
    return reviewed_category_pack(selected_id)


__all__ = [
    "CategoryPack",
    "CategoryPackId",
    "category_signals_from_observations",
    "reviewed_category_pack",
    "reviewed_category_packs",
    "select_category_pack",
]
