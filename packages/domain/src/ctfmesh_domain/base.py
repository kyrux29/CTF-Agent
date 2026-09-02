"""Shared primitives for versioned CTFMesh boundary contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, StringConstraints


def _parse_datetime(value: object) -> object:
    """Parse only ISO-8601 text; reject coercions such as numeric timestamps."""

    if not isinstance(value, str):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("datetime must use ISO-8601 format") from exc


def _freeze_sequence(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _normalize_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware values to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)


type UtcDatetime = Annotated[
    datetime,
    BeforeValidator(_parse_datetime),
    AfterValidator(_normalize_utc),
]
type Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    ),
]
type NonEmptyText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=16_384),
]
type Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]
type FrozenSequence[T] = Annotated[tuple[T, ...], BeforeValidator(_freeze_sequence)]


class ContractModel(BaseModel):
    """Strict base for data crossing a package or process boundary."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        populate_by_name=True,
        allow_inf_nan=False,
    )
