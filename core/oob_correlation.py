"""Exact, fresh, target-attributed OOB correlation helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


CorrelationStatus = Literal["correlated", "missing", "stale", "ambiguous"]


class OobCorrelationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: Literal["1.0"] = "1.0"
    correlation_id: str
    status: CorrelationStatus
    matched_count: int = 0
    target_attributed: bool = False
    stale_callback: bool = False
    interaction_digests: List[str] = Field(default_factory=list)
    reason: str = ""


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _contains_exact(value: Any, correlation_id: str) -> bool:
    pattern = rf"(?<![a-z0-9]){re.escape(correlation_id)}(?![a-z0-9])"
    return any(re.search(pattern, item, flags=re.IGNORECASE) for item in _strings(value))


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 10_000_000_000:
            numeric /= 1000.0
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    raw = str(value).strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _interaction_timestamp(interaction: Dict[str, Any]) -> Optional[datetime]:
    for key in ("timestamp", "created_at", "createdAt", "date", "time"):
        parsed = _parse_timestamp(interaction.get(key))
        if parsed:
            return parsed
    return None


def _digest(interaction: Dict[str, Any]) -> str:
    # Digests let the evidence layer refer to a callback without retaining a
    # raw request that might contain query data or secrets.
    payload = json.dumps(interaction, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def correlate_interactions(
    correlation_id: str,
    interactions: Iterable[Dict[str, Any]],
    *,
    expected_domain: str = "",
    issued_at: Optional[datetime] = None,
    now: Optional[datetime] = None,
) -> OobCorrelationResult:
    """Return a safe correlation decision from raw adapter interactions.

    A match is accepted only when the correlation token appears as a complete
    token, not as a substring of another token. If timestamps are available,
    callbacks older than the issued time are rejected. A callback also needs
    to contain the expected callback domain (or the exact token when no domain
    is supplied) to establish run attribution.
    """
    cid = str(correlation_id or "").strip()
    if not cid:
        return OobCorrelationResult(correlation_id="", status="missing", reason="Correlation ID is empty.")
    expected = str(expected_domain or "").strip().lower().rstrip(".")
    issued = issued_at.astimezone(timezone.utc) if issued_at and issued_at.tzinfo else issued_at
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    fresh: List[Dict[str, Any]] = []
    stale_count = 0
    attributed_count = 0
    for interaction in interactions or []:
        if not isinstance(interaction, dict) or not _contains_exact(interaction, cid):
            continue
        timestamp = _interaction_timestamp(interaction)
        if issued and timestamp and timestamp < issued:
            stale_count += 1
            continue
        if timestamp and timestamp > current:
            # Future-dated callbacks are not accepted as proof. They remain
            # diagnostic through the stale flag rather than being promoted.
            stale_count += 1
            continue
        fresh.append(interaction)
        values = [item.lower() for item in _strings(interaction)]
        attributed = bool(expected and any(expected in item for item in values))
        if attributed or (not expected and _contains_exact(interaction, cid)):
            attributed_count += 1

    if not fresh:
        return OobCorrelationResult(
            correlation_id=cid,
            status="stale" if stale_count else "missing",
            stale_callback=bool(stale_count),
            reason="Only stale callbacks matched." if stale_count else "No exact callback matched.",
        )
    digests = [_digest(item) for item in fresh]
    if len(set(digests)) != len(digests):
        return OobCorrelationResult(
            correlation_id=cid,
            status="ambiguous",
            matched_count=len(fresh),
            interaction_digests=sorted(set(digests)),
            reason="Duplicate callback records prevent unique evidence attribution.",
        )
    if attributed_count != len(fresh):
        return OobCorrelationResult(
            correlation_id=cid,
            status="ambiguous",
            matched_count=len(fresh),
            interaction_digests=digests,
            reason="A matching callback was not consistently attributed to the expected domain.",
        )
    return OobCorrelationResult(
        correlation_id=cid,
        status="correlated",
        matched_count=len(fresh),
        target_attributed=True,
        interaction_digests=digests,
        reason="Exact fresh callback matched the expected domain.",
    )


__all__ = ["OobCorrelationResult", "correlate_interactions"]
