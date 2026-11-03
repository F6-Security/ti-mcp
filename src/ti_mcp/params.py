# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Checks on tool arguments before they shape a URL or a query string, and the
resultId cache that keeps repeated reads inside the backend's scroll limits."""

import asyncio
import json
from datetime import datetime
from typing import Any

from ti_mcp.catalog import COLLECTIONS, DEPRECATED, collection_limit

# Dates accepted by the API, per pyf6's CollectionConsts.BASE_DATE_FORMATS.
DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ")

def as_int(name: str, value: Any, *, minimum: int, maximum: int | None = None) -> int | None:
    """Coerce a JSON number to int.

    str(10.0) would reach the API as "10.0", which its parsers silently
    discard in favour of the default — so only whole numbers pass.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{name} must be a whole number, got {value!r}")
    number = int(value)
    if number < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {number}")
    if maximum is not None and number > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {number}")
    return number


def clamp_limit(collection: str, limit: Any) -> int | None:
    """Keeps limit within the documented cap for the collection."""
    value = as_int("limit", limit, minimum=1)
    return None if value is None else min(value, collection_limit(collection))


def check_date(value: Any, param: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{param} must be a string")
    text = value.strip()
    for fmt in DATE_FORMATS:
        try:
            datetime.strptime(text, fmt)
            return text
        except ValueError:
            continue
    raise ValueError(f"{param} must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, got {value!r}")


def check_flag(value: Any, param: str) -> int | None:
    """apply_hunting_rules and the like are 0-or-1 integers; a JSON boolean is accepted too."""
    if isinstance(value, bool):
        return int(value)
    return as_int(param, value, minimum=0, maximum=1)


# Query parameters the tools own. extra_params may not override them: a model
# that wants a different limit or filter has a first-class parameter for it.
RESERVED_PARAMS = frozenset(
    {"q", "limit", "offset", "resultId", "use_scroll", "seqUpdate", "df", "dt",
     "apply_hunting_rules", "lang", "date", "collection"}
)


def _query_value(key: str, value: Any) -> Any:
    """One query value as the API reads it: scalars, or a list of scalars for
    repeated keys. Booleans become 0/1 because that is what the API expects."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (str, int, float)):
        return value
    if isinstance(value, list) and all(
        isinstance(item, (str, int, float)) and not isinstance(item, bool) for item in value
    ):
        return value
    raise ValueError(f"{key} must be a string, a number or a list of those, got {value!r}")


def query_params(value: Any, *, name: str, reserved: frozenset[str] = frozenset()) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    params: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"{name} keys must be non-empty strings")
        if key in reserved:
            raise ValueError(f"{name} must not set {key}; use the tool's own parameter for it")
        if item is None:
            continue
        params[key] = _query_value(key, item)
    return params


def extra_params(value: Any) -> dict[str, Any]:
    return query_params(value, name="extra_params", reserved=RESERVED_PARAMS)


def check_id(value: Any) -> str:
    """A record id is one path segment: anything else would address a different endpoint."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("id is required")
    item_id = value.strip()
    # No separators, and no percent-encoding either: the backend decodes the
    # path, so %2F or %61ction would become a separator or a refused segment.
    forbidden = any(ch in item_id for ch in "/?#\\%") or any(ch.isspace() for ch in item_id)
    if item_id in (".", "..") or forbidden:
        raise ValueError(f"id must be a single plain path segment, got {value!r}")
    return item_id


# What ti_request may reach under /api/v2: the collection sections plus the
# documented helper endpoints. Everything else (internal, web, srv ...) is not
# part of the API a client is given.
HELPER_ENDPOINTS = {"search", "sequence_list", "user", "utils"}
API_SECTIONS = frozenset({name.split("/")[0] for name in (*COLLECTIONS, *DEPRECATED)} | HELPER_ENDPOINTS)
REFUSED_SEGMENTS = {
    "action": (
        "ti_request is read-only: {collection}/{id}/action/{action} endpoints change data "
        "on the TI side and are refused here."
    ),
    "file": (
        "ti_request returns JSON only: {collection}/{id}/file/{file_id} serves a binary "
        "file, which has no place in a model's context."
    ),
}


def _plain_segment(segment: str) -> bool:
    """One literal path segment: the backend decodes the path, so a percent-encoded
    separator or segment name (%2F, %61ction) must be refused here, not sent."""
    if not segment or segment in (".", ".."):
        return False
    return not any(ch in "%\\" or ch.isspace() for ch in segment)


def check_path(value: Any) -> list[str]:
    """Splits a ti_request path into segments and refuses what the tool may not reach."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("path is required")
    path = value.strip().strip("/")
    if "?" in path or "#" in path:
        raise ValueError("put query parameters in params, not in path")
    segments = path.split("/")
    if any(not _plain_segment(seg) for seg in segments):
        raise ValueError(
            f"path must be plain segments separated by '/', without percent-encoding, got {value!r}"
        )
    if segments[0] not in API_SECTIONS:
        raise ValueError(
            f"path must start with one of: {', '.join(sorted(API_SECTIONS))}; got {value!r}"
        )
    for segment, reason in REFUSED_SEGMENTS.items():
        if segment in segments:
            raise ValueError(reason)
    return segments


def check_offset(value: Any) -> int | None:
    return as_int("offset", value, minimum=0)


class ResultIdCache:
    """Remembers the live resultId of every scroll this process has open.

    Some collections let a user open a new scroll only once per
    SCROLL_OPEN_INTERVAL seconds, so a repeated ti_get_collection call for the
    same collection and filter continues the scroll it already has instead of
    asking for a new one and getting a 429. Entries are keyed by the request
    parameters that define the result set and expire ttl seconds
    after their last use, in step with the backend.
    """

    def __init__(self, ttl: float) -> None:
        self._ttl = ttl
        self._entries: dict[str, tuple[str, float]] = {}

    @staticmethod
    def key(collection: str, params: dict[str, Any]) -> str:
        # limit and offset change the page, not the result set.
        defining = {
            k: v for k, v in params.items()
            if v is not None and k not in {"resultId", "limit", "offset"}
        }
        return collection + "?" + json.dumps(defining, sort_keys=True, ensure_ascii=False)

    def get(self, key: str) -> str | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        result_id, last_used = entry
        if asyncio.get_running_loop().time() - last_used > self._ttl:
            del self._entries[key]
            return None
        return result_id

    def put(self, key: str, result_id: str) -> None:
        self._entries[key] = (result_id, asyncio.get_running_loop().time())

    def drop(self, key: str) -> None:
        self._entries.pop(key, None)
