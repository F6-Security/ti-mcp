# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Settings from the environment, read once and validated when the server starts,
so a bad value fails it on startup rather than on the first tool call."""

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ti_mcp import __version__

DEFAULT_BASE_URL = "https://ti.f6.security"
API_ROOT = "/api/v2"

# A single tool result lands in the model's context, so a page of records is
# capped well below what the API itself is willing to send.
MAX_RESPONSE_BYTES = 1024 * 1024
# How much of an error body is echoed back: enough for the field name a 400
# carries, not enough for a traceback or a settings dump.
MAX_ERROR_CHARS = 512
# The whole error text a tool returns: a hint from STATUS_HINTS plus that body slice.
MAX_ERROR_TEXT_CHARS = 1500

# What the backend actually enforces on top of the RPS rule: a Common API call
# without resultId opens a new scroll, and on some collections one user may do
# that only once per SCROLL_OPEN_INTERVAL seconds (429 + Retry-After otherwise).
SCROLL_OPEN_INTERVAL = 60
# Without a scroll the backend refuses offset + limit beyond a fixed window.
OFFSET_WINDOW = 10_000

RETRY_STATUSES = {429, 500, 502, 503, 504}
AMBIENT_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")

# explicit so the UA doesn't silently change with the httpx version
USER_AGENT = f"f6-ti-mcp/{__version__}"


class SettingsError(RuntimeError):
    """An environment value the server refuses to start with."""


def _env_number(
    environ: Mapping[str, str], name: str, default: float, *, minimum: float, integer: bool = False
) -> float:
    """A numeric setting from the environment, with a readable failure."""
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw) if integer else float(raw)
    except ValueError:
        kind = "an integer" if integer else "a number"
        raise SettingsError(f"{name} must be {kind}, got {raw!r}") from None
    if value < minimum:
        raise SettingsError(f"{name} must be at least {minimum}, got {raw!r}")
    return value


def _validated_base_url(environ: Mapping[str, str]) -> str:
    """Reject a base URL that would send the API key somewhere unintended."""
    raw = environ.get("TI_BASE_URL", "").strip().rstrip("/") or DEFAULT_BASE_URL
    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise SettingsError(f"TI_BASE_URL must use https:// (got {parts.scheme or 'no'} scheme)")
    if not parts.hostname:
        raise SettingsError("TI_BASE_URL must contain a host")
    if parts.username or parts.password:
        raise SettingsError("TI_BASE_URL must not carry credentials; use TI_LOGIN and TI_API_KEY")
    if parts.query or parts.fragment:
        raise SettingsError("TI_BASE_URL must not contain a query string or fragment")
    # The guide spells the root out as https://host/api/v2; accept that too.
    if raw.endswith(API_ROOT):
        raw = raw[: -len(API_ROOT)]
    return raw


def _verification(environ: Mapping[str, str]) -> ssl.SSLContext | bool:
    """Build the TLS verification setting.

    trust_env=False means SSL_CERT_FILE and SSL_CERT_DIR are ignored, so an
    installation behind an internal CA needs a way in that is not verify=False.
    """
    bundle = environ.get("TI_CA_BUNDLE", "").strip()
    if not bundle:
        return True
    if not os.path.isfile(bundle):
        raise SettingsError(f"TI_CA_BUNDLE is not a file: {bundle}")
    try:
        return ssl.create_default_context(cafile=bundle)
    except ssl.SSLError as error:
        raise SettingsError(f"TI_CA_BUNDLE could not be loaded: {error}") from error


def _proxy(environ: Mapping[str, str]) -> str | None:
    """An explicit proxy. HTTP_PROXY and friends are ignored on purpose: the
    request carries the API key, so where it goes is stated, not inherited."""
    raw = environ.get("TI_PROXY", "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SettingsError(f"TI_PROXY must be an http:// or https:// URL, got {raw!r}")
    return raw


@dataclass(frozen=True)
class Settings:
    """Everything the server takes from the environment, read once at startup."""

    base_url: str
    login: str
    # Kept out of repr: a settings object in a traceback must not show the key
    # or a proxy password.
    api_key: str = field(repr=False)
    timeout: float
    verify: ssl.SSLContext | bool
    proxy: str | None = field(repr=False)
    # The guide's RPS rule: one request per second to one feed. Overridable
    # because a contract may raise it.
    min_feed_interval: float
    # How long a resultId stays usable after its last use: 150 s as measured
    # on the service.
    result_id_ttl: float
    # pyf6 retries 429/500/502/503/504 with a backoff; same idea, fewer
    # attempts because an MCP caller is waiting on the answer.
    retries: int
    # Whether HTTP(S)_PROXY is set, so a network error can say it was ignored.
    # Only the fact: the values can carry a password.
    ambient_proxy: bool

    @property
    def proxy_display(self) -> str | None:
        """What error messages may say about the proxy: host and port, never user:pass@."""
        return urlsplit(self.proxy).netloc.rpartition("@")[2] if self.proxy else None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        """Read and validate the TI_* variables; raises SettingsError on a bad value.

        Missing TI_LOGIN/TI_API_KEY is not an error here: the server still
        starts, and every tool call answers with what to set.
        """
        env = os.environ if environ is None else environ
        return cls(
            base_url=_validated_base_url(env),
            login=(env.get("TI_LOGIN") or "").strip(),
            api_key=(env.get("TI_API_KEY") or "").strip(),
            timeout=_env_number(env, "TI_TIMEOUT", 120, minimum=1),
            verify=_verification(env),
            proxy=_proxy(env),
            min_feed_interval=_env_number(env, "TI_MIN_FEED_INTERVAL", 1, minimum=0),
            result_id_ttl=_env_number(env, "TI_RESULT_ID_TTL", 150, minimum=0),
            retries=int(_env_number(env, "TI_RETRIES", 3, minimum=0, integer=True)),
            ambient_proxy=any(env.get(var) for var in AMBIENT_PROXY_VARS),
        )
