# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""The HTTP client: GETs to the TI API with Basic auth, throttling, retries and
the checks that keep an unexpected body out of the model's context."""

import asyncio
from typing import Any

import httpx

from ti_mcp.settings import (
    API_ROOT,
    MAX_ERROR_CHARS,
    MAX_RESPONSE_BYTES,
    RETRY_STATUSES,
    USER_AGENT,
    Settings,
)


class FeedThrottle:
    """Keeps requests to one feed at most one per min_interval seconds.

    The API answers 429 when a feed is polled faster than that, and different
    feeds may be polled at the same time — so the interval is tracked per feed
    and the lock is held across the wait to serialise same-feed callers.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._locks: dict[str, asyncio.Lock] = {}
        self._last_start: dict[str, float] = {}

    async def acquire(self, key: str) -> None:
        if self._min_interval <= 0:
            return
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            loop = asyncio.get_running_loop()
            last = self._last_start.get(key)
            if last is not None:
                wait = self._min_interval - (loop.time() - last)
                if wait > 0:
                    await asyncio.sleep(wait)
            self._last_start[key] = loop.time()


# Messages merge the troubleshooting section of General Info with pyf6's
# STATUS_CODE_MSGS, so a failing call says what to fix instead of echoing a code.
STATUS_HINTS: dict[int, str] = {
    400: (
        "bad request — a searchable tag this collection does not have (the body names the "
        "field), offset + limit beyond the 10000 window (use scroll=true for deeper reads), or "
        "an expired resultId (kept ~150 s after its last use; the body is then empty — call "
        "again without result_id)"
    ),
    401: (
        "TI_LOGIN/TI_API_KEY missing or wrong — the key is created in Личный кабинет → "
        "Безопасность и доступ → Персональный токен"
    ),
    403: (
        "either the source IP is not on the trusted list (Личный кабинет → Безопасность → "
        "Доверенные IP), the API key is inactive, or the account has no access to this collection"
    ),
    404: (
        "no such record, the endpoint does not exist for this collection, or (\"masked scroll id "
        "not found\") an expired resultId — call again without result_id"
    ),
    429: (
        "rate limited — besides one request per second per feed, on some collections a NEW scroll "
        "(Common API call without resultId) is allowed once per 60 s; continue with the resultId "
        "you already have, or wait Retry-After"
    ),
    500: "server-side error on the TI side, retry in a few minutes",
    504: "lower the limit parameter so the server has less to process",
}

class APIError(RuntimeError):
    """A non-2xx answer from TI, with the status kept for callers that branch on it."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status

class TIClient:
    """The TI API as this process sees it: one connection pool and one per-feed
    throttle for the server's whole lifetime, so calls reuse open connections
    and share the rate limit.

    trust_env=False keeps HTTP_PROXY and SSL_CERT_FILE out of the picture: the
    proxy is TI_PROXY, the CA is TI_CA_BUNDLE, both stated. follow_redirects
    stays off on purpose: per the guide a 301/302 means the caller's IP is not
    on the trusted list, and following it would hide that and forward the key.
    A transport, when given, replaces the network entirely (tests), so the
    proxy and TLS settings do not apply to it.
    """

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._throttle = FeedThrottle(settings.min_feed_interval)
        network: dict[str, Any] = (
            {"verify": settings.verify, "proxy": settings.proxy}
            if transport is None
            else {"transport": transport}
        )
        self._http = httpx.AsyncClient(
            timeout=settings.timeout, follow_redirects=False, trust_env=False, **network
        )

    async def __aenter__(self) -> "TIClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, params: dict[str, Any] | None = None, *, throttle_key: str) -> Any:
        settings = self._settings
        if not settings.login or not settings.api_key:
            raise RuntimeError("TI_LOGIN and TI_API_KEY environment variables must be set")

        # None is dropped, 0 is not: apply_hunting_rules=0 is a meaningful value.
        query = {k: v for k, v in (params or {}).items() if v is not None}
        url = f"{settings.base_url}{API_ROOT}/{path.lstrip('/')}"
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}

        try:
            for attempt in range(settings.retries + 1):
                await self._throttle.acquire(throttle_key)
                response = await self._http.get(
                    url, params=query, headers=headers, auth=(settings.login, settings.api_key)
                )
                if response.status_code not in RETRY_STATUSES or attempt == settings.retries:
                    break
                retry_after = (response.headers.get("Retry-After") or "").strip()
                delay = (
                    float(retry_after)
                    if retry_after.replace(".", "", 1).isdigit()
                    else settings.min_feed_interval * (2 ** attempt)
                )
                await asyncio.sleep(max(delay, settings.min_feed_interval))
        except httpx.HTTPError as error:
            # Transport failures such as ReadTimeout carry an empty message, so name
            # the class and the URL, and say how the proxy comes into play. Values
            # of the ambient variables are never echoed: they can carry a password.
            detail = str(error) or type(error).__name__
            if settings.proxy:
                hint = f" Requests go through TI_PROXY ({settings.proxy_display})."
            elif settings.ambient_proxy:
                hint = " HTTP(S)_PROXY is ignored; set TI_PROXY to route through a proxy."
            else:
                hint = ""
            raise RuntimeError(f"Network error contacting {url}: {detail}.{hint}") from error

        return _parse(response, path)


def _parse(response: httpx.Response, path: str) -> Any:
    """The JSON body of a successful answer, or an error that says what went wrong."""
    if response.is_redirect:
        location = response.headers.get("Location", "")
        raise RuntimeError(
            f"API error {response.status_code} (redirect to {location or 'unknown'}): "
            "your public IP is probably not on the F6 trusted list — see the IP white list section "
            "of the guide"
        )

    if not response.is_success:
        parts = [f"API error {response.status_code} {response.reason_phrase}".rstrip()]
        if hint := STATUS_HINTS.get(response.status_code, ""):
            parts.append(hint)
        # Only echo a JSON error body, and only a bounded slice of it: an HTML
        # error page can carry tracebacks, settings and upstream names.
        if _is_json(response) and (body := response.text.strip()):
            parts.append(body[:MAX_ERROR_CHARS])
        raise APIError(response.status_code, " — ".join(parts))

    if len(response.content) > MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"response is {len(response.content)} bytes, over the {MAX_RESPONSE_BYTES} byte limit "
            "— narrow the query or lower limit"
        )
    if not response.content:
        return {"status": response.status_code, "body": None}
    # Decided by the body, not the header: the endpoints are served by several
    # backends and not all of them are known to label JSON as such. An HTML
    # page or a binary file does not parse, so neither reaches the model.
    try:
        return response.json()
    except ValueError as error:
        content_type = response.headers.get("content-type", "unknown")
        raise RuntimeError(
            f"expected JSON from {path}, got an unparsable body (content-type '{content_type}')"
        ) from error


def _is_json(response: httpx.Response) -> bool:
    return response.headers.get("content-type", "").split(";")[0].strip() == "application/json"
