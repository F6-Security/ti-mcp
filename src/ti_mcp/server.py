# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""MCP server for the F6 Threat Intelligence API (https://ti.f6.security).

Built from the official API guides (General Info and Collections Info): Basic
auth with login + personal API key, REST/JSON under /api/v2, one request per
second per feed, per-feed record caps, the two iteration methods (Common API
with resultId, Updated API with seqUpdate), the helper endpoints (search,
sequence_list, granted_collections) and the response fields of every collection.

Endpoint shapes are cross-checked against the official client
https://pypi.org/project/pyf6/ (pyf6/pyf6.py, pyf6/const.py), which is
what the vendor's own integrations use.

The server-side behaviour that the guides leave out (scroll-open limit, resultId
TTL, searches that disable scrolling, parameters the backend ignores) was
verified against the service itself.
"""

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import ValidationError

from ti_mcp import __version__
from ti_mcp.arguments import (
    Arguments,
    DescribeCollectionsArguments,
    GetCollectionArguments,
    GetItemArguments,
    GetSequenceListArguments,
    GetUpdatesArguments,
    GlobalSearchArguments,
    GraphLookupArguments,
    ListCollectionsArguments,
    RequestArguments,
    describe_errors,
    input_schema,
)
from ti_mcp.catalog import (
    COLLECTIONS,
    DEFAULT_LIMIT,
    DEPRECATED,
    KNOWN_COLLECTIONS,
    ONLY_COMMON,
    describe,
    warnings_for,
)
from ti_mcp.client import APIError, TIClient
from ti_mcp.params import ResultIdCache, clamp_limit
from ti_mcp.settings import (
    MAX_ERROR_TEXT_CHARS,
    OFFSET_WINDOW,
    SCROLL_OPEN_INTERVAL,
    Settings,
    SettingsError,
)

READ_ONLY = types.ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
LOCAL_ONLY = types.ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)


@dataclass
class AppState:
    """What lives as long as the server: the settings, the API client with its
    connection pool and throttle, and the scrolls this process has open."""

    settings: Settings
    client: TIClient
    result_ids: ResultIdCache
    tools: list[types.Tool]


# A handler gets the server state, its validated arguments and a list to put
# notes in; it returns what goes back to the model as JSON.
Handler = Callable[[AppState, Any, list[str]], Awaitable[Any]]


@dataclass(frozen=True)
class ToolSpec:
    """One tool: what the client is told about it, what it accepts and what it does."""

    name: str
    # A function of the settings where the text quotes one of them.
    description: str | Callable[[Settings], str]
    arguments: type[Arguments]
    handler: Handler
    annotations: types.ToolAnnotations

    def tool(self, settings: Settings) -> types.Tool:
        description = self.description(settings) if callable(self.description) else self.description
        return types.Tool(
            name=self.name,
            description=description,
            annotations=self.annotations,
            inputSchema=input_schema(self.arguments),
        )


# Tools by name, in the order they are listed to the client.
TOOLS: dict[str, ToolSpec] = {}


def tool(
    name: str,
    arguments: type[Arguments],
    description: str | Callable[[Settings], str],
    annotations: types.ToolAnnotations = READ_ONLY,
) -> Callable[[Handler], Handler]:
    """Registers the decorated handler as the tool `name`."""

    def register(handler: Handler) -> Handler:
        TOOLS[name] = ToolSpec(name, description, arguments, handler, annotations)
        return handler

    return register


@tool(
    "ti_list_collections",
    ListCollectionsArguments,
    "List the collections this account may read: GET /api/v2/user/granted_collections. "
    "Each entry carries collection, label, route (NO_ROUTE means no data) and "
    "huntingRulesUsed. This is the guide's own configuration self-test — call it first "
    "to confirm credentials, IP allow-listing and access all work.",
)
async def list_collections(state: AppState, args: ListCollectionsArguments, notes: list[str]) -> Any:
    return await state.client.get("user/granted_collections", throttle_key="user/granted_collections")


def _get_collection_description(settings: Settings) -> str:
    return (
        "Common API — read records from a collection: GET /api/v2/{collection}. This is "
        "both the browse and the search call: add query to filter, df/dt to bound by date. "
        "The response carries count and items; records come back newest-first. "
        "Default paging is by offset: the first call returns the newest page, the next one "
        "passes offset += limit, until offset reaches count. The backend caps offset + limit "
        f"at {OFFSET_WINDOW}, which is plenty for answering questions. Set scroll=true only "
        f"to export a result set beyond {OFFSET_WINDOW} records or to walk a whole "
        "collection: the response then carries resultId, which this tool remembers per "
        "collection+filter and passes back automatically on the next call (stop when items is "
        f"empty; an id stays valid ~{settings.result_id_ttl:.0f} s after its last use, and on some "
        f"collections a NEW scroll is allowed only once per {SCROLL_OPEN_INTERVAL} s). Use "
        "ti_get_updates instead when tracking a feed continuously."
    )


@tool("ti_get_collection", GetCollectionArguments, _get_collection_description)
async def get_collection(state: AppState, args: GetCollectionArguments, notes: list[str]) -> Any:
    collection = args.collection
    notes.extend(warnings_for(collection, method="common"))
    params: dict[str, Any] = {
        "q": args.query,
        "limit": clamp_limit(collection, args.limit),
        "offset": args.offset,
        "df": args.date_from,
        "dt": args.date_to,
        "apply_hunting_rules": args.apply_hunting_rules,
        "lang": args.lang,
        **args.extra_params,
    }
    result_id = args.result_id or None
    if args.scroll:
        return await scroll_collection(state, collection, params, result_id, bool(args.restart), notes)
    if result_id is not None or args.restart:
        raise ValueError(
            "result_id and restart apply to scroll=true only; the default mode pages with offset"
        )
    # Offset paging: no scroll is opened, so neither the scroll-open limit nor
    # the resultId TTL applies, and the cache stays untouched.
    result = await state.client.get(collection, {**params, "use_scroll": 0}, throttle_key=collection)
    if isinstance(result, dict):
        if result.get("resultId") is None:
            # use_scroll=0 means no scroll; a null id would only invite the
            # model to wait for one.
            result.pop("resultId", None)
        else:
            notes.append(
                "The server ignored use_scroll=0 and opened a scroll for this "
                "collection: offset paging may not work here. Call again with "
                "scroll=true to iterate with resultId."
            )
    return result


async def scroll_collection(
    state: AppState,
    collection: str,
    params: dict[str, Any],
    result_id: str | None,
    restart: bool,
    notes: list[str],
) -> Any:
    """ti_get_collection with scroll=true: iterate with resultId, remembered per filter."""
    cache_key = state.result_ids.key(collection, params)
    from_cache = False
    if restart:
        state.result_ids.drop(cache_key)
    elif result_id is None and (cached := state.result_ids.get(cache_key)):
        result_id, from_cache = cached, True
        notes.append(
            f"Continued the scroll already open for this filter (resultId {cached}) "
            "instead of starting a new one, because some collections allow a new scroll "
            f"only once per {SCROLL_OPEN_INTERVAL} s. Pass restart=true "
            "to read from the first page again."
        )
    try:
        result = await state.client.get(
            collection, {**params, "resultId": result_id}, throttle_key=collection
        )
    except APIError as error:
        # An expired id is a 400 with an empty body or, depending on the
        # collection, a 404 "masked scroll id not found".
        if error.status not in (400, 404) or not from_cache:
            raise
        # The remembered id outlived the backend's TTL; start over once.
        state.result_ids.drop(cache_key)
        notes.append(
            f"The remembered resultId {result_id} had expired on the server; "
            "opened a new scroll from the first page."
        )
        result = await state.client.get(collection, params, throttle_key=collection)
    if isinstance(result, dict):
        new_id = result.get("resultId")
        if isinstance(new_id, str) and new_id and result.get("items"):
            state.result_ids.put(cache_key, new_id)
        elif isinstance(new_id, str) and new_id:
            # Empty page: the scroll is exhausted, the next call starts over.
            state.result_ids.drop(cache_key)
        else:
            state.result_ids.drop(cache_key)
            if "resultId" in result:
                notes.append(
                    "resultId is null: the server does not scroll this kind of query "
                    "(ip:/domain:/hash: searches). Call again without scroll=true and page "
                    "with offset — increase it by limit until it reaches count."
                )
    return result


@tool(
    "ti_get_updates",
    GetUpdatesArguments,
    "Updated API — poll a collection for records changed since a point in the update "
    "sequence: GET /api/v2/{collection}/updated. Start with a seq_update from "
    "ti_get_sequence_list (or omit it, optionally bounding with date_from), then feed "
    "the seqUpdate value from each response into the next call. Records come back "
    "oldest-first; stop when items is empty. Every record in TI has a unique seqUpdate "
    "and a record that gets updated is renumbered, so it resurfaces. Not available for "
    + ", ".join(ONLY_COMMON) + " — use ti_get_collection for those.",
)
async def get_updates(state: AppState, args: GetUpdatesArguments, notes: list[str]) -> Any:
    collection = args.collection
    if collection in ONLY_COMMON:
        raise ValueError(
            f'Collection "{collection}" has no /updated endpoint — use ti_get_collection '
            "and iterate with result_id instead."
        )
    notes.extend(warnings_for(collection, method="updated"))
    return await state.client.get(
        f"{collection}/updated",
        {
            "seqUpdate": args.seq_update,
            "q": args.query,
            "limit": clamp_limit(collection, args.limit),
            "df": args.date_from,
            "dt": args.date_to,
            "apply_hunting_rules": args.apply_hunting_rules,
            "lang": args.lang,
            **args.extra_params,
        },
        throttle_key=collection,
    )


@tool(
    "ti_global_search",
    GlobalSearchArguments,
    "Global search across every collection: GET /api/v2/search?q=... Answers which "
    "collections hold the indicator and how many records each has (apiPath, label, "
    "link, count). Start here when you have an indicator but not a collection, then "
    "pull the detail with ti_get_collection using the same query. Accepts free text "
    "(\"8.8.8.8\") or attribute:value (\"email:example@gmail.com\").",
)
async def global_search(state: AppState, args: GlobalSearchArguments, notes: list[str]) -> Any:
    return await state.client.get("search", {"q": args.query}, throttle_key="search")


@tool(
    "ti_get_sequence_list",
    GetSequenceListArguments,
    "GET /api/v2/sequence_list — the current seqUpdate of every collection, i.e. the "
    "starting points for ti_get_updates. Pass date to get the seqUpdate each collection "
    "stood at on that date, which is how you backfill from a chosen day rather than "
    "from the beginning of the feed.",
)
async def get_sequence_list(state: AppState, args: GetSequenceListArguments, notes: list[str]) -> Any:
    return await state.client.get(
        "sequence_list",
        {
            "date": args.date,
            "collection": args.collection,
            "apply_hunting_rules": args.apply_hunting_rules,
        },
        throttle_key="sequence_list",
    )


@tool(
    "ti_get_item",
    GetItemArguments,
    "Fetch one record by id: GET /api/v2/{collection}/{id}. Ids come from "
    "ti_get_collection or ti_get_updates results. Not every collection supports it — a "
    "404 here does not mean the record is gone, only that this collection has no "
    "by-id endpoint.",
)
async def get_item(state: AppState, args: GetItemArguments, notes: list[str]) -> Any:
    notes.extend(warnings_for(args.collection, method="item"))
    return await state.client.get(f"{args.collection}/{args.id}", throttle_key=args.collection)


@tool(
    "ti_graph_lookup",
    GraphLookupArguments,
    "WHOIS/graph enrichment for one IP or domain: GET /api/v2/utils/graph/ip?ip=... or "
    "GET /api/v2/utils/graph/domain?domain=... Complements the collections — it "
    "describes the object itself rather than the threat records mentioning it.",
)
async def graph_lookup(state: AppState, args: GraphLookupArguments, notes: list[str]) -> Any:
    return await state.client.get(
        f"utils/graph/{args.kind}", {args.kind: args.value}, throttle_key=f"utils/graph/{args.kind}"
    )


@tool(
    "ti_describe_collections",
    DescribeCollectionsArguments,
    "Reference data from the API guides, answered locally with no API call and no "
    "rate-limit cost: for each collection its category, availability (общая vs "
    "индивидуальная), TTL, Admiralty code, severity, max records per request, which "
    "iteration methods it supports, whether apply_hunting_rules applies, and "
    "its response fields — which are also the attributes usable as q=field:value. "
    "Call this before ti_get_collection to pick the right collection and filter.",
    annotations=LOCAL_ONLY,
)
async def describe_collections(
    state: AppState, args: DescribeCollectionsArguments, notes: list[str]
) -> Any:
    if args.collection:
        include = True if args.include_fields is None else args.include_fields
        return describe(args.collection, include_fields=include)
    include = bool(args.include_fields)
    names = [c for c in KNOWN_COLLECTIONS if not args.category or COLLECTIONS[c].category == args.category]
    ttl = state.settings.result_id_ttl
    return {
        "default_max_records_per_request": DEFAULT_LIMIT,
        "requests_per_second_per_feed": 1,
        "new_scroll_per_collection": (
            f"up to once per {SCROLL_OPEN_INTERVAL} s on some collections (a Common API call "
            "without resultId); "
            "with scroll=true, ti_get_collection reuses the remembered resultId to stay "
            "within it"
        ),
        "result_id_ttl_seconds": ttl,
        "offset_window": OFFSET_WINDOW,
        "iteration": {
            "common_api": (
                "GET /api/v2/{collection}: by default page with offset up to count "
                f"(offset + limit within {OFFSET_WINDOW}); with scroll=true iterate "
                f"with resultId (valid {ttl:.0f} s after last use)"
            ),
            "updated_api": "GET /api/v2/{collection}/updated, iterate with seqUpdate",
        },
        "deprecated": DEPRECATED,
        "collections": [describe(c, include_fields=include) for c in names],
    }


@tool(
    "ti_request",
    RequestArguments,
    "Escape hatch for a documented read-only TI endpoint this server does not model: "
    "performs GET /api/v2/{path} with the given query parameters and returns the raw "
    "JSON. Example: path \"malware/malware/network/<id>\", or path "
    "\"ioc/common/updated\" with {\"limit\": 5000}. Rate limiting still applies. "
    "The path must start with a collection section or one of search, sequence_list, "
    "user, utils. Refused: action segments ({collection}/{id}/action/{action} — the API "
    "performs those on GET, and this tool is read-only) and file segments (binary "
    "files, not JSON).",
)
async def request(state: AppState, args: RequestArguments, notes: list[str]) -> Any:
    # Throttle per feed: the first two segments name the collection.
    throttle_key = "/".join(args.path[:2])
    return await state.client.get("/".join(args.path), args.params, throttle_key=throttle_key)


def tools(settings: Settings) -> list[types.Tool]:
    """The tool list; built from the settings because a description quotes the resultId TTL."""
    return [spec.tool(settings) for spec in TOOLS.values()]


def app_state(settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> AppState:
    """A fresh state; the caller closes state.client. transport replaces the network (tests)."""
    return AppState(
        settings=settings,
        client=TIClient(settings, transport=transport),
        result_ids=ResultIdCache(settings.result_id_ttl),
        tools=tools(settings),
    )


async def on_list_tools(
    ctx: ServerRequestContext[Any],
    params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    state: AppState = ctx.lifespan_context
    return types.ListToolsResult(tools=state.tools)


async def on_call_tool(
    ctx: ServerRequestContext[Any],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    state: AppState = ctx.lifespan_context
    spec = TOOLS.get(params.name)
    if spec is None:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"Unknown tool: {params.name}")],
            isError=True,
        )
    notes: list[str] = []
    try:
        args = spec.arguments.model_validate(params.arguments or {})
        result = await spec.handler(state, args, notes)
        payload = json.dumps(result, indent=2, ensure_ascii=False)
        if notes:
            payload = "\n".join(f"Note: {note}" for note in notes) + "\n\n" + payload
        return types.CallToolResult(content=[types.TextContent(type="text", text=payload)])
    except Exception as error:
        if isinstance(error, ValidationError):
            detail = describe_errors(error)
        else:
            # Some exceptions (httpx timeouts) stringify to nothing — never
            # return a bare "Error:" to the model.
            detail = str(error) or type(error).__name__
        # Bounded: an error can carry an API body.
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"Error: {detail[:MAX_ERROR_TEXT_CHARS]}")],
            isError=True,
        )


def build_server(settings: Settings) -> Server[AppState]:
    """The MCP server; its state is created when it starts serving and closed when it stops."""

    @asynccontextmanager
    async def lifespan(_: Server[AppState]) -> AsyncIterator[AppState]:
        state = app_state(settings)
        try:
            yield state
        finally:
            await state.client.aclose()

    return Server(
        "ti-mcp",
        version=__version__,
        lifespan=lifespan,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


async def main(settings: Settings) -> None:
    server = build_server(settings)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def cli() -> None:
    """Console-script entry point. A bad setting stops the server before it serves anything."""
    try:
        settings = Settings.from_env()
    except SettingsError as error:
        raise SystemExit(f"ti-mcp: {error}") from None
    asyncio.run(main(settings))


if __name__ == "__main__":
    cli()
