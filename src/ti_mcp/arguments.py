# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Tool arguments as typed models: one model per tool both checks what the
caller sent and produces the tool's inputSchema, so the two cannot drift.

The checks themselves are the ones in params.py; the models only say which
check applies to which argument. Their messages name the argument and the
value, because the model reads them and has to fix the call.
"""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, PlainValidator, ValidationError, WithJsonSchema
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue

from ti_mcp.catalog import (
    DEFAULT_LIMIT,
    HUNTING_RULES_COLLECTIONS,
    KNOWN_COLLECTIONS,
    Category,
    resolve_collection,
)
from ti_mcp.params import (
    as_int,
    check_date,
    check_flag,
    check_id,
    check_offset,
    check_path,
    extra_params,
    query_params,
)
from ti_mcp.settings import OFFSET_WINDOW, SCROLL_OPEN_INTERVAL


def checked(kind: Any, check: Callable[[Any], Any], schema: JsonSchemaValue) -> Any:
    """An argument of type `kind` validated by one of the params.py checks and
    shown to the client as `schema`. The check alone decides what passes: no
    coercion by pydantic before or after it."""
    return Annotated[kind, PlainValidator(check), WithJsonSchema(schema)]


def _required_text(name: str) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")
        return value.strip()

    return check


def _optional_collection(value: Any) -> str | None:
    # An empty name means "all collections", as it always has.
    return resolve_collection(value) if value else None


def _flag(name: str) -> Callable[[Any], int | None]:
    return lambda value: check_flag(value, name)


def _date(name: str) -> Callable[[Any], str | None]:
    return lambda value: check_date(value, name)


STRING = {"type": "string"}
NUMBER = {"type": "number"}
BOOLEAN = {"type": "boolean"}
OBJECT = {"type": "object"}

# JSON numbers that must be whole: "number" in the schema because clients send
# 10.0 as readily as 10, the check then refuses 10.5.
CollectionName = checked(str, resolve_collection, STRING)
Limit = checked(int | None, lambda value: as_int("limit", value, minimum=1), NUMBER)
SeqUpdate = checked(int | None, lambda value: as_int("seq_update", value, minimum=0), NUMBER)
Offset = checked(int | None, check_offset, NUMBER)
HuntingRules = checked(int | None, _flag("apply_hunting_rules"), NUMBER)
ExtraParams = checked(dict[str, Any], extra_params, OBJECT)

COLLECTION_DESCRIPTION = (
    "Collection name without an endpoint suffix, e.g. \"ioc/common\" or "
    "\"compromised/account_group\". Known: " + ", ".join(KNOWN_COLLECTIONS) + ". "
    "Unknown names are passed through as-is; ti_list_collections shows what this account "
    "may actually read, ti_describe_collections what each one contains."
)
QUERY_DESCRIPTION = (
    "Optional q filter. Free text matches any attribute (\"8.8.8.8\"); \"attribute:value\" "
    "narrows it (\"domain:example.com\", \"email:a@b.com\"). Valid attributes are the "
    "collection's response fields — see ti_describe_collections."
)
HUNTING_DESCRIPTION = (
    "0 or 1. Applies this account's hunting rules so only matching data comes back. "
    "Supported by: " + ", ".join(HUNTING_RULES_COLLECTIONS) + "."
)
EXTRA_DESCRIPTION = (
    "Any further query parameters, passed through verbatim — e.g. "
    "{\"tags[filterSpam][]\": 1} to drop spam from compromised/messenger, or "
    "{\"has_exploit\": 1} for osi/vulnerability."
)
LIMIT_DESCRIPTION = f"Integer. Records per request. Default {DEFAULT_LIMIT}; capped per collection."
LANG_DESCRIPTION = "Response language, e.g. \"en\" or \"ru\"."
DATE_DESCRIPTION = "{param} — YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ."


class Arguments(BaseModel):
    """Base of every tool's arguments. Unknown keys are ignored, as they always were."""


class ListCollectionsArguments(Arguments):
    pass


class GetCollectionArguments(Arguments):
    collection: CollectionName = Field(description=COLLECTION_DESCRIPTION)
    query: str | None = Field(None, description=QUERY_DESCRIPTION)
    offset: Offset = Field(
        None,
        description=(
            "Integer. Skip this many records: 0 for the first page, then offset += limit. "
            f"offset + limit must stay within {OFFSET_WINDOW}. Not used with scroll=true."
        ),
    )
    scroll: checked(int | None, _flag("scroll"), BOOLEAN) = Field(
        None,
        description=(
            f"true = iterate with resultId instead of offset, for sets beyond {OFFSET_WINDOW} "
            "records or a full walk. Default false."
        ),
    )
    result_id: str | None = Field(
        None,
        description=(
            "Only with scroll=true: resultId from the previous response. Normally omit it "
            "— the remembered one is used automatically."
        ),
    )
    restart: checked(int | None, _flag("restart"), BOOLEAN) = Field(
        None,
        description=(
            "Only with scroll=true: ignore the remembered resultId and open a new scroll "
            "from the first page (on some collections allowed once per "
            f"{SCROLL_OPEN_INTERVAL} s)."
        ),
    )
    limit: Limit = Field(None, description=LIMIT_DESCRIPTION)
    date_from: checked(str | None, _date("date_from"), STRING) = Field(
        None, description=DATE_DESCRIPTION.format(param="df")
    )
    date_to: checked(str | None, _date("date_to"), STRING) = Field(
        None, description=DATE_DESCRIPTION.format(param="dt")
    )
    apply_hunting_rules: HuntingRules = Field(None, description=HUNTING_DESCRIPTION)
    lang: str | None = Field(None, description=LANG_DESCRIPTION)
    extra_params: ExtraParams = Field(default_factory=dict, description=EXTRA_DESCRIPTION)


class GetUpdatesArguments(Arguments):
    collection: CollectionName = Field(description=COLLECTION_DESCRIPTION)
    seq_update: SeqUpdate = Field(
        None, description="Integer seqUpdate to continue from; omit for the first call."
    )
    query: str | None = Field(None, description=QUERY_DESCRIPTION)
    limit: Limit = Field(None, description=LIMIT_DESCRIPTION)
    date_from: checked(str | None, _date("date_from"), STRING) = Field(
        None, description=DATE_DESCRIPTION.format(param="df")
    )
    date_to: checked(str | None, _date("date_to"), STRING) = Field(
        None,
        description="dt — sent as pyf6 does, though the guide lists dt only for the Common API.",
    )
    apply_hunting_rules: HuntingRules = Field(None, description=HUNTING_DESCRIPTION)
    lang: str | None = Field(None, description=LANG_DESCRIPTION)
    extra_params: ExtraParams = Field(default_factory=dict, description=EXTRA_DESCRIPTION)


class GlobalSearchArguments(Arguments):
    query: checked(str, _required_text("query"), STRING) = Field(
        description="Indicator to look for, optionally as attribute:value."
    )


class GetSequenceListArguments(Arguments):
    date: checked(str | None, _date("date"), STRING) = Field(
        None, description="YYYY-MM-DD; omit for the current values."
    )
    collection: checked(str | None, _optional_collection, STRING) = Field(
        None, description="Optional: just this collection instead of all of them."
    )
    apply_hunting_rules: HuntingRules = Field(
        None,
        description=(
            "0 or 1. Sent through, but the server currently ignores it on this "
            "endpoint — the values returned are the unfiltered ones."
        ),
    )


class GetItemArguments(Arguments):
    collection: CollectionName = Field(description=COLLECTION_DESCRIPTION)
    id: checked(str, check_id, STRING) = Field(
        description="Record id from a collection or search result."
    )


class GraphLookupArguments(Arguments):
    kind: Literal["ip", "domain"] = Field(description="What is being looked up.")
    value: checked(str, _required_text("value"), STRING) = Field(
        description="The IP address or domain name."
    )


class DescribeCollectionsArguments(Arguments):
    collection: checked(str | None, _optional_collection, STRING) = Field(
        None, description="Optional: describe just this one."
    )
    category: Category | None = Field(None, description="Optional: only collections in this category.")
    include_fields: bool | None = Field(
        None,
        description=(
            "Include the response-field lists. Default true for a single collection, "
            "false for a listing."
        ),
    )


class RequestArguments(Arguments):
    path: checked(list[str], check_path, STRING) = Field(
        description="Path under /api/v2, without leading slash, e.g. \"malware/cnc/updated\"."
    )
    params: checked(dict[str, Any], lambda value: query_params(value, name="params"), OBJECT) = Field(
        default_factory=dict,
        description="Optional query parameters, e.g. {\"limit\": 100, \"seqUpdate\": 16394859}.",
    )


class _ToolSchema(GenerateJsonSchema):
    """inputSchema as clients have always seen it: an optional argument is its
    type, not anyOf with null; no defaults and no titles."""

    def nullable_schema(self, schema: Any) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def default_schema(self, schema: Any) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def field_title_should_be_set(self, schema: Any) -> bool:
        return False


def input_schema(model: type[Arguments]) -> dict[str, Any]:
    schema = model.model_json_schema(schema_generator=_ToolSchema)
    schema.pop("title", None)
    return schema


def describe_errors(error: ValidationError) -> str:
    """One line per bad argument, worded for the model that has to fix the call."""
    messages = []
    for item in error.errors(include_url=False):
        name = ".".join(str(part) for part in item["loc"])
        if item["type"] == "missing":
            messages.append(f"{name} is required")
        elif item["type"] == "value_error":
            # A params.py check: its message already names the argument.
            messages.append(str(item["ctx"]["error"]))
        else:
            messages.append(f"{name}: {item['msg']}")
    return "; ".join(messages)
