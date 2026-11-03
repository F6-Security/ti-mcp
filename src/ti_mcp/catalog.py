# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""The collection catalogue from the API guides, and lookups over it."""

import re
from dataclasses import dataclass
from typing import Any, Literal

DEFAULT_LIMIT = 100

Category = Literal["leaks", "malware", "attacks", "suspicious_ip", "threats", "hidden"]
CATEGORIES: tuple[Category, ...] = ("leaks", "malware", "attacks", "suspicious_ip", "threats", "hidden")
# общая ("common"), индивидуальная ("individual") or both.
Availability = Literal["common", "individual", "common+individual"]


@dataclass(frozen=True)
class Collection:
    """One collection as the API guides describe it.

    None in a descriptive field means the guides leave it out, not that it is
    empty: the value is reported as unknown.
    """

    category: Category
    # The section and name the web portal shows it under.
    label: str
    # Max records per request, from the "Лимит записей" table.
    limit: int
    availability: Availability | None
    ttl_days: int | None
    # Admiralty code; free text because the guides give ranges ("A2..C1", "mostly B2").
    admiralty: str | None
    # 1..10, or a range as text where it depends on the source.
    severity: int | str | None
    # Response attributes, which are also the attributes usable as q=<field>:<value>.
    fields: tuple[str, ...]
    # A *_group collection: events of one entity merged into one record.
    group: bool = False
    # Only the Common API: no /updated endpoint.
    only_common: bool = False
    # apply_hunting_rules=1 narrows the answer to this account's hunting rules.
    hunting_rules: bool = False
    # Records carry files, served by {collection}/{id}/file/{file_id}.
    has_files: bool = False
    # What a caller should know that the fields above do not say.
    note: str | None = None

# One entry per collection. limit comes from the "Лимит записей" table in
# General Info (feeds absent from it fall back to the documented default of
# 100); ttl/admiralty/severity/availability/fields come from Collections Info.
# fields are the response attributes, which double as the searchable attributes
# for q=<field>:<value>.
COLLECTIONS: dict[str, Collection] = {
    # --- Категория Утечки -------------------------------------------------
    "compromised/account_group": Collection(
        category="leaks", label="Утечки :: Аккаунты", limit=500,
        availability="individual", ttl_days=90, admiralty="A2", severity=None,
        group=True,
        fields=("id", "dateFirstSeen", "dateLastSeen", "dateFirstCompromised",
                "dateLastCompromised", "port", "login", "password", "parsedLogin",
                "service", "events", "eventCount", "evaluation", "displayOptions",
                "malware", "threatActor", "source", "sourceType", "sourceId", "settings"),
    ),
    "compromised/bank_card_group": Collection(
        category="leaks", label="Утечки :: Банковские карты", limit=500,
        availability="individual", ttl_days=90, admiralty="A2", severity=None,
        group=True,
        fields=("id", "cardInfo", "events", "eventCount", "dateFirstSeen", "dateLastSeen",
                "dateFirstCompromised", "dateLastCompromised", "evaluation", "stixGuid",
                "displayOptions", "malware", "threatActor", "source", "sourceType",
                "sourceId", "settings"),
    ),
    "compromised/masked_card": Collection(
        category="leaks", label="Утечки :: Банковские карты (маскированные)", limit=500,
        availability="individual", ttl_days=90, admiralty="A2", severity=None,
        fields=("id", "cardInfo", "client", "cnc", "dateDetected", "dateCompromised",
                "displayOptions", "evaluation", "isDump", "isExpired", "isMasked",
                "malware", "owner", "sourceLink", "sourceType", "threatActor", "track"),
    ),
    "compromised/suspicious_payment": Collection(
        category="leaks", label="Утечки :: Подозрительные платёжные реквизиты",
        limit=DEFAULT_LIMIT,
        availability="common", ttl_days=90, admiralty="C3", severity=None,
        fields=("bankCard", "country", "dateFirstPublished", "dateFirstSeen",
                "dateLastPublished", "dateLastSeen", "displayOptions", "evaluation",
                "events", "eventsCount", "iban", "id", "service", "serviceType"),
    ),
    "osi/public_leak": Collection(
        category="leaks", label="Утечки :: Публичные утечки", limit=100,
        availability="individual", ttl_days=90, admiralty="C3", severity=None,
        hunting_rules=True,
        fields=("bind", "created", "data", "displayOptions", "evaluation", "hash", "id",
                "language", "linkList", "matches", "updated"),
    ),
    "osi/git_repository": Collection(
        category="leaks", label="Утечки :: Git утечки", limit=100,
        availability="individual", ttl_days=90, admiralty="A1", severity=None,
        fields=("company", "companyId", "contributors", "dataFound", "dateCreated",
                "dateDetected", "evaluation", "files", "id", "matchesTypes", "name",
                "numberOf", "relations", "source"),
    ),
    "compromised/breached": Collection(
        category="leaks", label="Утечки :: Утечки баз данных", limit=100,
        availability="individual", ttl_days=90, admiralty="C3", severity=None,
        only_common=True, hunting_rules=True,
        fields=("addInfo", "description", "downloadLinkList", "email", "evaluation", "id",
                "leakName", "leakPublished", "password", "taName", "updateTime", "uploadTime"),
    ),
    "compromised/access": Collection(
        category="leaks", label="Утечки :: Магазины", limit=500,
        availability="individual", ttl_days=90, admiralty="A2", severity=None,
        fields=("id", "name", "source", "companyId", "dateCreated", "dateDetected", "files",
                "contributors", "numberOf", "dataFound", "evaluation", "relations",
                "displayOptions"),
    ),
    "compromised/mule": Collection(
        category="leaks", label="Утечки :: Дропы", limit=500,
        availability=None, ttl_days=None, admiralty=None, severity=None,
        note="Only appears in the record-limit table of General Info; no field "
                "description in Collections Info and not in pyf6's collection list.",
        fields=(),
    ),

    # --- Категория Вредоносное ПО ----------------------------------------
    "malware/config": Collection(
        category="malware", label="ВПО :: Конфигурации", limit=100,
        availability="individual", ttl_days=90, admiralty="A1", severity=9,
        fields=("content", "contentLen", "dateFirstSeen", "dateLastSeen", "domainList",
                "file", "hash", "id", "ipList", "malware", "source"),
    ),
    "malware/malware": Collection(
        category="malware", label="ВПО :: Отчёты", limit=100,
        availability="common", ttl_days=None, admiralty=None, severity=7,
        fields=("aliases", "category", "id", "class", "fileIocList", "name", "platform",
                "platformOptions", "portalLink", "signatureCount", "signatureList",
                "fileCount", "configCount", "configList", "updatedAt", "attachedFile",
                "author", "deleted", "description", "geoRegion", "history", "langs",
                "seenCount", "shortDescription", "sourceCountry", "stixGuid",
                "threatActorList", "threatLevel", "threatLevelOptions", "yaraCount",
                "yaraRuleList"),
    ),
    "malware/signature": Collection(
        category="malware", label="ВПО :: Signatures (Suricata)", limit=5000,
        availability="common", ttl_days=365, admiralty=None, severity=8,
        fields=("alertHistory", "alertNum", "class", "content", "createdAt", "id", "malware",
                "name", "severity", "sid", "sourceName"),
    ),
    "malware/yara": Collection(
        category="malware", label="ВПО :: Yara rules", limit=5000,
        availability="common", ttl_days=365, admiralty=None, severity=8,
        fields=("alertNum", "class", "content", "createdAt", "id", "malware", "name",
                "sourceName"),
    ),
    "attacks/phishing_kit": Collection(
        category="malware", label="ВПО :: Фишинг комплекты", limit=1000,
        availability="common", ttl_days=30, admiralty="mostly B2", severity=9,
        note="Collections Info documents this as the current endpoint for фишинг-комплекты, "
                "while pyf6 marks it deprecated in favour of malware/phishing_kit. Both are "
                "accepted here; check ti_list_collections for what this account is granted.",
        fields=("id", "hash", "dateDetected", "dateFirstSeen", "dateLastSeen",
                "downloadedFrom", "emails", "evaluation", "login", "path", "source",
                "targetBrand", "telegramIds", "variables", "threatActors", "isFavourite",
                "isHidden", "settings"),
    ),
    "malware/phishing_kit": Collection(
        category="malware", label="ВПО :: Фишинг комплекты", limit=5000,
        availability="common", ttl_days=30, admiralty="mostly B2", severity=9,
        note="Present in the record-limit table and in pyf6's active collection list; "
                "Collections Info describes the same data under attacks/phishing_kit.",
        fields=(),
    ),
    "osi/vulnerability": Collection(
        category="malware", label="ВПО :: Уязвимости", limit=200,
        availability="common", ttl_days=30, admiralty="A1", severity=9,
        hunting_rules=True,
        fields=("affectedSoftware", "bulletinFamily", "cpe", "cpeTable", "cvss",
                "cvssAttackVector", "darkweb", "dateLastSeen", "dateModified",
                "datePublished", "description", "evaluation", "id", "portalLink", "cveList",
                "cveListEpss", "displayOptions", "epss", "exploitCount", "exploitList",
                "extDescription", "githubLinkList", "hasExploit", "mergedCvss",
                "mergedCvssVector", "provider", "references", "reporter", "seenInTheWild",
                "softwareMixed", "threatsList", "timeLineData"),
    ),

    # --- Категория Атаки --------------------------------------------------
    "attacks/ddos": Collection(
        category="attacks", label="Атаки :: DDoS", limit=5000,
        availability="common", ttl_days=30, admiralty="A2", severity=3,
        hunting_rules=True,
        fields=("id", "dateBegin", "dateEnd", "dateReg", "malware", "evaluation", "duration",
                "protocol", "source", "target", "threatActor", "cnc", "messageLink",
                "sourceRowId", "stixGuid", "requestData", "type", "displayOptions",
                "settings"),
    ),
    "attacks/phishing_group": Collection(
        category="attacks", label="Атаки :: Фишинг", limit=1000,
        availability="common", ttl_days=30, admiralty="A2-A3", severity=6,
        group=True, hunting_rules=True,
        fields=("brand", "countPhishing", "date", "domain", "domainInfo", "evaluation",
                "falsePositive", "id", "ip", "threatActor", "urlListLink", "whitelist",
                "phishing", "objective", "phishingKitArray", "screenshot", "signature",
                "source", "status", "uniqueTitles", "displayOptions"),
    ),
    "attacks/deface": Collection(
        category="attacks", label="Атаки :: Дефейсы", limit=100,
        availability="common", ttl_days=30, admiralty="B2", severity=3,
        fields=("contacts", "date", "displayOptions", "evaluation", "id", "mirrorLink",
                "portalLink", "providerDomain", "siteUrl", "source", "targetDomain",
                "targetDomainProvider", "targetIp", "threatActor", "tsCreate"),
    ),

    # --- Категория Опасные IP --------------------------------------------
    "suspicious_ip/tor_node": Collection(
        category="suspicious_ip", label="Опасные IP :: Tor", limit=100,
        availability="common", ttl_days=30, admiralty="A1", severity=3,
        hunting_rules=True,
        fields=("bind", "dateFirstSeen", "dateLastSeen", "evaluation", "id", "ipv4",
                "nodes", "portalLink", "source"),
    ),
    "suspicious_ip/open_proxy": Collection(
        category="suspicious_ip", label="Опасные IP :: Открытые прокси", limit=5000,
        availability="common", ttl_days=15, admiralty="C3", severity=3,
        hunting_rules=True,
        fields=("dateDetected", "dateFirstSeen", "dateLastSeen", "evaluation", "id", "ipv4",
                "port", "portalLink", "source", "sources", "stixGuid", "type"),
    ),
    "suspicious_ip/socks_proxy": Collection(
        category="suspicious_ip", label="Опасные IP :: Socks прокси на боте", limit=5000,
        availability="common", ttl_days=2, admiralty="A1", severity=3,
        hunting_rules=True,
        fields=("bind", "dateDetected", "dateFirstSeen", "dateLastSeen", "evaluation", "id",
                "ipv4", "portalLink", "source", "stixGuid"),
    ),
    "suspicious_ip/vpn": Collection(
        category="suspicious_ip", label="Опасные IP :: VPN", limit=100,
        availability="common", ttl_days=30, admiralty="A2", severity=1,
        hunting_rules=True,
        fields=("bind", "dateFirstSeen", "dateLastSeen", "evaluation", "id", "ipv4", "names",
                "portalLink", "rules", "source", "sources", "types"),
    ),
    "suspicious_ip/scanner": Collection(
        category="suspicious_ip", label="Опасные IP :: Сканирование IP", limit=5000,
        availability="common", ttl_days=30, admiralty="C3", severity=1,
        hunting_rules=True,
        fields=("bind", "categories", "dateFirstSeen", "dateLastSeen", "evaluation", "id",
                "ipv4", "portalLink", "sources"),
    ),

    # --- Категория Угрозы -------------------------------------------------
    "apt/threat_actor": Collection(
        category="threats", label="Угрозы :: Атакующие (APT)", limit=100,
        availability="common+individual", ttl_days=365, admiralty=None, severity=9,
        fields=("addedToThreatLandscapeFor", "aliases", "author", "country", "createdAt",
                "deleted", "description", "displayOptions", "files", "goals", "hasIocs",
                "history", "id", "isAPT", "isPublished", "labels", "langs", "name",
                "reportSeen", "stat", "stixGuid", "updatedAt", "countries", "cve",
                "dateFirstSeen", "dateLastSeen", "malware", "regions", "reports", "sectors",
                "targetedCompany"),
    ),
    "hi/threat_actor": Collection(
        category="threats", label="Угрозы :: Атакующие (HI)", limit=100,
        availability="common+individual", ttl_days=365, admiralty=None, severity=9,
        fields=("addedToThreatLandscapeFor", "aliases", "author", "country", "createdAt",
                "deleted", "description", "displayOptions", "files", "goals", "hasIocs",
                "history", "id", "isAPT", "isPublished", "labels", "langs", "name",
                "reportSeen", "sentForLangs", "spokenOnLangs", "stat", "stixGuid",
                "threatLandscapeOptions", "updatedAt", "allIndicatorsCount",
                "allReportsCount", "contactsCount", "countries", "cve", "dateFirstSeen",
                "dateLastSeen", "expertise", "forumsAccountsCount", "malware", "regions",
                "relatedThreatActorsCount", "reports", "sectors", "targetedCompany",
                "targetedPartnersAndClients"),
    ),
    "apt/threat": Collection(
        category="threats", label="Угрозы :: Последние угрозы (APT)", limit=10,
        availability="common+individual", ttl_days=90, admiralty="varies", severity=9,
        hunting_rules=True, has_files=True,
        fields=("author", "createdAt", "cveList", "dateFirstSeen", "dateLastSeen",
                "datePublished", "displayOptions", "evaluation", "files", "hasIocs", "id",
                "indicatorRelationships", "indicators", "isPublished", "langs", "malwareList",
                "mitreMatrix", "regions", "relatedThreatActors", "reportNumber",
                "reportRating", "sectors", "sources", "stixGuid", "targetedCompany",
                "threatActor", "updatedAt"),
    ),
    "hi/threat": Collection(
        category="threats", label="Угрозы :: Последние угрозы (HI)", limit=10,
        availability="common+individual", ttl_days=90, admiralty="varies", severity=9,
        hunting_rules=True, has_files=True,
        fields=("author", "createdAt", "cveList", "dateFirstSeen", "dateLastSeen",
                "datePublished", "displayOptions", "evaluation", "expertise", "files",
                "forumsAccounts", "hasIocs", "history", "id",
                "indicatorMalwareRelationships", "indicatorRelationships", "indicators",
                "isPublished", "langs", "malwareList", "mitreMatrix", "regions",
                "relatedThreatActors", "reportNumber", "reportRating", "reportSeen",
                "sectors", "sources", "stixGuid", "targetedCompany",
                "targetedPartnersAndClients", "threatActor", "unreliableIndicators",
                "updatedAt"),
    ),
    "hi/open_threats": Collection(
        category="threats", label="Угрозы :: Открытые угрозы", limit=100,
        availability="common", ttl_days=None, admiralty=None, severity=5,
        hunting_rules=True,
        note="Collections Info prints the endpoint as hi/open_threat, the record-limit table "
                "and pyf6 both use hi/open_threats; the plural is used here and the singular is "
                "accepted as an alias.",
        fields=("author", "createdAt", "data", "dateDetected", "detected", "displayOptions",
                "evaluation", "id", "link", "source", "sourceType", "text", "threatActors",
                "title", "updatedAt"),
    ),
    "compromised/reaper": Collection(
        category="threats", label="Угрозы :: Хак-форумы", limit=100,
        availability="common", ttl_days=90, admiralty=None, severity=None,
        only_common=True, hunting_rules=True,
        fields=("categories", "display_options", "domain", "evaluation", "first_post",
                "forum", "message_hash", "highlight", "id", "lang", "message_len", "message",
                "nickname", "pictures", "datetime", "quotes", "last_post", "message_lang",
                "clear_message", "thread_id", "topic", "topic_hash", "topic_info",
                "translation", "unhide_message", "update_datetime_alert", "upload_time",
                "url", "isFavourite", "isHidden"),
    ),
    "compromised/messenger": Collection(
        category="threats", label="Угрозы :: Мессенджеры (Telegram)", limit=100,
        availability="individual", ttl_days=90, admiralty=None, severity=None,
        hunting_rules=True,
        note="Spam can be filtered out with the extra parameter tags[filterSpam][]=1 "
                "(pass it through extra_params).",
        fields=("author", "chatStat", "deleted", "edits", "id", "isReply", "lastEditTs",
                "media", "message", "messageId", "messageTs", "repliedMessage", "rules",
                "selected", "translatedMessage"),
    ),
    "compromised/discord": Collection(
        category="threats", label="Угрозы :: Discord", limit=100,
        availability="individual", ttl_days=90, admiralty=None, severity=None,
        fields=("author", "channel", "deleted", "edits", "id", "media", "repliedMessage",
                "rules", "text", "ts", "translation", "highlight"),
    ),

    # --- Не представлены в веб-интерфейсе ---------------------------------
    "ioc/common": Collection(
        category="hidden", label="Mix (Common IoCs)", limit=5000,
        availability="common+individual", ttl_days=90, admiralty="A2..C1",
        severity="3..9",
        note="Admiralty and severity depend on the source of the indicator (analyst, "
                "autoreport, OSINT autoreport, F6 MXDR, hunting rules) and drop by 1 when the "
                "indicator reappears after more than a year unseen.",
        fields=("cnc", "dateDetected", "dateFirstSeen", "dateLastSeen", "domain", "file",
                "id", "ipv4", "ipv6", "malwareList", "platform", "threatActor", "url"),
    ),
    "malware/cnc": Collection(
        category="hidden", label="C2", limit=5000,
        availability="common", ttl_days=90, admiralty=None, severity=None,
        fields=("dateFirstSeen", "dateLastSeen", "domain", "id", "malwareList", "threatList",
                "type"),
    ),
}

# From the "Устаревшие" table of Collections Info plus pyf6's
# TI_DEPRECATED_COLLECTIONS. Requests still go through, but the backend answers
# them with an empty result; the answer carries a warning naming the replacement.
DEPRECATED: dict[str, str] = {
    "compromised/account": "compromised/account_group",
    "compromised/card": "compromised/bank_card_group or compromised/masked_card",
    "compromised/bank_card": "compromised/bank_card_group or compromised/masked_card",
    "compromised/imei": "no replacement documented",
    "osi/git_leak": "osi/git_repository",
    "attacks/phishing": "attacks/phishing_group",
    "malware/targeted_malware": "malware/malware with apply_hunting_rules=1",
    "bp/phishing": "attacks/phishing_group",
    "bp/phishing_kit": "attacks/phishing_kit",
}

ALIASES = {"hi/open_threat": "hi/open_threats"}

COLLECTION_NAME = re.compile(r"[a-z0-9_]+/[a-z0-9_]+")

KNOWN_COLLECTIONS = sorted(COLLECTIONS)
ONLY_COMMON = sorted(c for c, m in COLLECTIONS.items() if m.only_common)
HUNTING_RULES_COLLECTIONS = sorted(c for c, m in COLLECTIONS.items() if m.hunting_rules)

def resolve_collection(collection: Any) -> str:
    """Normalises a collection name: strips endpoint suffixes and applies aliases."""
    if not isinstance(collection, str) or not collection.strip():
        raise ValueError(f"collection is required, one of: {', '.join(KNOWN_COLLECTIONS)}")
    name = collection.strip().strip("/")
    # Callers copying names out of the guide often keep the endpoint suffix.
    if name.endswith("/updated"):
        name = name[: -len("/updated")]
    name = ALIASES.get(name, name)
    # Two plain segments: a name that is not shaped like one cannot be a
    # collection, and must not become a different path once joined into a URL.
    if not COLLECTION_NAME.fullmatch(name):
        raise ValueError(
            f'collection must look like "section/name", e.g. "ioc/common", got {collection!r}'
        )
    return name


def collection_limit(collection: str) -> int:
    meta = COLLECTIONS.get(collection)
    return meta.limit if meta else DEFAULT_LIMIT

def warnings_for(collection: str, *, method: str) -> list[str]:
    """Notes worth attaching to a result: deprecation, unknown name, method fit."""
    notes: list[str] = []
    if collection in DEPRECATED:
        notes.append(
            f'Collection "{collection}" is deprecated and the server answers it with an empty '
            f"result; use {DEPRECATED[collection]} instead."
        )
    elif collection not in COLLECTIONS:
        notes.append(
            f'Collection "{collection}" is not in the documented list — the request was sent '
            "as-is. Call ti_list_collections to see what this account may read."
        )
    meta = COLLECTIONS.get(collection)
    if meta and method == "updated" and meta.only_common:
        notes.append(
            f'"{collection}" has no /updated endpoint; only the Common API (ti_get_collection) '
            "is documented for it."
        )
    if meta and meta.note:
        notes.append(meta.note)
    return notes

def describe(collection: str, *, include_fields: bool) -> dict[str, Any]:
    meta = COLLECTIONS.get(collection)
    described: dict[str, Any] = {
        "collection": collection,
        "label": meta.label if meta else None,
        "category": meta.category if meta else None,
        "documented": meta is not None,
        "availability": meta.availability if meta else None,
        "ttl_days": meta.ttl_days if meta else None,
        "admiralty": meta.admiralty if meta else None,
        "severity": meta.severity if meta else None,
        "max_records_per_request": collection_limit(collection),
        "supports_common_api": True,
        "supports_updated_api": not (meta and meta.only_common),
        "supports_apply_hunting_rules": bool(meta and meta.hunting_rules),
    }
    if meta and meta.group:
        described["group_collection"] = True
    if meta and meta.has_files:
        described["files_endpoint"] = "{collection}/{id}/file/{file_id} (via ti_request)"
    if collection in DEPRECATED:
        described["deprecated_in_favour_of"] = DEPRECATED[collection]
    if meta and meta.note:
        described["note"] = meta.note
    if include_fields:
        described["fields"] = list(meta.fields) if meta else []
    return described
