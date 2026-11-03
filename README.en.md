<p align="center">
  <img src="https://raw.githubusercontent.com/F6-Security/ti-mcp/HEAD/docs/logo.png" alt="F6" width="220">
</p>

# F6 Threat Intelligence MCP Server

<p align="right"><a href="https://github.com/F6-Security/ti-mcp/blob/HEAD/README.md">Русский</a></p>

[![PyPI](https://img.shields.io/pypi/v/ti-mcp)](https://pypi.org/project/ti-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/ti-mcp)](https://pypi.org/project/ti-mcp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/F6-Security/ti-mcp/blob/HEAD/LICENSE)
[![CI](https://github.com/F6-Security/ti-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/F6-Security/ti-mcp/actions/workflows/ci.yml)

An MCP server for the [F6 Threat Intelligence](https://ti.f6.security) API. It gives
an AI assistant access to the TI collections — leaks, malware, attacks, suspicious
IPs, threats and threat actor profiles — by indicator search and filtered reads.

## Tools

| Tool | Purpose |
| --- | --- |
| `ti_list_collections` | Collections the account may read; doubles as a check of the key and IP |
| `ti_global_search` | Which collections mention an indicator, and how many records each holds |
| `ti_get_collection` | Read and search a collection, page by page |
| `ti_get_updates` | Changes in a collection from a point in its update sequence |
| `ti_get_sequence_list` | Starting points for `ti_get_updates`, optionally for a date |
| `ti_get_item` | One record by id |
| `ti_graph_lookup` | WHOIS enrichment for an IP or a domain |
| `ti_describe_collections` | Collection reference: fields, caps, methods; no API call |
| `ti_request` | Any documented read-only endpoint under `/api/v2` |

Every tool only reads. `ti_request` refuses paths that change data on the TI side
and does not serve binary files.

## Quick start

You need Python 3.10+, your TI web portal login and a personal API key
(Account → Security and access → Personal token). The address the server runs
from must be on the account's trusted IP list.

```json
{
  "mcpServers": {
    "ti": {
      "command": "uvx",
      "args": ["ti-mcp"],
      "env": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "<key>"
      }
    }
  }
}
```

This block works for Claude Desktop and Cursor. For VS Code, in `.vscode/mcp.json`:

```json
{
  "servers": {
    "ti": {
      "type": "stdio",
      "command": "uvx",
      "args": ["ti-mcp"],
      "env": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "<key>"
      }
    }
  }
}
```

For Claude Code:

```sh
claude mcp add ti \
  -e TI_LOGIN=user@example.com -e TI_API_KEY=<key> \
  -- uvx ti-mcp
```

For OpenCode, the `mcp` key in `~/.config/opencode/opencode.json` (all projects)
or in `opencode.json` at the project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ti": {
      "type": "local",
      "command": ["uvx", "ti-mcp"],
      "enabled": true,
      "timeout": 660000,
      "environment": {
        "TI_LOGIN": "user@example.com",
        "TI_API_KEY": "{file:~/.config/ti-mcp/key}"
      }
    }
  }
}
```

Unlike the configs above, `command` is an array that includes the arguments,
variables go in `environment`, and `"type": "local"` is required. The key does not
have to live in the config: OpenCode substitutes a file's contents (`{file:…}`) or
an environment variable (`{env:TI_API_KEY}`). `timeout` is in milliseconds, 30 s
per request by default, and one tool call can take longer: on 429 and 5xx the server
retries up to `TI_RETRIES` times (3 by default), each attempt waits up to
`TI_TIMEOUT` (120 s) for the portal, and a `Retry-After` pause is kept between
attempts. 660 s covers four attempts and pauses of a minute; if you change
`TI_TIMEOUT` or `TI_RETRIES`, recompute it. Check the connection with
`opencode mcp list`.

Instead of `uvx` you can `pip install ti-mcp` and run `ti-mcp`, or use the
container — `docker run -i --rm -e TI_LOGIN -e TI_API_KEY ghcr.io/f6-security/ti-mcp`
(built for `linux/amd64` and `linux/arm64`).

To run the server from source — for example, to try changes that are not yet
released — install it into its own environment from a clone of the repository:

```sh
git clone https://github.com/F6-Security/ti-mcp.git
cd ti-mcp
python3 -m venv venv
./venv/bin/pip install --require-hashes -r requirements.lock
./venv/bin/pip install --no-deps -e .
```

On Windows use `venv\Scripts\` instead of `venv/bin/`, including in the client path below.

Then give the client the command from that environment instead of `uvx ti-mcp`:

```sh
claude mcp add ti \
  -e TI_LOGIN=user@example.com -e TI_API_KEY=<key> \
  -- /path/to/ti-mcp/venv/bin/ti-mcp
```

In a JSON config that is `"command": "/path/to/ti-mcp/venv/bin/ti-mcp"` with no
`args`; in OpenCode, `"command": ["/path/to/ti-mcp/venv/bin/ti-mcp"]`. The package is installed in editable mode, so code changes take effect the
next time the server starts. For a test environment, set its address in `TI_BASE_URL`.

Call `ti_list_collections` first: it confirms the key, the IP and the collection
access all work.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `TI_LOGIN` | — | login (email) on the TI web portal |
| `TI_API_KEY` | — | personal API key |
| `TI_BASE_URL` | `https://ti.f6.security` | portal address; `https://` only |
| `TI_CA_BUNDLE` | — | PEM bundle of the CAs that verify the portal's certificate, e.g. a proxy's internal CA; replaces the system CAs, so it must contain every CA needed |
| `TI_PROXY` | — | proxy as `http://host:port`; `HTTP_PROXY` and `HTTPS_PROXY` from the environment are not read |
| `TI_TIMEOUT` | `120` | request timeout, seconds |
| `TI_RETRIES` | `3` | retries on 429/500/502/503/504, honouring `Retry-After` |
| `TI_MIN_FEED_INTERVAL` | `1` | minimum interval between requests to one collection, seconds |
| `TI_RESULT_ID_TTL` | `150` | how long the server remembers an open `scroll=true` read, seconds |

## Example queries

```
ti_global_search        query="8.8.8.8"
ti_describe_collections collection="ioc/common"
ti_get_collection       collection="ioc/common" query="ip:8.8.8.8"
ti_get_collection       collection="osi/vulnerability" date_from="2026-10-01" extra_params={"has_exploit": 1}
ti_get_collection       collection="apt/threat" limit=10 offset=10
ti_get_updates          collection="malware/cnc" seq_update=16394859
```

The usual path: `ti_global_search` on an indicator shows which collections mention
it; `ti_describe_collections` gives the fields and caps of the one you need;
`ti_get_collection` with the same query returns the records.

`query` is free text over every attribute (`"8.8.8.8"`) or `attribute:value`
(`"domain:example.com"`). The attributes are the collection's response fields,
listed by `ti_describe_collections`. `date_from`/`date_to` take `YYYY-MM-DD` or
`YYYY-MM-DDTHH:MM:SSZ`.

`ti_get_collection` pages with `offset` in steps of `limit` up to `count`. To
export a large set or walk a whole collection pass `scroll=true`: the server
continues the read itself on the next call. To follow a feed continuously use
`ti_get_updates` with the `seqUpdate` from the previous answer;
`ti_get_sequence_list` gives the starting point.

## Security

Everything the tools return enters the language model's context: compromised
accounts, cards, indicators, threat reports. Choose the model provider with that
in mind and give the server a user key with the narrowest set of collections the
task needs.

The key goes only to the address in `TI_BASE_URL` and only over `https://`; a
response over 1 MB is refused so one call cannot fill the context.

The threat model and how to report a vulnerability are in
[SECURITY.md](https://github.com/F6-Security/ti-mcp/blob/HEAD/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/F6-Security/ti-mcp/blob/HEAD/CONTRIBUTING.md).

## License

[Apache License 2.0](https://github.com/F6-Security/ti-mcp/blob/HEAD/LICENSE)
