# BurpSuite MCP

A **Model Context Protocol (MCP)** server written in TypeScript that exposes **66 tools** across 10 modules to connect MCP-compatible AI clients (Antigravity, OpenCode, Claude Desktop) with **BurpSuite Community Edition** and **BurpSuite Professional** over `stdio` or **Streamable HTTP**.

---

## Table of Contents

- [Overview](#overview)
- [Edition Compatibility](#edition-compatibility)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Build the MCP Server](#1-build-the-mcp-server)
  - [2. Optional: Load the Community Bridge Extension](#2-optional-load-the-community-bridge-extension)
- [Configuration](#configuration)
- [Transports: Stdio vs Streamable HTTP](#transports-stdio-vs-streamable-http)
- [Client Setup](#client-setup)
  - [Antigravity (`agy`)](#antigravity-agy)
  - [OpenCode](#opencode)
  - [Claude Desktop](#claude-desktop)
- [Available Tools (66)](#available-tools-66)
  - [Proxy (9)](#proxy-9)
  - [Scanner (9)](#scanner-9)
  - [Repeater (6)](#repeater-6)
  - [Intruder (6)](#intruder-6)
  - [Spider (7)](#spider-7)
  - [Sitemap & Scope (10)](#sitemap--scope-10)
  - [Extensions & Core (12)](#extensions--core-12)
  - [Decoder (3)](#decoder-3)
  - [Comparer (3)](#comparer-3)
  - [Report (1)](#report-1)
- [Usage Examples](#usage-examples)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## Overview

`burpsuite-mcp` communicates over `stdio` or **Streamable HTTP** (`--http`) using `@modelcontextprotocol/sdk` and adapts automatically to the BurpSuite edition running locally:

- **Without an API key (BurpSuite Community Edition)**:
  - **Standalone mode** (zero Burp extensions required): routes Repeater, Intruder, and local Spider HTTP/HTTPS traffic through the Burp Proxy (`127.0.0.1:8080`), automatically handles Burp's local MITM TLS certificate, maintains an in-memory proxy history, sitemap, and scope, and performs 11 passive security checks.
  - **Live GUI Bridge mode** (with the included [`burp-extension/burp_mcp_bridge.py`](./burp-extension/burp_mcp_bridge.py) Jython extension): exposes live Burp Community Proxy History, real-time Proxy Interception (`IProxyListener`), live Match & Replace rules, Target Site Map, Target Scope, Send-to-Repeater UI tabs, and live JSON configuration (`saveConfigAsJson` / `loadConfigFromJson`) on port `1337`.
- **With or without an API key (BurpSuite Professional)**:
  - Connects directly to BurpSuite Pro's built-in REST API (`v0.1`).
  - When `BURP_API_KEY` is configured, `BURP_API_KEY_MODE=auto` targets PortSwigger's native URL-path authentication (`http://<host>:<apiPort>/<key>/v0.1/...`) and automatically falls back to header authentication (`X-Burp-Api-Token`, `API-KEY`, `Authorization`) if a third-party REST plugin is in use.

---

## Edition Compatibility

| Feature Area | Community (Standalone) | Community + `burp_mcp_bridge.py` | BurpSuite Pro |
|---|---|---|---|
| Proxy History (`get_proxy_history`, `get_proxy_history_item`) | MCP local history | Live Burp GUI history | Live Burp Pro REST API |
| Live Proxy Intercept (`set_proxy_intercept`, `get_intercepted_requests`, `forward_intercepted_request`, `drop_intercepted_request`) | Unsupported notice | Live via `IProxyListener` | Live Burp Pro REST API |
| Proxy Match & Replace (`add/list/delete_proxy_match_replace_rule`) | MCP memory only | Live on all Burp Proxy traffic | Live Burp Pro REST API |
| Repeater HTTP/HTTPS Replay (`repeater_*`) | Live via Proxy `:8080` | Live via Proxy `:8080` | Live via Proxy `:8080` |
| Send to Burp Repeater UI (`burp_send_to_repeater`) | Unsupported notice | Live UI tab creation | Live REST API |
| Intruder Engine (`intruder_*`) | Live via Proxy `:8080` | Live via Proxy `:8080` | Live via Proxy `:8080` |
| Spider / Discovery (`spider_*`) | Local crawler via Proxy `:8080` | Reads live Burp sitemap + local crawler | Native Burp crawler |
| Target Sitemap & Technologies (`sitemap_get*`) | MCP local sitemap | Live Burp GUI sitemap | Live Burp Pro REST API |
| Clear Site Map (`sitemap_clear`) | Clears MCP local cache | Clears MCP local cache (GUI clear is manual) | Native API if supported |
| Scope Management (`scope_*`) | MCP local scope | Live `include`/`exclude`/`check` in Burp GUI | Live Burp Pro REST API |
| **Passive Security Analysis** (`start_passive_scan`, `get_all_issues`, `get_issues_for_host`) | 11 local passive checks | 11 passive checks on live Burp sitemap | Native Burp passive audit |
| **Decoder & Comparer** (`decoder_*`, `comparer_*`) | Full local encoding/decoding/hashing & text/HTTP diff | Full local tools + live Proxy item diffing | Full local tools + live Proxy item diffing |
| **Audit Report Export** (`report_export`) | Markdown/JSON from local cache & passive checks | Markdown/JSON from live sitemap & passive checks | Markdown/JSON from Pro findings & sitemap |
| **Active Scanner** (`start_scan`, `get_scan_status`, `get_scan_issues`, `stop_scan`, `list_scans`) | Unsupported notice | Unsupported notice | Native Burp Pro scanner |
| Burp Configuration (`burp_get_configuration`, `burp_update_configuration`) | Unsupported notice | Live (`saveConfigAsJson` / `loadConfigFromJson`) | Live Burp Pro REST API |
| Save Project State (`burp_save_state`) | Unsupported (Pro only) | Unsupported (Pro only) | Live Burp Pro REST API |
| Extensions Management (`extensions_*`) | Unsupported notice | Bridge self-info, logs, and unload | Live Burp Pro REST API |

---

## Prerequisites

- **Node.js** v18 or later (tested on Node.js v24)
- **BurpSuite Community Edition** or **BurpSuite Professional**
- *(Optional, for Community GUI integration)* **Jython standalone JAR** configured in Burp under `Settings -> Extensions -> Python environment`

---

## Installation

### 1. Build the MCP Server

```bash
git clone https://github.com/Steph-ux/burpsuite-mcp.git
cd burpsuite-mcp
npm install
npm run build
```

Compiled JavaScript output is written to `dist/index.js` (marked executable and exposed as the `burpsuite-mcp` CLI binary in `package.json`). You can link it globally with `npm link` and run `burpsuite-mcp` directly, or point your MCP client to `dist/index.js`. For watch-mode development:

```bash
npm run dev
```

### 2. Optional: Load the Community Bridge Extension

If you are using **BurpSuite Community Edition** and want the MCP server to read your live GUI Proxy History/Sitemap, toggle real-time interception, apply Match & Replace rules to browser traffic, open Repeater UI tabs, and read/update Burp JSON configuration:

1. In BurpSuite Community, go to **Extensions -> Extensions settings -> Python environment** and select your Jython standalone `.jar` file.
2. Go to **Extensions -> Installed -> Add**:
   - **Extension type**: `Python`
   - **Extension file**: select `burp-extension/burp_mcp_bridge.py`
3. Click **Next**. The Output tab should display:
   `[BurpSuite MCP Bridge v0.2] Listening on http://127.0.0.1:1337 (api_key=disabled)`

If you later upgrade to **BurpSuite Professional**, unload `burp_mcp_bridge.py`, enable Burp Pro's native REST API (`Settings -> Suite -> REST API -> Service enabled`), and set `BURP_API_KEY`.

---

## Configuration

Copy `.env.example` to `.env` (or pass environment variables directly through your MCP client configuration):

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `BURP_HOST` | `127.0.0.1` | Hostname for both Burp Proxy and Burp REST API |
| `BURP_PORT` | `8080` | Burp HTTP proxy port (used by Repeater, Intruder, and local Spider) |
| `BURP_API_PORT` | `1337` | Burp REST API port (Burp Pro or Community Bridge) |
| `BURP_API_KEY` | `""` | Optional API key. Leave empty for Community Edition or unauthenticated REST API |
| `BURP_API_KEY_MODE` | `auto` | `auto`, `path` (`/<key>/v0.1/...`), or `header` (`X-Burp-Api-Token` / `API-KEY` / `Authorization`) |
| `BURP_EDITION` | `auto` | `auto` (REST when `:1337` is reachable, local fallback otherwise), `community`, or `pro` |
| `BURP_PROXY_TLS_REJECT_UNAUTHORIZED` | `false` | Set to `true` only if Burp's CA certificate is installed in Node's trust store |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` (all logs are written exclusively to `stderr`) |
| `MCP_TRANSPORT` | `stdio` | Transport mode (`stdio` or `http`) |
| `MCP_HTTP_HOST` | `127.0.0.1` | Bind address for Streamable HTTP mode |
| `MCP_HTTP_PORT` | `3000` | Listen port for Streamable HTTP mode |
| `MCP_HTTP_TOKEN` | `""` | Optional Bearer token required on HTTP `/mcp` requests |

---

## Transports: Stdio vs Streamable HTTP

By default, `burpsuite-mcp` runs over `stdio`. To run as a stateful **Streamable HTTP** MCP server (for example, when BurpSuite runs inside a separate VM or remote workstation):

```bash
npm run start:http
# or with custom bind host, port, and Bearer token:
node dist/index.js --http --host 127.0.0.1 --port 3000 --token your-secret-token
```

Exposed HTTP endpoints:
- `POST /mcp`, `GET /mcp`, `DELETE /mcp` — MCP Streamable HTTP transport (`Mcp-Session-Id` stateful sessions)
- `GET /health` — JSON health check returning tool count and active session count

If `--token` (`MCP_HTTP_TOKEN`) is configured, clients must pass `Authorization: Bearer <token>`.

---

## Client Setup

### Antigravity (`agy`)

```bash
agy mcp add \
  --env BURP_HOST=127.0.0.1 \
  --env BURP_PORT=8080 \
  --env BURP_API_PORT=1337 \
  --env BURP_API_KEY= \
  --env BURP_API_KEY_MODE=auto \
  --env BURP_EDITION=auto \
  burpsuite /usr/bin/node /absolute/path/to/burpsuite-mcp/dist/index.js
```

### OpenCode

Add the following entry inside the `"mcp"` block of `~/.config/opencode/opencode.json` (or your project's `opencode.json`):

```json
{
  "mcp": {
    "burpsuite": {
      "type": "local",
      "command": [
        "/usr/bin/node",
        "/absolute/path/to/burpsuite-mcp/dist/index.js"
      ],
      "environment": {
        "BURP_HOST": "127.0.0.1",
        "BURP_PORT": "8080",
        "BURP_API_PORT": "1337",
        "BURP_API_KEY": "",
        "BURP_API_KEY_MODE": "auto",
        "BURP_EDITION": "auto"
      },
      "enabled": true
    }
  }
}
```

### Claude Desktop

A template is provided in [`claude_desktop_config.json`](./claude_desktop_config.json):

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "node",
      "args": ["/absolute/path/to/burpsuite-mcp/dist/index.js"],
      "env": {
        "BURP_HOST": "127.0.0.1",
        "BURP_PORT": "8080",
        "BURP_API_PORT": "1337",
        "BURP_API_KEY": "",
        "BURP_API_KEY_MODE": "auto",
        "BURP_EDITION": "auto"
      }
    }
  }
}
```

---

## Available Tools (66)

### Proxy (9)

| Tool | Description |
|---|---|
| `get_proxy_history` | Retrieve Proxy HTTP history with optional `limit`, URL substring `filter`, and `include_body` flag |
| `get_proxy_history_item` | Retrieve a single Proxy history item by numeric `id` with full request and response |
| `set_proxy_intercept` | Enable or disable Burp Proxy request/response interception (`enabled`) |
| `get_intercepted_requests` | List requests currently waiting in the Proxy intercept queue |
| `forward_intercepted_request` | Forward an intercepted item by `id`, optionally replacing raw text with `modified_request` |
| `drop_intercepted_request` | Drop an intercepted item by `id` |
| `add_proxy_match_replace_rule` | Create a match-and-replace rule (`match_condition`, `match_type`, `replace_string`, `enabled`, `is_regex`, `comment`) |
| `list_proxy_match_replace_rules` | List configured Proxy match-and-replace rules |
| `delete_proxy_match_replace_rule` | Delete a Proxy match-and-replace rule by `id` |

### Scanner (9)

| Tool | Description |
|---|---|
| `start_scan` | Launch an active scan on `urls` (Burp Pro REST API) with optional `scan_configurations`, `scope_included`, `scope_excluded` |
| `get_scan_status` | Get scan status and progress by `task_id` |
| `get_scan_issues` | Retrieve vulnerability issues found by `task_id` |
| `stop_scan` | Stop a running scan by `task_id` |
| `list_scans` | List all active and completed scans |
| `start_passive_scan` | Passively analyze a captured `url`, `request`, and `response` pair |
| `get_all_issues` | Retrieve all findings site-wide (Burp Pro issues or local passive analysis of the live sitemap) |
| `get_issue_definitions` | Retrieve known issue definitions (Burp Pro catalog or 11 built-in passive rule definitions) |
| `get_issues_for_host` | Retrieve vulnerability findings filtered by `host` |

### Repeater (6)

| Tool | Description |
|---|---|
| `repeater_send_request` | Send a custom HTTP/HTTPS request (`host`, `port`, `use_https`, `method`, `path`, `headers`, optional `body`, `follow_redirects`, `use_burp_proxy`) |
| `repeater_get_history` | List in-memory Repeater history entries (most recent first, optional `limit`) |
| `repeater_get_item` | Retrieve a full Repeater entry (request + response) by UUID `id` |
| `repeater_replay_from_proxy_history` | Fetch an item by `proxy_history_id` and replay it with optional `modifications` (`headers_to_add`, `headers_to_remove`, `body_override`) |
| `repeater_save_request` | Save a named request template to Repeater memory without sending it |
| `repeater_clear_history` | Clear all entries from in-memory Repeater history |

### Intruder (6)

| Tool | Description |
|---|---|
| `intruder_start_attack` | Launch an attack (`sniper`, `battering_ram`, `pitchfork`, `cluster_bomb`) using `§marker§` positions in `request_template` and `payload_sets` |
| `intruder_get_attack_status` | Check attack status, `total_requests`, `completed_requests`, and `results_count` by `attack_id` |
| `intruder_get_results` | Retrieve paginated results (`limit`, `offset`) with `filter_status_codes`, `min_response_length`, and `max_response_length` |
| `intruder_stop_attack` | Stop a running Intruder attack by `attack_id` |
| `intruder_list_attacks` | List all Intruder attacks currently in memory |
| `intruder_clear_attack` | Stop (if running) and delete an attack record by `attack_id` |

### Spider (7)

| Tool | Description |
|---|---|
| `spider_start_crawl` | Start a crawl-only task on `urls` (Burp Pro REST API or local Burp-proxied crawler in Community mode) |
| `spider_get_crawl_status` | Poll crawl progress and request counters by `task_id` |
| `spider_get_discovered_urls` | Return unique URLs discovered during crawl or present in the sitemap |
| `spider_stop_crawl` | Stop an active crawl by `task_id` |
| `spider_list_crawls` | List active and finished crawl tasks |
| `spider_get_forms` | Extract POST/PUT/PATCH endpoints and HTML `<form>` tags with detected input/body parameters |
| `spider_get_endpoints` | Return deduplicated endpoints with HTTP method, status code, MIME type, query parameters, and body parameters |

### Sitemap & Scope (10)

| Tool | Description |
|---|---|
| `sitemap_get` | Retrieve the target sitemap grouped by host (optional `host` filter) |
| `sitemap_get_host_details` | Retrieve endpoints, status code distribution, and detected technologies for a `host` |
| `scope_get` | Retrieve current included and excluded scope rules |
| `scope_add_url` | Add a `url` to the active target scope |
| `scope_remove_url` | Add a `url` to the target scope exclusion list |
| `scope_set` | Replace scope rules with `included` and `excluded` lists |
| `scope_check_url` | Check whether a `url` is currently in scope |
| `sitemap_get_requests_for_host` | Retrieve recorded full request/response pairs for a `host` (optional `limit`) |
| `sitemap_clear` | Clear the sitemap (or local MCP sitemap cache in Community mode) |
| `sitemap_get_technologies` | Fingerprint server software, languages, frameworks, and CMSes from response headers |

### Extensions & Core (12)

| Tool | Description |
|---|---|
| `extensions_list` | List installed Burp extensions |
| `extensions_get` | Get details for a specific extension by `extension_id` |
| `extensions_toggle` | Enable or disable an extension (`extension_id`, `enabled`) |
| `extensions_get_output` | Retrieve stdout/stderr buffer for an extension by `extension_id` |
| `extensions_clear_output` | Clear stdout/stderr output buffer for an extension by `extension_id` |
| `extensions_install` | Attempt API installation or return step-by-step manual installation instructions |
| `extensions_unload` | Unload an extension by `extension_id` |
| `burp_get_version` | Retrieve BurpSuite edition, version, and REST/bridge status |
| `burp_get_configuration` | Export current BurpSuite configuration JSON |
| `burp_update_configuration` | Apply a partial or full BurpSuite configuration JSON object |
| `burp_save_state` | Export BurpSuite Pro project state to `file_path` |
| `burp_send_to_repeater` | Send a Proxy history item (`proxy_history_id`) to a Burp Repeater UI tab |

### Decoder (3)

| Tool | Description |
|---|---|
| `decoder_encode` | Encode text using `base64`, `base64url`, `url`, `url_all`, `html`, `hex`, `unicode_escape`, or `gzip_base64` |
| `decoder_decode` | Decode encoded payloads or JWT tokens (`auto` detection or explicit format) |
| `decoder_hash` | Compute cryptographic digests (`md5`, `sha1`, `sha256`, `sha512`) |

### Comparer (3)

| Tool | Description |
|---|---|
| `comparer_diff_text` | Diff two strings at `lines`, `words`, or `chars` granularity |
| `comparer_diff_proxy_items` | Diff status codes, response headers, and bodies for two Proxy History items by `left_id` and `right_id` |
| `comparer_diff_repeater_items` | Diff status codes, response headers, and bodies for two Repeater items by UUID |

### Report (1)

| Tool | Description |
|---|---|
| `report_export` | Generate a structured Markdown or JSON defensive audit report (hosts, endpoints, technologies, findings with remediation) and optionally save to `output_path` |

---

## Usage Examples

### Export a Defensive Audit Report

```json
report_export({
  "host": "example.com",
  "format": "markdown",
  "include_endpoints": true,
  "output_path": "./audit-report.md"
})
```

### Decode a JWT and Diff Two Proxy Responses

```json
decoder_decode({ "input": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig", "format": "jwt" })
comparer_diff_proxy_items({ "left_id": 1, "right_id": 2, "mode": "lines" })
```

### Inspect Proxy History and Send to Burp Repeater UI

```json
// 1. Check Burp connection and edition
burp_get_version()

// 2. Fetch recent traffic matching a path
get_proxy_history({ "limit": 20, "filter": "/api/" })

// 3. Open item #1 in a Burp Repeater UI tab
burp_send_to_repeater({ "proxy_history_id": 1 })
```

### Replay and Modify a Request via Repeater

```json
repeater_replay_from_proxy_history({
  "proxy_history_id": 1,
  "modifications": {
    "headers_to_add": { "X-Debug": "1" },
    "headers_to_remove": ["Cookie"]
  },
  "use_burp_proxy": true
})
```

### Run Passive Analysis and Inspect Sitemap Technologies

```json
sitemap_get_technologies({ "host": "example.com" })
get_issues_for_host({ "host": "example.com" })
```

### Launch an Intruder Attack

```json
intruder_start_attack({
  "host": "target.local",
  "port": 443,
  "use_https": true,
  "request_template": "POST /login HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=§FUZZ§",
  "attack_type": "sniper",
  "payload_sets": [["test1", "test2", "test3"]],
  "max_concurrent": 10
})
```

### Launch an Active Scan (BurpSuite Pro)

```json
start_scan({
  "urls": ["https://example.com/"],
  "scope_included": ["https://example.com/"]
})
get_scan_status({ "task_id": "1" })
get_scan_issues({ "task_id": "1" })
```

---

## Architecture

```text
+-------------------------------------------------------------------+
|      MCP Client (Antigravity / OpenCode / Claude Desktop)         |
+---------------------------------+---------------------------------+
                                  | MCP JSON-RPC (stdio or --http)
+---------------------------------v---------------------------------+
|                     src/index.ts (66 tools)                       |
|  +---------+ +---------+ +----------+ +----------+ +----------+   |
|  |  proxy  | | scanner | | repeater | | intruder | |  spider  |   |
|  +---------+ +---------+ +----------+ +----------+ +----------+   |
|  +-----------+ +------------+ +---------+ +----------+ +--------+ |
|  |  sitemap  | | extensions | | decoder | | comparer | | report | |
|  +-----------+ +------------+ +---------+ +----------+ +--------+ |
|                     src/utils/local-store.ts                      |
|                     src/utils/burp-client.ts                      |
+------------------------+-----------------------+------------------+
                         | REST (:1337)          | HTTP Proxy (:8080)
+------------------------v-----------------------v------------------+
|   BurpSuite Pro REST API  OR  Burp Community + burp_mcp_bridge.py |
+-------------------------------------------------------------------+
```

- All runtime logs are written exclusively to `stderr` via `src/utils/logger.ts` so `stdout` remains strictly reserved for MCP JSON-RPC frames.
- `src/utils/burp-client.ts` handles both unauthenticated endpoints and API-key endpoints (`path` or `header` modes) and routes Community fallbacks through `withRestFallback()`.

---

## Troubleshooting

- **`scope_get` or `get_all_issues` returns Community local data instead of Burp GUI data**: ensure `burp-extension/burp_mcp_bridge.py` v0.2 is loaded in Burp (`Extensions -> Installed`) and listening on `127.0.0.1:1337`.
- **HTTPS requests in Repeater or Intruder fail with TLS certificate errors**: verify `BURP_PROXY_TLS_REJECT_UNAUTHORIZED` is `false` (default) when routing through Burp's intercepting proxy.
- **Upgrading from Community to Pro**: unload `burp_mcp_bridge.py` in Burp, enable the built-in Pro REST API on port `1337`, and set `BURP_API_KEY` in `.env` or your MCP client config.
