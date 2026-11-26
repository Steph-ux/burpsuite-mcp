# BurpSuite MCP

A **Model Context Protocol (MCP)** server written in TypeScript that exposes **78 tools** across 12 modules to connect MCP-compatible AI clients (Antigravity, OpenCode, Claude Desktop) with **BurpSuite Community Edition** and **BurpSuite Professional** over `stdio` or **Streamable HTTP**.

---

## Table of Contents

- [Overview](#overview)
- [Edition Compatibility](#edition-compatibility)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Build the MCP Server](#1-build-the-mcp-server)
  - [2. Load the Full Pro / Community Bridge Extension](#2-load-the-full-pro--community-bridge-extension)
- [Configuration](#configuration)
- [Transports: Stdio vs Streamable HTTP](#transports-stdio-vs-streamable-http)
- [Client Setup](#client-setup)
  - [Antigravity (`agy`)](#antigravity-agy)
  - [OpenCode](#opencode)
  - [Claude Desktop](#claude-desktop)
- [Available Tools (78)](#available-tools-78)
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
  - [Session Persistence (3)](#session-persistence-3)
  - [Pro & Montoya Bridge (9)](#pro--montoya-bridge-9)
- [Usage Examples](#usage-examples)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

`burpsuite-mcp` communicates over `stdio` or **Streamable HTTP** (`--http`) using `@modelcontextprotocol/sdk` and adapts automatically to the BurpSuite edition running locally:

- **BurpSuite Professional + Full Pro Bridge ([`burpsuite-mcp-bridge.jar`](./burp-extension/burpsuite-mcp-bridge.jar) / Montoya Java API)**:
  - PortSwigger's built-in `:1337` REST API only exposes basic scan tasks and KB definitions. Loading [`burp-extension/burpsuite-mcp-bridge.jar`](./burp-extension/burpsuite-mcp-bridge.jar) (or the Jython bridge [`burp_mcp_bridge.py`](./burp-extension/burp_mcp_bridge.py) v0.3) unlocks **all 78 tools** over `:1337`, including Crawl + Active Audit scans, **Burp Collaborator OAST**, **WebSocket proxy history**, **BChecks** and **Bambda** import, **Intruder UI (`§marker§`)** and **Organizer** integration, live Proxy Intercept & Match/Replace, Sitemap, Scope, and Task Execution Engine control.
- **BurpSuite Community Edition (Standalone or Jython/Montoya Bridge)**:
  - **Standalone mode** (zero Burp extensions required): routes Repeater, Intruder, and local Spider HTTP/HTTPS traffic through the Burp Proxy (`127.0.0.1:8080`), automatically handles Burp's local MITM TLS certificate, maintains an in-memory proxy history, sitemap, and scope, and performs 11 passive security checks.
  - **Live GUI Bridge mode**: load [`burp-extension/burpsuite-mcp-bridge.jar`](./burp-extension/burpsuite-mcp-bridge.jar) (no Jython needed) or [`burp-extension/burp_mcp_bridge.py`](./burp-extension/burp_mcp_bridge.py) to control live GUI Proxy History, Intercept, Match & Replace, Target Sitemap/Scope, Repeater tabs, and JSON config on port `1337`.

---

## Edition Compatibility

| Feature Area | Community (Standalone) | Community + Bridge | BurpSuite Pro + Montoya Full Pro Bridge |
|---|---|---|---|
| Proxy History & WebSockets (`get_proxy_history*`, `proxy_get_websockets`) | MCP local HTTP history | Live GUI HTTP (+ WebSockets in JAR) | Live Pro HTTP + WebSocket history |
| Live Proxy Intercept (`set_proxy_intercept`, `get/forward/drop_intercepted_request`) | Unsupported notice | Live queue + modify/drop | Live queue + modify/drop |
| Proxy Match & Replace (`add/list/delete_proxy_match_replace_rule`) | MCP memory only | Live on all Burp Proxy traffic | Live on all Burp Proxy traffic |
| Repeater, Intruder & Organizer UI (`repeater_*`, `burp_send_to_*`, `organizer_list_items`) | Replay via `:8080` | Live Repeater & Organizer/Intruder | Full Repeater, Intruder (`§marker§`), Organizer |
| Spider / Discovery (`spider_*`) | Local crawler via `:8080` | Local crawler + live sitemap | Native Burp Crawl Engine |
| Target Sitemap & Scope (`sitemap_*`, `scope_*`) | MCP local sitemap & scope | Live GUI sitemap & scope | Live Pro sitemap (+ issues) & scope |
| **Active & Passive Scanner** (`start_scan`, `get_scan_*`, `get_all_issues`, `scanner_import_bcheck`) | 11 local passive checks | 11 passive checks on live sitemap | Full Active Audit, Crawl+Audit, BChecks & Pro Issues |
| **Burp Collaborator OAST** (`collaborator_generate_payload`, `collaborator_poll_interactions`) | Pro only | Pro only | Native Collaborator DNS/HTTP/SMTP polling |
| **Bambda & Task Engine** (`burp_import_bambda`, `burp_task_engine`) | Montoya JAR only | Supported (Montoya JAR) | Live Bambda import & Pause/Resume engine |
| **Decoder, Comparer & Report** (`decoder_*`, `comparer_*`, `report_export`) | Full local tools & passive report | Full tools + live sitemap report | Full tools + Pro findings Markdown/JSON report |
| Burp Configuration (`burp_get_configuration`, `burp_update_configuration`) | Unsupported notice | Live JSON export/import | Live project options JSON export/import |
| MCP Session Persistence (`session_save`, `session_load`, `session_info`) | Full JSON save/restore of MCP state | Full JSON save/restore + live Burp sync | Full JSON save/restore + live Burp sync |
| Extensions Management (`extensions_*`) | Unsupported notice | Bridge info, logs, and unload | Bridge info, logs, and unload |

---

## Prerequisites

- **Node.js** v18 or later (tested on Node.js v24)
- **BurpSuite Professional** (recommended for Active Scanner, Collaborator OAST, Crawl+Audit, BChecks) or **BurpSuite Community Edition**
- **JDK 21+** *(only if recompiling `burp-extension/montoya-bridge/` from source; pre-built `burp-extension/burpsuite-mcp-bridge.jar` is included)*
- *(Optional, only for `burp_mcp_bridge.py`)* **Jython standalone JAR** configured in `Settings -> Extensions -> Python environment`

---

## Installation

### 1. Build the MCP Server

```bash
git clone https://github.com/Steph-ux/burpsuite-mcp.git
cd burpsuite-mcp
npm install
npm run build
```

Compiled JavaScript output is written to `dist/index.js` (marked executable and exposed as the `burpsuite-mcp` CLI binary in `package.json`). You can link it globally with `npm link` and run `burpsuite-mcp` directly, or point your MCP client to `dist/index.js`. For watch-mode development or running the automated test suite:

```bash
npm run dev
npm test
```

### 2. Load the Full Pro / Community Bridge Extension

**Option A — Recommended: Montoya Full Pro Bridge JAR (Burp Pro & Community, zero Jython required)**

1. Unload any older bridge or disable Burp's built-in `:1337` REST API if running on the same port.
2. In BurpSuite, go to **Extensions -> Installed -> Add**:
   - **Extension type**: `Java`
   - **Extension file**: select `burp-extension/burpsuite-mcp-bridge.jar` (or rebuild it with `./burp-extension/montoya-bridge/build.sh`)
3. Click **Next**. The Output tab should display:
   `[BurpSuite MCP Full Pro Bridge (Montoya) v1.0.0] Listening on http://127.0.0.1:1337 (edition=PROFESSIONAL, api_key=disabled)`

**Option B — Python Jython Bridge (`burp-extension/burp_mcp_bridge.py` v0.3)**

1. Configure your Jython standalone `.jar` under **Extensions -> Extensions settings -> Python environment**.
2. Go to **Extensions -> Installed -> Add** (`Extension type: Python`, select `burp-extension/burp_mcp_bridge.py`).
3. Supports live Proxy/Sitemap/Scope/Repeater in Community plus Active Scan, Collaborator OAST, and Intruder UI in Pro.

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

## Available Tools (78)

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

### Session Persistence (3)

| Tool | Description |
|---|---|
| `session_info` | Inspect current in-memory session counts and REST/bridge connectivity |
| `session_save` | Export MCP/Community session state (proxy history, scope, rules, passive issues, Repeater history) to a JSON file |
| `session_load` | Restore a saved JSON session into memory (`merge` option) and sync scope/rules to Burp if reachable |

### Pro & Montoya Bridge (9)

| Tool | Description |
|---|---|
| `collaborator_generate_payload` | Generate a Burp Collaborator OAST domain/payload (`custom_data`, `secret_key`) |
| `collaborator_poll_interactions` | Poll Burp Collaborator for received DNS, HTTP, and SMTP out-of-band interactions |
| `burp_send_to_intruder` | Send a proxy item or raw `request_template` with `§marker§` positions to Burp Intruder UI |
| `burp_send_to_organizer` | Send a proxy item or custom request/response to Burp Suite Organizer |
| `organizer_list_items` | List items currently stored in Burp Suite Organizer with status and notes |
| `proxy_get_websockets` | Retrieve WebSocket frames captured by Burp Proxy (`limit`, `filter`, `direction`) |
| `scanner_import_bcheck` | Import a custom BCheck scan script directly into Burp Pro's Scanner |
| `burp_import_bambda` | Import a Bambda filter/custom-action script into Burp Suite |
| `burp_task_engine` | Inspect or set Burp Suite's global Task Execution Engine (`RUNNING` / `PAUSED`) |

---

## Usage Examples

### Generate & Poll Burp Collaborator OAST Payloads (Burp Pro)

```json
// 1. Generate payload for out-of-band SSRF / Blind XXE
collaborator_generate_payload({ "custom_data": "ssrf-probe-1" })

// 2. Poll DNS / HTTP / SMTP interactions
collaborator_poll_interactions({ "interaction_id": "<interaction_id>" })
```

### Send Marked Insertion Points to Burp Intruder UI & Import a BCheck

```json
burp_send_to_intruder({
  "url": "https://example.com/search",
  "request_template": "GET /search?q=§probe§ HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "tab_name": "Search Fuzz"
})
```

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
|                     src/index.ts (78 tools)                       |
|  +---------+ +---------+ +----------+ +----------+ +----------+   |
|  |  proxy  | | scanner | | repeater | | intruder | |  spider  |   |
|  +---------+ +---------+ +----------+ +----------+ +----------+   |
|  +-----------+ +------------+ +---------+ +----------+ +--------+ |
|  |  sitemap  | | extensions | | decoder | | comparer | | report | |
|  +-----------+ +------------+ +---------+ +----------+ +--------+ |
|  +-----------+ +-----+                                            |
|  |  session  | | pro |  src/utils/local-store.ts & burp-client    |
|  +-----------+ +-----+                                            |
+------------------------+-----------------------+------------------+
                         | REST (:1337)          | HTTP Proxy (:8080)
+------------------------v-----------------------v------------------+
|  Montoya Pro Bridge JAR (recommended) OR Jython bridge / Pro API  |
+-------------------------------------------------------------------+
```

- All runtime logs are written exclusively to `stderr` via `src/utils/logger.ts` so `stdout` remains strictly reserved for MCP JSON-RPC frames.
- `src/utils/burp-client.ts` handles both unauthenticated endpoints and API-key endpoints (`path` or `header` modes) and routes Community fallbacks through `withRestFallback()`.

---

## Troubleshooting

- **`scope_get` or `get_all_issues` returns Community local data instead of Burp GUI data**: ensure `burp-extension/burpsuite-mcp-bridge.jar` (or `burp_mcp_bridge.py` v0.3) is loaded in Burp (`Extensions -> Installed`) and listening on `127.0.0.1:1337`.
- **Collaborator, BChecks, WebSockets, or Organizer report `pro-bridge-required`**: load the Montoya Java bridge `burp-extension/burpsuite-mcp-bridge.jar` in BurpSuite Pro (`Extensions -> Installed -> Add -> Java`). PortSwigger's built-in `:1337` REST API alone does not expose these endpoints.
- **HTTPS requests in Repeater or Intruder fail with TLS certificate errors**: verify `BURP_PROXY_TLS_REJECT_UNAUTHORIZED` is `false` (default) when routing through Burp's intercepting proxy.
- **Upgrading from Community to Pro**: load `burp-extension/burpsuite-mcp-bridge.jar` (recommended) or `burp_mcp_bridge.py` v0.3 in BurpSuite Pro on port `1337`; if using PortSwigger's built-in REST API instead, set `BURP_API_KEY` in `.env` or your MCP client config.

---

## License

This project is licensed under the [MIT License](./LICENSE).
