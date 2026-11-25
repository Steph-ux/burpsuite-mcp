# BurpSuite MCP

A **Model Context Protocol (MCP)** server that exposes BurpSuite Pro's REST API as AI-callable tools. Connect any MCP-compatible client (Claude Desktop, Antigravity, …) directly to your running BurpSuite instance and automate pentesting workflows with natural language.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage with Claude Desktop](#usage-with-claude-desktop)
- [Available Tools](#available-tools)
  - [Proxy](#-proxy)
  - [Scanner](#-scanner)
  - [Repeater](#-repeater)
  - [Intruder](#-intruder)
  - [Spider](#-spider)
  - [Sitemap](#-sitemap)
  - [Extensions](#-extensions)
- [Usage Examples](#usage-examples)
- [Architecture](#architecture)

---

## Prerequisites

| Requirement | Details |
|---|---|
| **BurpSuite Community or Pro** | Works with **Community** (no API key required) and **Professional** (with or without API key) |
| **Burp HTTP Proxy** | Default `127.0.0.1:8080` (used by Repeater, Intruder, and Community Spider) |
| **Burp REST API** *(Pro)* | `Burp → Settings → Suite → REST API` → tick *Service enabled* on port `1337` |
| **API key** *(optional)* | Leave `BURP_API_KEY` empty for Community or unauthenticated Pro; set it when using Pro API key auth |
| **Optional Community Bridge** | Load [`burp-extension/burp_mcp_bridge.py`](./burp-extension/burp_mcp_bridge.py) in Burp Community (Jython) for live GUI Proxy History / Sitemap access |
| **Node.js** | v18 or later |

---

## Installation

```bash
# 1. Clone / enter the project
cd burpsuite-mcp

# 2. Install dependencies
npm install

# 3. Build
npm run build
# → compiled output lands in dist/
```

For development with live-reload:

```bash
npm run dev
```

---

## Configuration

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

```ini
# .env
BURP_HOST=127.0.0.1       # Burp proxy & REST host
BURP_PORT=8080            # Burp HTTP proxy port
BURP_API_PORT=1337        # Burp REST API port (Pro or optional Community bridge)
BURP_API_KEY=             # Leave blank without key (Community / no-auth); set when using Pro key
BURP_API_KEY_MODE=auto    # auto | path (/<key>/v0.1/...) | header (X-Burp-Api-Token / API-KEY)
BURP_EDITION=auto         # auto | community | pro
```

### How Community vs Pro & API Key Modes Work

1. **Without API Key (Burp Community Edition today)**:
   - Leave `BURP_API_KEY=` empty and `BURP_EDITION=auto`.
   - **Repeater**, **Intruder**, and **Spider** route traffic directly through Burp's proxy (`127.0.0.1:8080`), automatically populating Burp's UI and tolerating Burp's MITM TLS certificate.
   - **Proxy History**, **Sitemap**, **Scope**, and **Passive Scan** automatically use an in-memory local store + passive security analyzer when port `1337` is closed.
   - *(Optional)* Load `burp-extension/burp_mcp_bridge.py` in Burp Community (`Extensions → Add → Python`) to expose live GUI Proxy History, Sitemap, and Scope on port `1337`.
2. **With API Key (when upgrading to BurpSuite Pro)**:
   - Just set `BURP_API_KEY=your-key` in `.env` (or in your MCP `env` block).
   - `BURP_API_KEY_MODE=auto` automatically supports PortSwigger's native URL-path auth (`http://127.0.0.1:1337/<key>/v0.1/...`) and falls back to header auth (`X-Burp-Api-Token`, `API-KEY`, `Authorization`) if a custom REST extension is used.

---

## Usage with Claude Desktop

Add the following block to your Claude Desktop configuration file.

**macOS** – `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows** – `%APPDATA%\Claude\claude_desktop_config.json`  
**Linux** – `~/.config/Claude/claude_desktop_config.json`

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

Replace `/absolute/path/to/burpsuite-mcp` with the real path on your machine, then restart Claude Desktop. The BurpSuite tools will appear automatically.

---

## Available Tools

### 🔀 Proxy

| Tool | Description |
|---|---|
| `get_proxy_history` | Fetch proxy history with optional URL filter and limit |
| `get_proxy_history_item` | Retrieve full request + response for a specific history item |
| `set_proxy_intercept` | Enable or disable request/response interception |
| `get_intercepted_requests` | List requests currently held in the intercept queue |
| `forward_intercepted_request` | Forward an intercepted request (optionally modified) |
| `drop_intercepted_request` | Drop an intercepted request |
| `add_proxy_match_replace_rule` | Add a match-and-replace rule for proxy traffic |
| `list_proxy_match_replace_rules` | List all active match-and-replace rules |
| `delete_proxy_match_replace_rule` | Delete a match-and-replace rule by ID |

### 🔍 Scanner

| Tool | Description |
|---|---|
| `start_scan` | Launch an active scan against one or more URLs |
| `get_scan_status` | Poll the status and progress of a running scan |
| `get_scan_issues` | Retrieve vulnerabilities found by a scan task |
| `stop_scan` | Cancel a running scan |
| `list_scans` | List all scan tasks |
| `start_passive_scan` | Submit a request/response pair for passive analysis |
| `get_all_issues` | Retrieve all issues site-wide (across all scans) |
| `get_issue_definitions` | Get the full Burp issue definitions catalogue |
| `get_issues_for_host` | Get all issues found for a specific host |

### 🔁 Repeater

| Tool | Description |
|---|---|
| `repeater_send_request` | Send a raw HTTP/HTTPS request (optionally through Burp proxy) and return full response |
| `repeater_get_history` | List saved request history (most recent first) |
| `repeater_get_item` | Retrieve a full request+response entry by UUID |
| `repeater_replay_from_proxy_history` | Replay a request from the proxy history via Repeater |
| `repeater_save_request` | Save a manually-constructed request to history |
| `repeater_clear_history` | Clear all Repeater history entries |

### ⚔️ Intruder

| Tool | Description |
|---|---|
| `intruder_start_attack` | Launch an Intruder attack (sniper/battering_ram/pitchfork/cluster_bomb) with payloads |
| `intruder_get_attack_status` | Get status and progress of an attack |
| `intruder_get_results` | Retrieve paginated results with optional status code/length filters |
| `intruder_stop_attack` | Stop a running Intruder attack |
| `intruder_list_attacks` | List all Intruder attacks in memory |
| `intruder_clear_attack` | Delete an attack from memory |

### 🕷️ Spider

| Tool | Description |
|---|---|
| `spider_start_crawl` | Start a spider/crawl task on a URL |
| `spider_get_crawl_status` | Get the status of a crawl task |
| `spider_get_discovered_urls` | Get all URLs discovered by a crawl |
| `spider_stop_crawl` | Stop a running crawl task |
| `spider_list_crawls` | List all crawl tasks |
| `spider_get_forms` | Get HTML forms discovered during crawl |
| `spider_get_endpoints` | Get API-style endpoints discovered during crawl |

### 🗺️ Sitemap

| Tool | Description |
|---|---|
| `sitemap_get` | Retrieve the site map tree grouped by host |
| `sitemap_get_host_details` | Get detailed info for a specific host (endpoints, status distribution, technologies) |
| `scope_get` | Get current scope definition (included/excluded rules) |
| `scope_add_url` | Add a URL pattern to the active scope |
| `scope_remove_url` | Remove a URL pattern from scope |
| `scope_set` | Replace entire scope definition |
| `scope_check_url` | Check whether a specific URL is in scope |
| `sitemap_get_requests_for_host` | Get requests with full req+res for a host |
| `sitemap_clear` | Clear the site map |
| `sitemap_get_technologies` | Fingerprint technologies from response headers |

### 🧩 Extensions

| Tool | Description |
|---|---|
| `extensions_list` | List all installed extensions |
| `extensions_get` | Get details of a specific extension |
| `extensions_toggle` | Enable or disable an extension |
| `extensions_get_output` | Retrieve stdout/stderr output of an extension |
| `extensions_clear_output` | Clear an extension's output buffer |
| `extensions_install` | Install an extension from a .jar or .py file |
| `extensions_unload` | Unload an extension |
| `burp_get_version` | Get BurpSuite version information |
| `burp_get_configuration` | Get the current BurpSuite configuration |
| `burp_update_configuration` | Update BurpSuite configuration |
| `burp_save_state` | Save the current project state |
| `burp_send_to_repeater` | Send a proxy history item to the Repeater UI |

---

## Usage Examples

### Scan a target

```
"Scan https://example.com for vulnerabilities"
→ start_scan({ urls: ["https://example.com"], scope_included: ["https://example.com"] })
→ get_scan_status({ task_id: "..." })  // poll
→ get_scan_issues({ task_id: "..." })  // read results
```

### Review proxy history

```
"Show me the last 20 requests to /api/"
→ get_proxy_history({ limit: 20, filter: "/api/" })
```

### Fuzz a parameter

```
"Run an Intruder sniper attack on this login request with the top 100 passwords"
→ intruder_start_attack({
    host: "target.com",
    port: 443,
    use_https: true,
    request_template: "POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=§FUZZ§",
    attack_type: "sniper",
    payload_sets: [["password1", "password2"]]
  })
```

### Check extension output

```
"What did the SQLMap extension log?"
→ extensions_list()
→ extensions_get_output({ extension_id: "sqlmap-id" })
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│          MCP Client (Claude Desktop)        │
└─────────────────┬───────────────────────────┘
                  │ MCP over stdio
┌─────────────────▼───────────────────────────┐
│          src/index.ts (this server)         │
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐   │
│  │  proxy  │ │ scanner │ │  repeater   │   │
│  │intruder │ │  spider │ │   sitemap   │   │
│  │          extensions                 │   │
│  └────────────────────┬────────────────┘   │
│              BurpClient│                    │
└───────────────────────┼────────────────────┘
                        │ HTTP REST
┌───────────────────────▼────────────────────┐
│       BurpSuite Pro (REST API :1337)       │
└────────────────────────────────────────────┘
```

Each module (`src/modules/*.ts`) exports a `*_TOOLS` array. `src/index.ts` merges them, registers them with the MCP `Server`, and routes incoming `call_tool` requests to the matching handler, passing a shared `BurpClient` instance.
