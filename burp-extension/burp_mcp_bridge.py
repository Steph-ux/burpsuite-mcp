# -*- coding: utf-8 -*-
"""
Optional BurpSuite Community Edition REST Bridge Extension (Jython)
====================================================================
BurpSuite Community Edition does not ship with PortSwigger's built-in :1337
REST API (which is Pro-only). Load this extension in Burp Community
(Extensions -> Add -> Extension type: Python) to expose live Burp Community
control on 127.0.0.1:1337:
  - Proxy History, Live Proxy Intercept (toggle/list/forward/drop), Live Match & Replace
  - Target Sitemap & Scope (read/add/remove/check)
  - Send to Repeater UI
  - Burp Configuration (saveConfigAsJson / loadConfigFromJson)
  - Bridge Extension metadata & unload

Note: burpsuite-mcp ALSO works in Community Edition without loading this file
(via local proxy/crawler/passive fallback on port 8080), and works natively
with BurpSuite Pro when you upgrade and set BURP_API_KEY.
"""

import json
import os
import re
import threading
import traceback
import uuid
from urlparse import urlparse, parse_qs

from burp import (
    IBurpExtender,
    IExtensionStateListener,
    IInterceptedProxyMessage,
    IProxyListener,
)
from com.sun.net.httpserver import HttpServer, HttpHandler
from java.io import ByteArrayOutputStream
from java.net import InetSocketAddress, URL
from java.util.concurrent import Executors
import jarray

try:
    _STR_TYPES = (basestring,)
except NameError:
    _STR_TYPES = (str,)


class ProxyController(IProxyListener):
    """Handles live Proxy interception queue and Match/Replace rules in Burp Community."""

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.lock = threading.Lock()
        self.intercept_requests = False
        self.intercept_responses = False
        self.pending = {}  # id -> {"event": Event, "action": "forward"|"drop", "modified": str|None, "info": dict}
        self.match_replace_rules = []
        self.output_log = []

    def log(self, msg):
        self.callbacks.printOutput(msg)
        with self.lock:
            self.output_log.append(msg)
            if len(self.output_log) > 200:
                self.output_log = self.output_log[-200:]

    def set_intercept(self, is_request, enabled):
        released = 0
        with self.lock:
            if is_request:
                self.intercept_requests = bool(enabled)
            else:
                self.intercept_responses = bool(enabled)

            master = self.intercept_requests or self.intercept_responses
            try:
                self.callbacks.setProxyInterceptionEnabled(master)
            except Exception:
                pass

            if not enabled:
                for item in self.pending.values():
                    if item["is_request"] == is_request:
                        item["action"] = "forward"
                        item["event"].set()
                        released += 1
        return {
            "intercept_requests": self.intercept_requests,
            "intercept_responses": self.intercept_responses,
            "released_pending": released,
        }

    def release_all(self):
        with self.lock:
            for item in self.pending.values():
                item["action"] = "forward"
                item["event"].set()

    def list_pending(self):
        with self.lock:
            return [dict(v["summary"]) for v in self.pending.values()]

    def resolve_pending(self, item_id, action, modified_raw=None):
        with self.lock:
            entry = self.pending.get(item_id)
            if not entry:
                return False
            entry["action"] = action
            entry["modified"] = modified_raw
            entry["event"].set()
            return True

    def _apply_match_replace(self, is_request, message_info):
        with self.lock:
            rules = [dict(r) for r in self.match_replace_rules if r.get("enabled", True)]
        if not rules:
            return

        raw_bytes = message_info.getRequest() if is_request else message_info.getResponse()
        if not raw_bytes:
            return

        raw_str = self.helpers.bytesToString(raw_bytes)
        sep = "\r\n\r\n" if "\r\n\r\n" in raw_str else "\n\n"
        line_sep = "\r\n" if "\r\n" in raw_str else "\n"
        parts = raw_str.split(sep, 1)
        head = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        head_lines = head.split(line_sep)
        first_line = head_lines[0] if head_lines else ""
        hdr_lines = head_lines[1:] if len(head_lines) > 1 else []
        changed = False

        def sub_text(text, rule):
            pattern = rule.get("match", "")
            repl = rule.get("replace", "")
            if not pattern:
                return text, False
            if rule.get("is_simple_match", True):
                if pattern in text:
                    return text.replace(pattern, repl), True
                return text, False
            new_text, n = re.subn(pattern, repl, text)
            return new_text, n > 0

        for rule in rules:
            rtype = rule.get("rule_type", "")
            if is_request and rtype == "request_first_line":
                first_line, did = sub_text(first_line, rule)
                changed = changed or did
            elif is_request and rtype == "request_header":
                new_hdrs = []
                for hl in hdr_lines:
                    nl, did = sub_text(hl, rule)
                    changed = changed or did
                    if nl:
                        new_hdrs.append(nl)
                hdr_lines = new_hdrs
            elif is_request and rtype == "request_body":
                body, did = sub_text(body, rule)
                changed = changed or did
            elif (not is_request) and rtype == "response_header":
                new_hdrs = []
                for hl in hdr_lines:
                    nl, did = sub_text(hl, rule)
                    changed = changed or did
                    if nl:
                        new_hdrs.append(nl)
                hdr_lines = new_hdrs
            elif (not is_request) and rtype == "response_body":
                body, did = sub_text(body, rule)
                changed = changed or did

        if changed:
            rebuilt = line_sep.join([first_line] + hdr_lines) + sep + body
            out_bytes = self.helpers.stringToBytes(rebuilt)
            if is_request:
                message_info.setRequest(out_bytes)
            else:
                message_info.setResponse(out_bytes)

    def processProxyMessage(self, messageIsRequest, message):
        msg_info = message.getMessageInfo()
        self._apply_match_replace(bool(messageIsRequest), msg_info)

        with self.lock:
            should_hold = self.intercept_requests if messageIsRequest else self.intercept_responses
        if not should_hold:
            return

        ref_id = str(message.getMessageReference())
        svc = message.getHttpService()
        raw_bytes = msg_info.getRequest() if messageIsRequest else msg_info.getResponse()
        raw_text = self.helpers.bytesToString(raw_bytes) if raw_bytes else ""
        url_str = ""
        method_str = ""
        if messageIsRequest and raw_bytes:
            req_info = self.helpers.analyzeRequest(svc, raw_bytes)
            url_str = str(req_info.getUrl())
            method_str = req_info.getMethod()

        ev = threading.Event()
        entry = {
            "event": ev,
            "is_request": bool(messageIsRequest),
            "action": "forward",
            "modified": None,
            "summary": {
                "id": ref_id,
                "is_request": bool(messageIsRequest),
                "host": svc.getHost() if svc else "",
                "port": svc.getPort() if svc else 80,
                "protocol": svc.getProtocol() if svc else "http",
                "method": method_str,
                "url": url_str,
                "raw": raw_text[:20000],
            },
        }
        with self.lock:
            self.pending[ref_id] = entry

        # Wait up to 120s for MCP forward/drop; auto-forward on timeout to avoid deadlocking Burp
        ev.wait(120.0)

        with self.lock:
            resolved = self.pending.pop(ref_id, entry)

        if resolved["action"] == "drop":
            message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP)
            return

        if resolved.get("modified") is not None:
            mod_bytes = self.helpers.stringToBytes(resolved["modified"])
            if messageIsRequest:
                msg_info.setRequest(mod_bytes)
            else:
                msg_info.setResponse(mod_bytes)

        message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)


class BridgeHandler(HttpHandler):
    def __init__(self, callbacks, helpers, api_key, proxy_ctrl):
        self.callbacks = callbacks
        self.helpers = helpers
        self.api_key = api_key or ""
        self.proxy_ctrl = proxy_ctrl
        self.scope_rules = {"include": [], "exclude": []}

    def _build_raw_request(self, req_obj, host):
        if isinstance(req_obj, _STR_TYPES):
            return req_obj
        if isinstance(req_obj, dict) and "request" in req_obj and isinstance(req_obj["request"], dict):
            req_obj = req_obj["request"]
        if isinstance(req_obj, dict):
            if req_obj.get("raw"):
                return req_obj["raw"]
            method = req_obj.get("method", "GET")
            path = req_obj.get("path", "/")
            if not path and req_obj.get("url"):
                parsed = urlparse(req_obj["url"])
                path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
            headers = req_obj.get("headers") or {}
            lines = ["%s %s HTTP/1.1" % (method, path)]
            has_host = False
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if str(k).lower() == "host":
                        has_host = True
                    lines.append("%s: %s" % (k, v))
            if not has_host and host:
                lines.append("Host: %s" % host)
            body_str = req_obj.get("body") or ""
            return "\r\n".join(lines) + "\r\n\r\n" + body_str
        return ""

    def _send_json(self, exchange, status, data):
        body = json.dumps(data).encode("utf-8")
        headers = exchange.getResponseHeaders()
        headers.set("Content-Type", "application/json; charset=utf-8")
        exchange.sendResponseHeaders(status, len(body))
        out = exchange.getResponseBody()
        out.write(body)
        out.close()

    def _read_body(self, exchange):
        stream = exchange.getRequestBody()
        baos = ByteArrayOutputStream()
        buf = jarray.zeros(4096, "b")
        while True:
            n = stream.read(buf)
            if n <= 0:
                break
            baos.write(buf, 0, n)
        raw = baos.toString("UTF-8")
        return json.loads(raw) if raw and raw.strip() else {}

    def _check_auth_and_strip_path(self, exchange):
        raw_path = exchange.getRequestURI().getRawPath() or "/"
        if not self.api_key:
            return True, raw_path

        prefix = "/" + self.api_key + "/v0.1"
        if raw_path.startswith(prefix):
            return True, "/v0.1" + raw_path[len(prefix):]

        req_headers = exchange.getRequestHeaders()
        for hdr in ("X-Burp-Api-Token", "API-KEY", "Authorization"):
            val = req_headers.getFirst(hdr)
            if val == self.api_key:
                return True, raw_path

        return False, raw_path

    def _parse_message(self, item, msg_id):
        req_bytes = item.getRequest()
        res_bytes = item.getResponse()
        svc = item.getHttpService()
        host = svc.getHost() if svc else ""
        port = svc.getPort() if svc else 80
        proto = svc.getProtocol() if svc else "http"

        req_obj = {}
        if req_bytes:
            req_info = self.helpers.analyzeRequest(svc, req_bytes)
            req_headers = {}
            for h in list(req_info.getHeaders())[1:]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    req_headers[k.strip().lower()] = v.strip()
            offset = req_info.getBodyOffset()
            req_body = self.helpers.bytesToString(req_bytes[offset:])
            url_obj = req_info.getUrl()
            req_obj = {
                "method": req_info.getMethod(),
                "url": str(url_obj) if url_obj else "",
                "path": (url_obj.getPath() + ("?" + url_obj.getQuery() if url_obj.getQuery() else "")) if url_obj else "/",
                "headers": req_headers,
                "body": req_body,
            }

        res_obj = {}
        status_code = 0
        mime_type = ""
        if res_bytes:
            res_info = self.helpers.analyzeResponse(res_bytes)
            status_code = res_info.getStatusCode()
            mime_type = res_info.getStatedMimeType() or ""
            res_headers = {}
            for h in list(res_info.getHeaders())[1:]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    res_headers[k.strip().lower()] = v.strip()
            offset = res_info.getBodyOffset()
            res_body = self.helpers.bytesToString(res_bytes[offset:])
            res_obj = {
                "statusCode": status_code,
                "headers": res_headers,
                "body": res_body[:50000],
                "mimeType": mime_type,
            }

        return {
            "id": msg_id,
            "messageId": msg_id,
            "host": host,
            "port": port,
            "protocol": proto,
            "path": req_obj.get("path", "/"),
            "responseCode": status_code,
            "mimeType": mime_type,
            "request": req_obj,
            "response": res_obj,
        }

    def handle(self, exchange):
        try:
            ok, path = self._check_auth_and_strip_path(exchange)
            if not ok:
                self._send_json(exchange, 401, {"error": "Unauthorized"})
                return

            method = exchange.getRequestMethod().upper()
            raw_query = exchange.getRequestURI().getRawQuery() or ""
            query = parse_qs(raw_query)

            if method == "GET" and path in ("/v0.1", "/v0.1/"):
                self._send_json(exchange, 200, {"bridge": "burpsuite-mcp-community", "version": "0.2"})
                return

            if method == "GET" and path in ("/v0.1/burp/version", "/burp/versions"):
                ver = list(self.callbacks.getBurpVersion())
                self._send_json(exchange, 200, {
                    "edition": ver[0] if len(ver) > 0 else "Burp Suite",
                    "version": ".".join(ver[1:]) if len(ver) > 1 else "unknown",
                    "bridge": True,
                })
                return

            if method == "GET" and path == "/v0.1/burp/configuration":
                cfg_json = self.callbacks.saveConfigAsJson()
                self._send_json(exchange, 200, json.loads(cfg_json))
                return

            if method == "PUT" and path == "/v0.1/burp/configuration":
                body = self._read_body(exchange)
                self.callbacks.loadConfigFromJson(json.dumps(body))
                self._send_json(exchange, 200, {"updated": True})
                return

            # ── Proxy History ─────────────────────────────────
            if method == "GET" and path == "/v0.1/proxy/history":
                items = list(self.callbacks.getProxyHistory())
                messages = [self._parse_message(item, idx + 1) for idx, item in enumerate(items)]
                self._send_json(exchange, 200, {"messages": messages})
                return

            if method == "GET" and path.startswith("/v0.1/proxy/history/"):
                target_id = int(path.rsplit("/", 1)[-1])
                items = list(self.callbacks.getProxyHistory())
                if 1 <= target_id <= len(items):
                    self._send_json(exchange, 200, self._parse_message(items[target_id - 1], target_id))
                else:
                    self._send_json(exchange, 404, {"error": "Proxy history item not found"})
                return

            # ── Proxy Intercept (live via IProxyListener) ──────
            if method == "PUT" and path in ("/v0.1/proxy/intercept_requests", "/v0.1/proxy/intercept_responses"):
                body = self._read_body(exchange)
                enabled = str(body.get("intercept", "")).lower() == "enabled"
                is_req = path.endswith("intercept_requests")
                res = self.proxy_ctrl.set_intercept(is_req, enabled)
                self._send_json(exchange, 200, res)
                return

            if method == "GET" and path == "/v0.1/proxy/intercept_requests":
                self._send_json(exchange, 200, {"requests": self.proxy_ctrl.list_pending()})
                return

            if method == "POST" and path.startswith("/v0.1/proxy/intercept_requests/"):
                parts = path.strip("/").split("/")
                # /v0.1/proxy/intercept_requests/<id>/<action>
                if len(parts) == 5 and parts[4] in ("forward", "drop"):
                    item_id = parts[3]
                    action = parts[4]
                    body = self._read_body(exchange)
                    mod_req = body.get("request") if action == "forward" else None
                    found = self.proxy_ctrl.resolve_pending(item_id, action, mod_req)
                    if found:
                        self._send_json(exchange, 200, {"ok": True, "id": item_id, "action": action})
                    else:
                        self._send_json(exchange, 404, {"error": "Intercepted request not found", "id": item_id})
                    return

            # ── Proxy Match & Replace (live via IProxyListener) ─
            if method == "GET" and path == "/v0.1/proxy/match_replace_rules":
                with self.proxy_ctrl.lock:
                    rules = list(self.proxy_ctrl.match_replace_rules)
                self._send_json(exchange, 200, {"rules": rules})
                return

            if method == "POST" and path == "/v0.1/proxy/match_replace_rules":
                body = self._read_body(exchange)
                rule = {
                    "id": str(uuid.uuid4())[:8],
                    "rule_type": body.get("rule_type", "request_header"),
                    "match": body.get("match", ""),
                    "replace": body.get("replace", ""),
                    "is_simple_match": bool(body.get("is_simple_match", True)),
                    "enabled": bool(body.get("enabled", True)),
                    "comment": body.get("comment", ""),
                }
                with self.proxy_ctrl.lock:
                    self.proxy_ctrl.match_replace_rules.append(rule)
                self._send_json(exchange, 201, rule)
                return

            if method == "DELETE" and path.startswith("/v0.1/proxy/match_replace_rules/"):
                rule_id = path.rsplit("/", 1)[-1]
                with self.proxy_ctrl.lock:
                    before = len(self.proxy_ctrl.match_replace_rules)
                    self.proxy_ctrl.match_replace_rules = [
                        r for r in self.proxy_ctrl.match_replace_rules if r.get("id") != rule_id
                    ]
                    deleted = len(self.proxy_ctrl.match_replace_rules) < before
                self._send_json(exchange, 200 if deleted else 404, {"deleted": deleted, "id": rule_id})
                return

            # ── Target Sitemap & Scope ────────────────────────
            if method == "GET" and path == "/v0.1/target/sitemap":
                host_filter = query.get("host", [None])[0] or query.get("base_url", [None])[0]
                prefix = ("http://" + host_filter) if host_filter and "://" not in host_filter else host_filter
                items = list(self.callbacks.getSiteMap(prefix))
                nodes = [self._parse_message(item, idx + 1) for idx, item in enumerate(items)]
                self._send_json(exchange, 200, nodes)
                return

            if method == "GET" and path == "/v0.1/target/scope":
                self._send_json(exchange, 200, self.scope_rules)
                return

            if method == "GET" and path == "/v0.1/target/scope/check":
                url_str = query.get("url", [""])[0]
                in_scope = bool(url_str and self.callbacks.isInScope(URL(url_str)))
                self._send_json(exchange, 200, {"inScope": in_scope})
                return

            if method == "PUT" and path == "/v0.1/target/scope":
                body = self._read_body(exchange)
                for entry in body.get("include", []):
                    u = entry.get("url") if isinstance(entry, dict) else entry
                    if u:
                        self.callbacks.includeInScope(URL(u))
                        if not any(r.get("url") == u for r in self.scope_rules["include"]):
                            self.scope_rules["include"].append({"enabled": True, "url": u})
                for entry in body.get("exclude", []):
                    u = entry.get("url") if isinstance(entry, dict) else entry
                    if u:
                        self.callbacks.excludeFromScope(URL(u))
                        if not any(r.get("url") == u for r in self.scope_rules["exclude"]):
                            self.scope_rules["exclude"].append({"enabled": True, "url": u})
                self._send_json(exchange, 200, {"updated": True})
                return

            # ── Repeater UI ───────────────────────────────────
            if method == "POST" and path == "/v0.1/repeater":
                body = self._read_body(exchange)
                req_container = body.get("request", {})
                host = body.get("host", "") or (req_container.get("host", "") if isinstance(req_container, dict) else "")
                port = int(body.get("port") or (req_container.get("port") if isinstance(req_container, dict) and req_container.get("port") else 443))
                proto = body.get("protocol") or (req_container.get("protocol") if isinstance(req_container, dict) and req_container.get("protocol") else "https")
                if not host and isinstance(req_container, dict):
                    inner_url = (req_container.get("request") or {}).get("url") if isinstance(req_container.get("request"), dict) else req_container.get("url")
                    if inner_url:
                        parsed_u = urlparse(inner_url)
                        host = parsed_u.hostname or ""
                        proto = parsed_u.scheme or proto
                        port = parsed_u.port or (443 if proto == "https" else 80)
                use_https = proto == "https"
                raw_req = self._build_raw_request(req_container, host)
                if host and raw_req:
                    self.callbacks.sendToRepeater(host, port, use_https, self.helpers.stringToBytes(raw_req), "MCP")
                    self._send_json(exchange, 200, {"sent": True, "host": host, "port": port})
                else:
                    self._send_json(exchange, 400, {"error": "host and request required"})
                return

            # ── Extensions (bridge self-management) ───────────
            if method == "GET" and path == "/v0.1/extensions":
                self._send_json(exchange, 200, [{
                    "id": "burp-mcp-bridge",
                    "name": "BurpSuite MCP Community Bridge",
                    "version": "0.2.0",
                    "state": "enabled",
                }])
                return

            if method == "GET" and path == "/v0.1/extensions/burp-mcp-bridge":
                self._send_json(exchange, 200, {
                    "id": "burp-mcp-bridge",
                    "name": "BurpSuite MCP Community Bridge",
                    "version": "0.2.0",
                    "state": "enabled",
                })
                return

            if method == "GET" and path == "/v0.1/extensions/burp-mcp-bridge/output":
                with self.proxy_ctrl.lock:
                    logs = "\n".join(self.proxy_ctrl.output_log)
                self._send_json(exchange, 200, {"id": "burp-mcp-bridge", "stdout": logs, "stderr": ""})
                return

            if method in ("DELETE", "POST") and path.startswith("/v0.1/extensions/burp-mcp-bridge/output"):
                with self.proxy_ctrl.lock:
                    self.proxy_ctrl.output_log = []
                self._send_json(exchange, 200, {"cleared": True})
                return

            if method == "DELETE" and path == "/v0.1/extensions/burp-mcp-bridge":
                self._send_json(exchange, 200, {"unloading": True, "id": "burp-mcp-bridge"})
                self.callbacks.unloadExtension()
                return

            self._send_json(exchange, 404, {"error": "Endpoint not supported by Community Bridge", "path": path})
        except Exception as exc:
            self._send_json(exchange, 500, {"error": str(exc), "trace": traceback.format_exc()})


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpSuite MCP Community Bridge")
        callbacks.registerExtensionStateListener(self)

        self.proxy_ctrl = ProxyController(callbacks, self.helpers)
        callbacks.registerProxyListener(self.proxy_ctrl)

        port = int(os.environ.get("BURP_API_PORT", "1337"))
        api_key = os.environ.get("BURP_API_KEY", "")

        self.server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
        self.server.createContext("/", BridgeHandler(callbacks, self.helpers, api_key, self.proxy_ctrl))
        self.server.setExecutor(Executors.newFixedThreadPool(4))
        self.server.start()

        self.proxy_ctrl.log("[BurpSuite MCP Bridge v0.2] Listening on http://127.0.0.1:%d (api_key=%s)" % (
            port, "configured" if api_key else "disabled"
        ))

    def extensionUnloaded(self):
        if hasattr(self, "proxy_ctrl") and self.proxy_ctrl:
            self.proxy_ctrl.release_all()
        if hasattr(self, "server") and self.server:
            self.server.stop(0)
            self.callbacks.printOutput("[BurpSuite MCP Bridge] Stopped.")
