// ============================================================
// BurpSuite MCP – Report Export Module
// Generates structured Markdown or JSON defensive audit reports
// from Burp sitemap, technologies, and passive/active findings.
// ============================================================

import fs from "node:fs";
import path from "node:path";
import { type BurpClient, getBurpClient } from "../utils/burp-client.js";
import { detectTechnologies, fetchSiteMapEntries } from "./sitemap.js";
import { analyzeCommunityLiveSitemap } from "./scanner.js";

interface ReportFinding {
  name: string;
  severity: string;
  confidence: string;
  host: string;
  path: string;
  description: string;
  remediation: string;
  evidence?: string;
}

const SEVERITY_ORDER: Record<string, number> = {
  high: 0,
  medium: 1,
  low: 2,
  info: 3,
  information: 3,
};

function severityRank(sev: string): number {
  return SEVERITY_ORDER[sev.toLowerCase()] ?? 4;
}

async function collectFindings(
  client: BurpClient,
  host?: string
): Promise<{ mode: string; findings: ReportFinding[] }> {
  return client.withRestFallback(
    async () => {
      const [defsRes, sitemapRes] = await Promise.all([
        client.get("/v0.1/issue-definitions"),
        client.get(host ? `/v0.1/target/sitemap?host=${encodeURIComponent(host)}` : "/v0.1/target/sitemap"),
      ]);

      const definitions: Record<number, Record<string, unknown>> = {};
      const rawDefs = Array.isArray(defsRes)
        ? defsRes
        : ((defsRes as Record<string, unknown>)?.issue_definitions ?? []);
      for (const def of rawDefs as Record<string, unknown>[]) {
        const idx = def.type_index ?? def.issue_type_id;
        if (idx !== undefined) definitions[idx as number] = def;
      }

      const nodes = Array.isArray(sitemapRes)
        ? (sitemapRes as Record<string, unknown>[])
        : (((sitemapRes as Record<string, unknown>)?.sitemap as Record<string, unknown>[]) ?? []);

      const findings: ReportFinding[] = [];
      for (const node of nodes) {
        const nodeIssues = Array.isArray(node.issues)
          ? (node.issues as Record<string, unknown>[])
          : [];
        for (const issue of nodeIssues) {
          const typeIdx = issue.type_index as number | undefined;
          const def = typeIdx !== undefined ? definitions[typeIdx] : undefined;
          findings.push({
            name: String(issue.name ?? def?.name ?? "Unknown"),
            severity: String(issue.severity ?? "info").toLowerCase(),
            confidence: String(issue.confidence ?? "tentative").toLowerCase(),
            host: String(issue.origin ?? issue.host ?? node.host ?? ""),
            path: String(issue.path ?? node.path ?? "/"),
            description: String(issue.description ?? issue.detail ?? def?.description ?? ""),
            remediation: String(issue.remediation ?? issue.recommendation ?? def?.remediation ?? ""),
          });
        }
      }
      return { mode: "burp-rest-api", findings };
    },
    async () => {
      const passive = await analyzeCommunityLiveSitemap(client, host);
      return {
        mode: passive.mode,
        findings: passive.issues.map((i) => ({
          name: i.name,
          severity: i.severity,
          confidence: i.confidence,
          host: i.host,
          path: i.path,
          description: i.description,
          remediation: i.remediation,
          ...(i.evidence ? { evidence: i.evidence } : {}),
        })),
      };
    }
  );
}

function renderMarkdownReport(data: {
  generated_at: string;
  burp_info: Record<string, unknown>;
  host_filter: string | null;
  sitemap_mode: string;
  findings_mode: string;
  hosts: string[];
  technologies: Record<string, string[]>;
  severity_counts: Record<string, number>;
  findings: ReportFinding[];
  endpoints: Array<{ host: string; method: string; path: string; status: number | null; mime: string }>;
}): string {
  const lines: string[] = [];
  lines.push("# BurpSuite Audit Report");
  lines.push("");
  lines.push(`- **Generated at**: ${data.generated_at}`);
  lines.push(`- **Burp Edition**: ${String(data.burp_info.edition ?? "Unknown")} ${String(data.burp_info.version ?? "")}`.trim());
  lines.push(`- **Target Scope**: ${data.host_filter ?? (data.hosts.length ? data.hosts.join(", ") : "All captured hosts")}`);
  lines.push(`- **Data Sources**: sitemap=${data.sitemap_mode}, findings=${data.findings_mode}`);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("|---|---:|");
  lines.push(`| Hosts observed | ${data.hosts.length} |`);
  lines.push(`| Endpoints observed | ${data.endpoints.length} |`);
  lines.push(`| Total findings | ${data.findings.length} |`);
  lines.push(`| High severity | ${data.severity_counts.high ?? 0} |`);
  lines.push(`| Medium severity | ${data.severity_counts.medium ?? 0} |`);
  lines.push(`| Low severity | ${data.severity_counts.low ?? 0} |`);
  lines.push(`| Informational | ${data.severity_counts.info ?? 0} |`);
  lines.push("");

  lines.push("## Detected Technologies");
  lines.push("");
  const techEntries = Object.entries(data.technologies);
  if (techEntries.length === 0) {
    lines.push("No technology fingerprints detected.");
  } else {
    lines.push("| Category | Values |");
    lines.push("|---|---|");
    for (const [k, vals] of techEntries) {
      lines.push(`| \`${k}\` | ${vals.join(", ")} |`);
    }
  }
  lines.push("");

  lines.push("## Findings");
  lines.push("");
  if (data.findings.length === 0) {
    lines.push("No findings recorded.");
  } else {
    // Group findings by (name, severity) for clean readability
    const grouped = new Map<string, { finding: ReportFinding; locations: string[]; evidences: string[] }>();
    for (const f of data.findings) {
      const key = `${f.severity}:${f.name}`;
      if (!grouped.has(key)) {
        grouped.set(key, { finding: f, locations: [], evidences: [] });
      }
      const grp = grouped.get(key)!;
      const loc = `${f.host}${f.path}`;
      if (!grp.locations.includes(loc)) grp.locations.push(loc);
      if (f.evidence && !grp.evidences.includes(f.evidence)) grp.evidences.push(f.evidence);
    }

    for (const { finding, locations, evidences } of grouped.values()) {
      lines.push(`### [${finding.severity.toUpperCase()}] ${finding.name}`);
      lines.push("");
      lines.push(`- **Confidence**: ${finding.confidence}`);
      lines.push(`- **Affected URLs (${locations.length})**: ${locations.slice(0, 15).map((l) => `\`${l}\``).join(", ")}${locations.length > 15 ? ` (+${locations.length - 15} more)` : ""}`);
      if (evidences.length > 0) {
        lines.push(`- **Evidence**: \`${evidences.slice(0, 5).join(" | ")}\``);
      }
      if (finding.description) {
        lines.push(`- **Description**: ${finding.description}`);
      }
      if (finding.remediation) {
        lines.push(`- **Remediation**: ${finding.remediation}`);
      }
      lines.push("");
    }
  }

  if (data.endpoints.length > 0) {
    lines.push("## Observed Endpoints");
    lines.push("");
    lines.push("| Host | Method | Path | Status | MIME |");
    lines.push("|---|---|---|---:|---|");
    for (const ep of data.endpoints.slice(0, 200)) {
      lines.push(`| ${ep.host} | ${ep.method} | \`${ep.path}\` | ${ep.status ?? "-"} | ${ep.mime || "-"} |`);
    }
    if (data.endpoints.length > 200) {
      lines.push(`\n_Truncated to 200 of ${data.endpoints.length} endpoints._`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

export const REPORT_TOOLS = [
  {
    name: "report_export",
    description:
      "Generate a structured defensive audit report (Markdown or JSON) aggregating observed hosts, endpoints, detected technologies, and security findings with remediation guidance. Optionally save directly to disk.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Optional hostname filter (e.g. 'example.com'). Omit to include all observed hosts.",
        },
        format: {
          type: "string",
          enum: ["markdown", "json"],
          default: "markdown",
          description: "Output report format (default: markdown).",
        },
        include_endpoints: {
          type: "boolean",
          default: true,
          description: "Include observed endpoints table/list in the report (default: true).",
        },
        output_path: {
          type: "string",
          description: "Optional file path where the generated report should be written.",
        },
      },
      required: [],
    },
    handler: async (
      args: {
        host?: string;
        format?: "markdown" | "json";
        include_endpoints?: boolean;
        output_path?: string;
      },
      burpClient?: BurpClient
    ) => {
      const client = burpClient ?? getBurpClient();
      const format = args.format ?? "markdown";
      const includeEndpoints = args.include_endpoints !== false;

      const [burpInfo, sitemapData, findingsData] = await Promise.all([
        client.withRestFallback(
          () => client.get<Record<string, unknown>>("/v0.1/burp/version"),
          () => ({ edition: "Burp Suite Community Edition", version: "local-fallback", bridge: false })
        ),
        fetchSiteMapEntries(client, args.host),
        collectFindings(client, args.host),
      ]);

      const hostsSet = new Set<string>();
      const endpointMap = new Map<
        string,
        { host: string; method: string; path: string; status: number | null; mime: string }
      >();

      for (const entry of sitemapData.entries) {
        const h = entry.host ?? "unknown";
        if (args.host && !h.toLowerCase().includes(args.host.toLowerCase())) continue;
        hostsSet.add(h);
        const method = (entry.request?.method ?? "GET").toUpperCase();
        const p = entry.path ?? "/";
        const key = `${h}:${method}:${p}`;
        if (!endpointMap.has(key)) {
          endpointMap.set(key, {
            host: h,
            method,
            path: p,
            status: entry.responseCode ?? entry.response?.statusCode ?? null,
            mime: entry.mimeType ?? entry.response?.mimeType ?? "",
          });
        }
      }

      const sortedFindings = [...findingsData.findings].sort(
        (a, b) => severityRank(a.severity) - severityRank(b.severity)
      );

      const severityCounts: Record<string, number> = {
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      for (const f of sortedFindings) {
        const k = f.severity.toLowerCase() === "information" ? "info" : f.severity.toLowerCase();
        severityCounts[k] = (severityCounts[k] ?? 0) + 1;
      }

      const technologies = detectTechnologies(sitemapData.entries);
      const endpoints = includeEndpoints ? Array.from(endpointMap.values()) : [];

      const reportData = {
        generated_at: new Date().toISOString(),
        burp_info: burpInfo,
        host_filter: args.host ?? null,
        sitemap_mode: sitemapData.mode,
        findings_mode: findingsData.mode,
        hosts: Array.from(hostsSet),
        technologies,
        severity_counts: severityCounts,
        findings: sortedFindings,
        endpoints,
      };

      const content =
        format === "json"
          ? JSON.stringify(reportData, null, 2)
          : renderMarkdownReport(reportData);

      let savedPath: string | undefined;
      if (args.output_path) {
        savedPath = path.resolve(args.output_path);
        fs.mkdirSync(path.dirname(savedPath), { recursive: true });
        fs.writeFileSync(savedPath, content, "utf8");
      }

      return {
        format,
        ...(savedPath ? { output_path: savedPath, bytes_written: Buffer.byteLength(content, "utf8") } : {}),
        summary: {
          hosts: reportData.hosts.length,
          endpoints: endpointMap.size,
          findings: sortedFindings.length,
          severity_counts: severityCounts,
        },
        report: format === "json" ? reportData : content,
      };
    },
  },
];
