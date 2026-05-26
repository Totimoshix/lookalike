import type { AnalysisResult, EvidenceSummary } from "@capstone/shared";
import { headlineForVerdict, toPlainBullet } from "./plainLanguage";

type EvidenceItem = EvidenceSummary["evidence_items"][number];

const SEVERITY_ORDER: Record<EvidenceItem["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityStyle(sev: EvidenceItem["severity"]): string {
  switch (sev) {
    case "critical": return "background:#fee2e2;color:#991b1b;";
    case "high":     return "background:#ffedd5;color:#9a3412;";
    case "medium":   return "background:#dbeafe;color:#1d4ed8;";
    case "low":      return "background:#dcfce7;color:#166534;";
    default:         return "background:#f1f1f1;color:#555;";
  }
}

function verdictStyle(verdict: AnalysisResult["verdict"]): string {
  switch (verdict) {
    case "Safe":
    case "Low":       return "color:#166534;";
    case "Medium":    return "color:#9a3412;";
    case "High":      return "color:#9a3412;";
    case "Critical":
    case "Malicious": return "color:#991b1b;";
    default:          return "color:#555;";
  }
}

function scoreBarColor(score: number): string {
  if (score >= 75) return "#dc2626";
  if (score >= 50) return "#f97316";
  if (score >= 25) return "#eab308";
  return "#22c55e";
}

function esc(value: string | null | undefined): string {
  if (!value) return "";
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function val(value: string | null | undefined, fallback = "—"): string {
  return esc(value) || fallback;
}

function statusDot(status: string): string {
  const color =
    status === "ok"             ? "#22c55e" :
    status === "not_configured" ? "#aaa"    :
    status === "query_failed"   ? "#dc2626" : "#f97316";
  return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${color};margin-right:5px;vertical-align:middle;"></span>`;
}

function kv(label: string, value: string | null | undefined): string {
  if (!value) return "";
  return `
    <tr>
      <td style="padding:4px 12px 4px 0;color:#666;font-size:12px;white-space:nowrap;vertical-align:top;">${esc(label)}</td>
      <td style="padding:4px 0;font-size:12px;color:#111;word-break:break-all;">${esc(value)}</td>
    </tr>`;
}

export function generateAnalystReportHtml(result: AnalysisResult): string {
  const genDate = new Date(result.export_metadata.generated_at).toLocaleString();
  const score = result.threat_score;
  const barColor = scoreBarColor(score);
  const contacts = result.reporting_contacts;
  const auth = contacts.local_authorities;

  const sortedEvidence = [...result.evidence_summary.evidence_items].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  const evidenceRows = sortedEvidence.map(item => {
    const plain = toPlainBullet(item, result);
    const note = item.note && item.note !== plain
      ? `<div style="font-size:11px;color:#666;margin-top:2px;">${esc(item.note)}</div>`
      : "";
    return `
      <tr style="border-bottom:1px solid #f0f0f0;">
        <td style="padding:8px 10px 8px 0;vertical-align:top;white-space:nowrap;">
          <span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:3px;${severityStyle(item.severity)}">
            ${item.severity.toUpperCase()}
          </span>
        </td>
        <td style="padding:8px 10px 8px 0;vertical-align:top;width:100%;">
          <div style="font-size:12px;font-weight:500;color:#111;">${esc(plain)}</div>
          ${note}
        </td>
        <td style="padding:8px 0;vertical-align:top;text-align:right;white-space:nowrap;">
          <span style="font-size:10px;color:#aaa;">${esc(item.category)}</span>
        </td>
      </tr>`;
  }).join("");

  const diagnosticRows = result.evidence_summary.signal_diagnostics.map(d => `
    <tr style="border-bottom:1px solid #f8f8f8;">
      <td style="padding:5px 12px 5px 0;font-size:12px;color:#111;">${statusDot(d.status)}${esc(d.provider)}</td>
      <td style="padding:5px 0;font-size:11px;color:#666;">${esc(d.signal)}</td>
      <td style="padding:5px 0;font-size:11px;text-align:right;color:${
        d.status === "ok" ? "#166534" : d.status === "query_failed" ? "#991b1b" : "#999"
      };">${esc(d.status.replace("_", " "))}</td>
    </tr>`
  ).join("");

  const notesHtml = contacts.notes.length > 0
    ? `<ul style="margin:10px 0 0;padding-left:18px;">
        ${contacts.notes.map(n => `<li style="font-size:12px;color:#444;margin-bottom:4px;">${esc(n)}</li>`).join("")}
       </ul>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Threat Report — ${esc(result.normalized_domain)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: "Helvetica Neue", Arial, sans-serif;
      font-size: 13px;
      color: #111;
      background: #fff;
      max-width: 820px;
      margin: 0 auto;
      padding: 0;
    }

    .page-header {
      background: #0f0f0f;
      color: #fff;
      padding: 18px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .page-header h1 { font-size: 15px; font-weight: 600; }
    .page-header .meta { font-size: 11px; color: #aaa; text-align: right; }

    .content { padding: 28px 32px; }

    /* Verdict hero */
    .verdict-hero {
      display: flex;
      align-items: flex-start;
      gap: 20px;
      padding: 20px;
      border: 1px solid #e8e8e8;
      border-radius: 8px;
      margin-bottom: 24px;
      background: #fafafa;
    }
    .verdict-score {
      text-align: center;
      min-width: 72px;
    }
    .verdict-score .number {
      font-size: 42px;
      font-weight: 700;
      line-height: 1;
    }
    .verdict-score .out-of { font-size: 12px; color: #999; }
    .score-bar {
      height: 4px;
      border-radius: 2px;
      background: #eee;
      margin-top: 6px;
      overflow: hidden;
    }
    .score-bar-fill { height: 100%; border-radius: 2px; }
    .verdict-body { flex: 1; }
    .verdict-label { font-size: 20px; font-weight: 700; }
    .verdict-headline { font-size: 13px; color: #555; margin-top: 2px; }
    .verdict-reasoning {
      margin-top: 10px;
      font-size: 12px;
      line-height: 1.7;
      color: #333;
      padding: 10px 12px;
      background: #fff;
      border: 1px solid #e8e8e8;
      border-radius: 6px;
    }

    /* Sections */
    .section { margin-bottom: 28px; }
    .section-heading {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: #888;
      padding: 5px 8px;
      background: #f5f5f5;
      border-radius: 4px;
      margin-bottom: 12px;
    }

    /* Contact cards */
    .contact-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
    }
    .contact-card {
      border: 1px solid #e8e8e8;
      border-radius: 6px;
      padding: 12px;
    }
    .contact-card-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      color: #aaa;
      margin-bottom: 6px;
    }
    .contact-name { font-size: 12px; font-weight: 600; color: #111; margin-bottom: 6px; }
    .contact-row { font-size: 11px; color: #555; margin-top: 3px; word-break: break-all; }
    .contact-row strong { color: #888; font-weight: 500; }

    /* Footer */
    .page-footer {
      border-top: 1px solid #e8e8e8;
      padding: 14px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 10px;
      color: #bbb;
    }

    /* Print */
    @media print {
      body { max-width: 100%; }
      .page-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .verdict-hero { break-inside: avoid; }
      .section { break-inside: avoid; }
      .contact-grid { break-inside: avoid; }
      tr { break-inside: avoid; }
      .print-hint { display: none; }
    }
  </style>
</head>
<body>

  <header class="page-header">
    <h1>Domain Threat Analysis Report</h1>
    <div class="meta">
      <div>Capstone Domain Guardian</div>
      <div>${esc(genDate)}</div>
    </div>
  </header>

  <div class="content">

    <!-- Verdict hero -->
    <div class="verdict-hero">
      <div class="verdict-score">
        <div class="number" style="${verdictStyle(result.verdict)}">${score}</div>
        <div class="out-of">/ 100</div>
        <div class="score-bar">
          <div class="score-bar-fill" style="width:${score}%;background:${barColor};"></div>
        </div>
      </div>
      <div class="verdict-body">
        <div class="verdict-label" style="${verdictStyle(result.verdict)}">${esc(result.verdict)}</div>
        <div class="verdict-headline">${esc(headlineForVerdict(result.verdict))}</div>
        ${result.reasoning
          ? `<div class="verdict-reasoning">${esc(result.reasoning)}</div>`
          : ""}
      </div>
    </div>

    <!-- Subject -->
    <div class="section">
      <div class="section-heading">Subject</div>
      <table style="border-collapse:collapse;width:100%;">
        ${kv("Analyzed domain",    result.normalized_domain)}
        ${kv("Analyzed URL",       result.normalized_url)}
        ${kv("Target brand",       result.brand_match.brand_name !== "Unknown" ? result.brand_match.brand_name : null)}
        ${kv("Brand confidence",   result.brand_match.brand_name !== "Unknown"
            ? `${Math.round(result.brand_match.confidence * 100)}% (${result.brand_match.method})`
            : null)}
        ${kv("Registrar",          result.risk_factors.infrastructure.registrar)}
        ${kv("Registrant country", result.risk_factors.infrastructure.registrant_country)}
        ${kv("Domain age",         result.risk_factors.infrastructure.domain_age_days !== null
            ? `${result.risk_factors.infrastructure.domain_age_days} days`
            : null)}
        ${kv("Analysis mode",      result.mode)}
      </table>
    </div>

    <!-- Key evidence -->
    <div class="section">
      <div class="section-heading">Key evidence</div>
      ${sortedEvidence.length === 0
        ? `<p style="font-size:12px;color:#aaa;font-style:italic;">No evidence items triggered.</p>`
        : `<table style="border-collapse:collapse;width:100%;">${evidenceRows}</table>`}
    </div>

    <!-- Reporting contacts -->
    <div class="section">
      <div class="section-heading">Reporting contacts</div>
      <div class="contact-grid">

        <div class="contact-card">
          <div class="contact-card-label">Registrar abuse</div>
          <div class="contact-name">${val(contacts.registrar_information.registrar_name, "Unknown registrar")}</div>
          <div class="contact-row"><strong>Email: </strong>${val(contacts.registrar_information.abuse_contact)}</div>
          <div class="contact-row"><strong>Portal: </strong>${val(contacts.registrar_information.abuse_portal)}</div>
        </div>

        <div class="contact-card">
          <div class="contact-card-label">Brand / APWG</div>
          <div class="contact-name">${
            result.brand_match.brand_name !== "Unknown"
              ? esc(result.brand_match.brand_name)
              : "No brand matched"
          }</div>
          <div class="contact-row"><strong>Brand: </strong>${val(contacts.brand_protection.brand_contact)}</div>
          <div class="contact-row"><strong>APWG: </strong>${val(contacts.brand_protection.apwg_contact)}</div>
          <div class="contact-row"><strong>GSB report: </strong>${val(contacts.brand_protection.google_safe_browsing_report)}</div>
        </div>

        <div class="contact-card">
          <div class="contact-card-label">CERT / CSIRT</div>
          <div class="contact-name">${val(auth.csirt_name, "Global (APWG)")}</div>
          <div class="contact-row"><strong>Country: </strong>${val(auth.csirt_country)}</div>
          <div class="contact-row"><strong>Email: </strong>${val(auth.csirt)}</div>
          <div class="contact-row"><strong>Portal: </strong>${val(auth.csirt_portal)}</div>
        </div>

      </div>
      ${notesHtml}
    </div>

    <!-- Signal coverage -->
    <div class="section">
      <div class="section-heading">Signal coverage</div>
      <table style="border-collapse:collapse;width:100%;">
        <thead>
          <tr style="border-bottom:1px solid #e8e8e8;">
            <th style="text-align:left;font-size:11px;color:#888;font-weight:500;padding:4px 12px 4px 0;">Provider</th>
            <th style="text-align:left;font-size:11px;color:#888;font-weight:500;padding:4px 12px 4px 0;">Signal</th>
            <th style="text-align:right;font-size:11px;color:#888;font-weight:500;padding:4px 0;">Status</th>
          </tr>
        </thead>
        <tbody>${diagnosticRows}</tbody>
      </table>
    </div>

  </div>

  <footer class="page-footer">
    <span>Capstone Domain Guardian · ${esc(result.export_metadata.schema_version)}</span>
    <span class="print-hint" style="color:#bbb;font-size:10px;">To save as PDF: File → Print → Save as PDF</span>
    <span>${esc(genDate)}</span>
  </footer>

</body>
</html>`;
}
