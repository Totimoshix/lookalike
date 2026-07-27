// Live-API evaluation: runs the labelled corpus against the DEPLOYED endpoint
// with every external provider enabled, complementing the offline harness in
// api/src/eval/. The offline harness suppresses network evidence for
// reproducibility, so it cannot exercise the reputation-driven verdict floors
// or produce the upper verdict bands. This script does.
//
// It is deliberately NOT part of CI: it makes ~63 network calls, consumes
// third-party provider quota, and its results vary with live feed contents.
//
//   BASE=https://<api>/prod npx tsx scripts/evaluate-live.ts
//
// Concurrency is held low because the VirusTotal free tier permits only four
// requests per minute; rate-limited providers degrade to a reported diagnostic
// rather than failing the request, which this script records.

import { writeFileSync } from "node:fs";
import { EVAL_CORPUS, type EvalEntry } from "../api/src/eval/corpus.js";

const BASE = process.env.BASE ?? "https://x7g9yk2qm5.execute-api.ca-central-1.amazonaws.com/prod";
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 2);
const OUT = process.env.OUT ?? "/tmp/live-eval-results.json";

type Row = {
  url: string;
  label: string;
  group: string;
  verdict: string | null;
  score: number | null;
  brand: string | null;
  method: string | null;
  confidence: number | null;
  reputational: Record<string, unknown> | null;
  timings: Record<string, unknown> | null;
  providerStatus: Record<string, string>;
  flagged: boolean;
  correct: boolean;
  wallMs: number;
  error: string | null;
};

const FLAGGING = new Set(["High", "Critical", "Malicious"]);

async function analyze(entry: EvalEntry): Promise<Row> {
  const startedAt = Date.now();
  const base: Row = {
    url: entry.url,
    label: entry.label,
    group: entry.group,
    verdict: null,
    score: null,
    brand: null,
    method: null,
    confidence: null,
    reputational: null,
    timings: null,
    providerStatus: {},
    flagged: false,
    correct: false,
    wallMs: 0,
    error: null
  };

  try {
    const response = await fetch(`${BASE}/analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: entry.url, mode: "manual_entry" }),
      signal: AbortSignal.timeout(35_000)
    });
    const wallMs = Date.now() - startedAt;
    if (!response.ok) {
      return { ...base, wallMs, error: `HTTP ${response.status}` };
    }
    const body = (await response.json()) as any;
    const verdict = String(body.verdict);
    const flagged = FLAGGING.has(verdict);
    const providerStatus: Record<string, string> = {};
    for (const source of body.signal_sources ?? []) {
      providerStatus[String(source.source)] = String(source.status);
    }
    return {
      ...base,
      verdict,
      score: Number(body.threat_score),
      brand: body.brand_match?.brand_name ?? null,
      method: body.brand_match?.method ?? null,
      confidence: body.brand_match?.confidence ?? null,
      reputational: body.risk_factors?.reputational ?? null,
      timings: body.timings ?? null,
      providerStatus,
      flagged,
      correct: entry.label === "phish" ? flagged : !flagged,
      wallMs
    };
  } catch (error) {
    return {
      ...base,
      wallMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "unknown error"
    };
  }
}

async function pool<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await fn(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, rank))];
}

async function main() {
  console.error(`Live evaluation against ${BASE} (concurrency ${CONCURRENCY}, ${EVAL_CORPUS.length} domains)`);
  let done = 0;
  const rows = await pool(EVAL_CORPUS, CONCURRENCY, async (entry) => {
    const row = await analyze(entry);
    done += 1;
    console.error(
      `[${String(done).padStart(2)}/${EVAL_CORPUS.length}] ${row.url.replace("https://", "").padEnd(34)} ` +
        `${(row.verdict ?? row.error ?? "?").padEnd(10)} ${String(row.score ?? "-").padStart(3)}  ${row.wallMs}ms`
    );
    return row;
  });

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const byGroup: Record<string, { total: number; correct: number; scores: number[] }> = {};
  const verdicts: Record<string, number> = {};
  const errors: Row[] = [];

  for (const row of rows) {
    if (row.error) {
      errors.push(row);
      continue;
    }
    if (row.label === "phish") {
      if (row.flagged) tp += 1;
      else fn += 1;
    } else if (row.flagged) {
      fp += 1;
    } else {
      tn += 1;
    }
    byGroup[row.group] ??= { total: 0, correct: 0, scores: [] };
    byGroup[row.group].total++;
    if (row.correct) byGroup[row.group].correct++;
    if (row.score !== null) byGroup[row.group].scores.push(row.score);
    verdicts[row.verdict!] = (verdicts[row.verdict!] ?? 0) + 1;
  }

  const ratio = (n: number, d: number) => (d === 0 ? 1 : Number((n / d).toFixed(4)));
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const scored = rows.filter((r) => !r.error);
  const wall = scored.map((r) => r.wallMs);
  const totals = scored.map((r) => Number((r.timings as any)?.total_ms)).filter((n) => Number.isFinite(n));

  const summary = {
    base: BASE,
    corpusSize: EVAL_CORPUS.length,
    completed: scored.length,
    failed: errors.length,
    confusion: { tp, fp, tn, fn },
    precision,
    recall,
    f1: precision + recall === 0 ? 0 : Number(((2 * precision * recall) / (precision + recall)).toFixed(4)),
    accuracy: ratio(tp + tn, scored.length),
    falsePositiveRate: ratio(fp, fp + tn),
    specificity: ratio(tn, tn + fp),
    verdictDistribution: verdicts,
    byGroup: Object.fromEntries(
      Object.entries(byGroup).map(([group, g]) => [
        group,
        {
          total: g.total,
          correct: g.correct,
          accuracy: ratio(g.correct, g.total),
          scoreMin: Math.min(...g.scores),
          scoreMax: Math.max(...g.scores)
        }
      ])
    ),
    latencyMs: {
      wallMedian: percentile(wall, 50),
      wallP95: percentile(wall, 95),
      wallMin: Math.min(...wall),
      wallMax: Math.max(...wall),
      serverTotalMedian: percentile(totals, 50),
      serverTotalP95: percentile(totals, 95)
    },
    misses: scored.filter((r) => !r.correct).map((r) => ({ url: r.url, label: r.label, verdict: r.verdict, score: r.score, brand: r.brand })),
    errors: errors.map((r) => ({ url: r.url, error: r.error }))
  };

  writeFileSync(OUT, JSON.stringify({ summary, rows }, null, 2));
  console.error("\n=== SUMMARY ===");
  console.error(JSON.stringify(summary, null, 2));
  console.error(`\nFull per-domain results written to ${OUT}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
