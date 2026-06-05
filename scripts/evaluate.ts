// CLI: measure the lookalike-detection core against the labeled corpus and
// print a precision/recall report. Run with:  npm run eval
//
// This reports the OFFLINE detector only (lexical + brand + structure + ML);
// reputation-feed/GSB/VirusTotal floors are evaluated against the live API and
// are intentionally not part of this reproducible, network-free benchmark.

import { runEvaluation } from "../api/src/eval/evaluate.js";

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const bar = "─".repeat(64);

async function main() {
  const m = await runEvaluation();

  console.log(`\n${bar}`);
  console.log("  Lookalike-Detection Evaluation — offline core (no network)");
  console.log(`  ${m.total} labeled domains | flagged = verdict ≥ High`);
  console.log(bar);

  console.log("\n  Headline metrics");
  console.log(`    Precision        ${pct(m.precision)}   (of flagged domains, how many were truly phishing)`);
  console.log(`    Recall           ${pct(m.recall)}   (of phishing domains, how many we caught)`);
  console.log(`    F1               ${pct(m.f1)}`);
  console.log(`    Accuracy         ${pct(m.accuracy)}`);
  console.log(`    False-positive   ${pct(m.falsePositiveRate)}   (legit domains wrongly flagged — lower is better)`);
  console.log(`    Specificity      ${pct(m.specificity)}`);

  console.log("\n  Confusion matrix");
  console.log("                       predicted PHISH    predicted LEGIT");
  console.log(`    actual PHISH            TP ${String(m.truePositive).padStart(3)}            FN ${String(m.falseNegative).padStart(3)}`);
  console.log(`    actual LEGIT            FP ${String(m.falsePositive).padStart(3)}            TN ${String(m.trueNegative).padStart(3)}`);

  console.log("\n  Accuracy by group");
  for (const [group, g] of Object.entries(m.byGroup).sort()) {
    const acc = g.total === 0 ? 0 : g.correct / g.total;
    console.log(`    ${group.padEnd(16)} ${String(g.correct).padStart(2)}/${String(g.total).padEnd(2)}  ${pct(acc)}`);
  }

  console.log("\n  Verdict distribution");
  for (const v of ["Safe", "Low", "Medium", "High", "Critical", "Malicious"]) {
    const count = m.verdictHistogram[v] ?? 0;
    if (count > 0) console.log(`    ${v.padEnd(10)} ${"█".repeat(count)} ${count}`);
  }

  if (m.misses.length > 0) {
    console.log(`\n  Misses (${m.misses.length}) — findings worth discussing, not hidden`);
    console.log(`    ${"domain".padEnd(34)} ${"label".padEnd(6)} ${"verdict".padEnd(9)} score  brand`);
    for (const r of m.misses) {
      const kind = r.label === "phish" ? "FN" : "FP";
      console.log(
        `    ${kind} ${r.url.replace("https://", "").padEnd(31)} ${r.label.padEnd(6)} ${r.verdict.padEnd(9)} ${String(r.score).padStart(3)}    ${r.brand}`
      );
    }
  } else {
    console.log("\n  No misses on this corpus.");
  }

  console.log(`\n${bar}\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
