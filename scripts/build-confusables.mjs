#!/usr/bin/env node
/**
 * Build the bundled Unicode confusables map used by the lexical homoglyph
 * detector in shared/src/utils.ts.
 *
 * Source: Unicode UTR #39 confusables.txt (authoritative). Format:
 *
 *     <source codepoint(s)> ; <target codepoint(s)> ; <type>     # comment
 *
 * Output: shared/src/data/confusables.generated.ts
 *   export const CONFUSABLES_MAP: Record<string, readonly string[]>
 *   Keyed by lowercase ASCII a–z, mapping to an array of non-ASCII
 *   single-codepoint characters that visually resemble that letter.
 *
 * Filters applied:
 *   - Single-codepoint source only (skip "ce" → "œ" style multi-char).
 *   - Single-codepoint target only (skip multi-char skeletons).
 *   - Target must be ASCII A–Z or a–z (we lowercase it).
 *   - Source restricted to the Basic Multilingual Plane (≤ U+FFFF) so the
 *     glyph reliably renders in the browser address bar.
 *   - Source must not itself be ASCII a–z; we want non-ASCII confusables,
 *     plus a handful of curated ASCII↔ASCII swaps (`0↔o`, `1↔l/i`, `5↔s`,
 *     `$↔s`) provided as a separate hand-curated list in utils.ts.
 *   - Source must be a printable character (excludes control / formatting).
 */

import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_URL =
  process.env.CONFUSABLES_URL ??
  "https://www.unicode.org/Public/security/latest/confusables.txt";

const here = path.dirname(fileURLToPath(import.meta.url));
const outPath = path.resolve(
  here,
  "..",
  "shared",
  "src",
  "data",
  "confusables.generated.ts"
);

const ASCII_A_LOWER = "a".charCodeAt(0);
const ASCII_Z_LOWER = "z".charCodeAt(0);
const ASCII_A_UPPER = "A".charCodeAt(0);
const ASCII_Z_UPPER = "Z".charCodeAt(0);

function isAsciiLetter(codepoint) {
  return (
    (codepoint >= ASCII_A_LOWER && codepoint <= ASCII_Z_LOWER) ||
    (codepoint >= ASCII_A_UPPER && codepoint <= ASCII_Z_UPPER)
  );
}

function parseHexCodepoints(field) {
  return field
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((hex) => parseInt(hex, 16));
}

function isPrintable(codepoint) {
  // Reject control chars + format chars (Cf) where we can detect them.
  // Simple heuristic: must be > U+0020 and not in C0/C1 controls.
  if (codepoint <= 0x20) return false;
  if (codepoint >= 0x7f && codepoint <= 0xa0) return false;
  // BMP only — surrogates outside BMP rendered inconsistently in URL bars.
  if (codepoint > 0xffff) return false;
  return true;
}

async function main() {
  console.log(`[confusables] downloading ${SOURCE_URL}`);
  const response = await fetch(SOURCE_URL, {
    headers: {
      "user-agent": "capstone-domain-guardian/0.1 (confusables builder)"
    }
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching confusables.txt`);
  }
  const text = await response.text();
  console.log(
    `[confusables] downloaded ${(text.length / 1024).toFixed(1)} KB`
  );

  const byTarget = new Map();
  for (const letter of "abcdefghijklmnopqrstuvwxyz") byTarget.set(letter, new Set());

  let totalLines = 0;
  let dataLines = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    totalLines++;
    if (!rawLine || rawLine.startsWith("#")) continue;
    // Strip inline comment.
    const codePart = rawLine.split("#")[0];
    const fields = codePart.split(";");
    if (fields.length < 2) continue;

    const sourceCodepoints = parseHexCodepoints(fields[0]);
    const targetCodepoints = parseHexCodepoints(fields[1]);
    if (sourceCodepoints.length !== 1) continue;
    if (targetCodepoints.length !== 1) continue;
    dataLines++;

    const sourceCp = sourceCodepoints[0];
    const targetCp = targetCodepoints[0];
    if (!isAsciiLetter(targetCp)) continue;
    if (isAsciiLetter(sourceCp)) continue; // ASCII swaps handled separately
    if (!isPrintable(sourceCp)) continue;

    const targetLetter = String.fromCodePoint(targetCp).toLowerCase();
    const sourceChar = String.fromCodePoint(sourceCp);
    byTarget.get(targetLetter).add(sourceChar);
  }

  const records = {};
  let totalSources = 0;
  for (const letter of "abcdefghijklmnopqrstuvwxyz") {
    const variants = Array.from(byTarget.get(letter)).sort();
    records[letter] = variants;
    totalSources += variants.length;
  }

  const json = JSON.stringify(records, null, 2);
  const banner = [
    "// Auto-generated from Unicode UTR #39 confusables.txt.",
    "// DO NOT EDIT BY HAND — regenerate with `npm run build:confusables`.",
    "// Source: https://www.unicode.org/Public/security/latest/confusables.txt",
    "// License: Unicode-DFS-2016 (redistribution permitted).",
    `// Generated: ${new Date().toISOString()}`,
    `// Total mappings: ${totalSources} non-ASCII codepoints → 26 ASCII targets.`,
    ""
  ].join("\n");

  const body =
    `${banner}export const CONFUSABLES_MAP: Record<string, readonly string[]> = ${json};\n`;

  await writeFile(outPath, body, "utf8");
  console.log(
    `[confusables] parsed ${dataLines} data rows from ${totalLines} lines`
  );
  console.log(
    `[confusables] wrote ${totalSources} ASCII-target mappings → ${outPath}`
  );
}

main().catch((err) => {
  console.error("[confusables] failed:", err.message);
  process.exit(1);
});
