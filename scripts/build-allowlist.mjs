#!/usr/bin/env node
/**
 * Build the bundled allowlist of popular registrable domains for the
 * extension's background service worker.
 *
 * Source: Tranco — academic top-list aggregating Cisco Umbrella, Majestic,
 * Chrome UX, and Cloudflare Radar. Updated daily, redistributable.
 *
 * Output: extension/src/background/allowlistData.json
 *   JSON array of N lowercase registrable domains, sorted by Tranco rank.
 *
 * Usage:
 *   npm run build:allowlist                # default top 10000
 *   ALLOWLIST_SIZE=5000 npm run build:allowlist
 *
 * Strategy: download the zipped CSV to a tempfile, extract with the system
 * `unzip -p` (preinstalled on macOS, Linux, and Git-Bash for Windows), slice
 * to ALLOWLIST_SIZE rows, write JSON. Avoids adding a runtime zip dependency.
 */

import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const SOURCE_URL = process.env.TRANCO_URL ?? "https://tranco-list.eu/top-1m.csv.zip";
const TARGET_SIZE = Number(process.env.ALLOWLIST_SIZE ?? 10_000);

const here = path.dirname(fileURLToPath(import.meta.url));
const outPath = path.resolve(
  here,
  "..",
  "shared",
  "src",
  "data",
  "trancoTop10k.generated.ts"
);

async function main() {
  if (!Number.isFinite(TARGET_SIZE) || TARGET_SIZE <= 0 || TARGET_SIZE > 1_000_000) {
    throw new Error(`Invalid ALLOWLIST_SIZE: ${TARGET_SIZE}`);
  }

  console.log(`[allowlist] downloading ${SOURCE_URL}`);
  const response = await fetch(SOURCE_URL, {
    headers: { "user-agent": "capstone-domain-guardian/0.1 (allowlist builder)" }
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching Tranco zip`);
  }
  const zipBuffer = Buffer.from(await response.arrayBuffer());
  console.log(`[allowlist] downloaded ${(zipBuffer.length / 1024 / 1024).toFixed(1)} MB`);

  const tempDir = await mkdtemp(path.join(tmpdir(), "tranco-"));
  const zipPath = path.join(tempDir, "top-1m.csv.zip");
  await writeFile(zipPath, zipBuffer);

  try {
    // Stream `unzip -p <zipfile>` line-by-line and stop reading once we have
    // enough rows — avoids buffering the entire ~30 MB extracted CSV.
    const domains = await streamTrancoCsv(zipPath, TARGET_SIZE);

    if (domains.length < TARGET_SIZE) {
      console.warn(
        `[allowlist] only got ${domains.length} domains (wanted ${TARGET_SIZE}); proceeding anyway`
      );
    }

    const banner = [
      "// Auto-generated from the Tranco top-1m list (https://tranco-list.eu/).",
      "// DO NOT EDIT BY HAND — regenerate with `npm run build:allowlist`.",
      `// Generated: ${new Date().toISOString()}`,
      `// Entries: ${domains.length} registrable domains ranked by Tranco aggregate score.`,
      "// License: Tranco multi-source (Cisco Umbrella + Majestic + Chrome UX + Cloudflare Radar) — redistribution permitted.",
      ""
    ].join("\n");
    const body = `${banner}export const TRANCO_DOMAINS_RAW: readonly string[] = ${JSON.stringify(domains)};\n`;
    await writeFile(outPath, body, "utf8");
    console.log(`[allowlist] wrote ${domains.length} domains → ${outPath}`);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function streamTrancoCsv(zipPath, targetSize) {
  return new Promise((resolve, reject) => {
    const child = spawn("unzip", ["-p", zipPath], { stdio: ["ignore", "pipe", "pipe"] });
    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    const domains = [];
    const seen = new Set();
    let done = false;

    const stopReading = () => {
      if (done) return;
      done = true;
      rl.close();
      child.stdout.destroy();
      try {
        child.kill("SIGTERM");
      } catch {
        // best-effort
      }
      resolve(domains);
    };

    rl.on("line", (line) => {
      if (done) return;
      const trimmed = line.trim();
      if (!trimmed) return;
      const parts = trimmed.split(",");
      const domain = parts[1]?.toLowerCase();
      if (!domain || seen.has(domain)) return;
      seen.add(domain);
      domains.push(domain);
      if (domains.length >= targetSize) stopReading();
    });

    rl.on("close", () => {
      if (!done) {
        done = true;
        resolve(domains);
      }
    });

    child.on("error", (err) => {
      if (!done) {
        done = true;
        reject(err);
      }
    });

    child.stderr.on("data", (chunk) => {
      // Don't fail on stderr — `unzip` may warn after we SIGTERM it.
      process.stderr.write(chunk);
    });
  });
}

main().catch((err) => {
  console.error("[allowlist] failed:", err.message);
  process.exit(1);
});
