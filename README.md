# Capstone Domain Guardian

A Chrome (Manifest V3) extension and AWS-backed API that detect lookalike / phishing domains. It works two ways: paste a link for an on-demand verdict, **and** optional always-on protection that quietly checks pages as you browse and shows a full-page warning before a flagged site loads.

## What it does

- **Simplified popup** — paste a link (or use the current tab) and get a clear, colour-coded verdict (Safe → Likely phishing) with three plain-English reasons and quick actions.
- **Expert mode** — a toggle that reveals the full analyst breakdown: 0–100 threat score, evidence panel, eight risk categories (~70 fields), reporting contacts, and JSON export.
- **Real-time warning** — a background service worker watches navigation and redirects to a Safe-Browsing-style interstitial when a site scores High or above. Includes "Go back" and a two-click "Continue anyway" session bypass.
- **Universal brand detection** — identifies the impersonated brand for any domain in the bundled catalog **or** the Tranco top-10k, and flags keyword-stuffing lookalikes such as `payment-sheridancollege.ca → Sheridan College`.
- **Reporting guidance** — country-aware CSIRT/registrar/brand abuse contacts and an exportable analyst report.

## Repository layout

- `extension/` — React MV3 extension: popup, options page, full-page warning, and the background service worker.
- `api/` — Node 22 TypeScript backend: Lambda handlers, CDK stack, the scoring engine, brand resolver, provider connectors, and Bedrock prompt orchestration.
- `shared/` — Zod schemas, URL/lexical helpers, the Tranco list, and the Unicode confusables map used by both sides.
- `tests/` — Vitest unit + integration tests.

## Endpoints

- `POST /analyze` — full analysis; returns the structured `AnalysisResult`.
- `POST /analyze/fast` — sub-second lexical + reputation pass used by the real-time guard (`partial: true`).
- `POST /generate-lookalikes` — DNSTwister-sourced lookalike candidates (Expert mode).
- `GET /health` — service + per-provider readiness.

## Scoring

Deterministic, evidence-driven weighted score across lexical (24%), content (19%), infrastructure (18%), reputation (18%), behavioural (7%), email-auth (5%), ML composite (5%), and passive-history (4%) categories, mapped to a six-level verdict. **Verdict floors** guarantee a minimum score for authoritative signals — a Google Safe Browsing hit floors to Malicious, an OpenPhish/PhishTank hit to Critical, and a confident keyword-stuffing/homoglyph lookalike to High — so confirmed phishing can't land in "Low". The LLM (AWS Bedrock) supplies the human-readable explanation only; it never overrides the verdict.

## Quick start (local)

```bash
npm install
cp .env.example .env          # optional: add provider keys (see below)
npm run build                 # builds shared → api → extension
npm run start:api             # local API on http://127.0.0.1:3000  (terminal 1)
```

Load the extension: `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select `extension/dist`. Reload the extension after any rebuild.

> The built extension defaults to the deployed production API, so a teammate can `npm install && npm run build` and load `extension/dist` with **no configuration**. For local dev, set `VITE_API_BASE_URL=http://127.0.0.1:3000` at build time, or override the endpoint at runtime from the extension's options page.

Run the test suite: `npm test`. Type-check everything: `npm run typecheck`.

## API keys

Detection degrades gracefully without keys (unconfigured providers report `not_configured`). For full coverage set:

- `VT_API_KEY` — VirusTotal (free 500/day)
- `ABUSEIPDB_API_KEY` — AbuseIPDB (free 1,000/day)
- `GOOGLE_SAFE_BROWSING_API_KEY` — Google Safe Browsing (free 10,000/day)
- `BEDROCK_MODEL_ID` — e.g. `us.amazon.nova-lite-v1:0`, with `BEDROCK_REGION=us-east-1`

Keyless sources used out of the box: DNSTwister, RDAP, DNS, TLS, ipwho.is, crt.sh, Internet Archive, OpenPhish, PhishTank.

Locally these go in `.env`; in production they live in AWS Secrets Manager (written by the CDK deploy). Never commit secrets — `.env` is gitignored.

## Deployment

The full production runbook (CDK bootstrap, deploy, provider keys, Bedrock region/model, extension build, verification, and the data-residency note) is in **[DEPLOY.md](DEPLOY.md)**.

Short version:
```bash
export APP_STAGE=prod APP_AWS_REGION=ca-central-1
export BEDROCK_REGION=us-east-1 BEDROCK_MODEL_ID="us.amazon.nova-lite-v1:0"
export VT_API_KEY=… ABUSEIPDB_API_KEY=… GOOGLE_SAFE_BROWSING_API_KEY=…
npm run build:shared && npm run build:api
npm --workspace @capstone/api exec -- cdk deploy CapstoneDomainGuardianStack-prod --require-approval never
```
The stack provisions four Lambdas (analyze, analyze-fast, generate-lookalikes, health), an API Gateway REST API, a DynamoDB cache, a Secrets Manager secret, CloudWatch alarms/logs, and a 5-minute warmer that keeps the analysis Lambdas hot. Then rebuild the extension against the printed `ApiBaseUrl`.

## Regenerating bundled data

```bash
npm run build:allowlist     # refresh the Tranco top-10k list
npm run build:confusables   # refresh the Unicode confusables map
```

## Notes

- Deterministic evidence drives every score; the LLM only narrates and never changes the verdict.
- The backend returns partial-but-valid results when enrichment sources fail; readiness is exposed via `GET /health`.
- Real-time protection requires `tabs`/`webNavigation`/`<all_urls>`; it ships enabled and can be turned off from the popup or the options page.
- Keep all provider secrets server-side — the extension never embeds credentials.
