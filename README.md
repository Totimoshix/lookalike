# Capstone Domain Guardian

Manual-entry Chrome extension and AWS-backed API for lookalike and phishing-domain analysis.

## Project Status
- Phase 1 core workflow is implemented.
- Phase 2 planning documents are included in the repository.
- Secrets are not stored in the repository. Use `.env` or AWS Secrets Manager for real provider credentials.

## What Is Included
- `extension/`: Chrome Manifest V3 React extension with manual URL analysis, brand override, JSON export, and lookalike generation.
- `api/`: AWS-oriented TypeScript backend with Lambda handlers, CDK stack, deterministic scoring, Bedrock prompt orchestration, optional enrichment connectors, and DNSTwister-backed lookalike retrieval.
- `shared/`: Shared Zod schemas and normalization helpers used by both the extension and the API.
- `tests/`: Unit and integration tests for normalization, lookalike generation, and scoring behavior.

## Core Workflows
- Manual analysis: submit a URL or domain to `/analyze` and receive a structured `AnalysisResultV2`.
- Lookalike generation: submit a legitimate domain to `/generate-lookalikes` and receive a versioned candidate set sourced from DNSTwister.
- JSON export: export the exact canonical analysis payload from the extension UI.

## Key Capabilities
- Brand inference with optional analyst override
- Deterministic weighted scoring across lexical, infrastructure, content, reputation, behavioral, and history signals
- Provider-readiness and signal-diagnostic reporting
- DNSTwister-based lookalike candidate retrieval
- AWS deployment support through CDK
- Cross-platform installer scripts for macOS, Linux, and Windows

## Architecture Notes
- Deterministic evidence drives the score. The LLM is used only for evidence-bound reasoning, reporting guidance formatting, and weak-confidence brand inference.
- The extension does not inspect the current tab and does not require content-script permissions.
- The backend is resilient to missing provider data and returns partial-but-valid results when enrichment sources fail.
- Provider readiness is exposed through `GET /health`, and per-signal diagnostics are returned in `AnalysisResultV2.evidence_summary.signal_diagnostics`.
- Passive/history evidence uses free or open sources: RDAP, crt.sh, Internet Archive CDX, OpenPhish, and PhishTank.

## Local Setup
1. Copy `.env.example` to `.env` and fill in any optional provider keys you plan to use.
2. Install dependencies with `npm install`.
3. Run `npm run build` to build all workspaces.
4. Run `npm run start:api` to start the local API on `http://127.0.0.1:3000`.
5. Load the unpacked extension from `extension/dist` in Chrome.
6. Run `npm run test` to execute the Vitest suite, or `npm run synth` to synthesize the AWS stack.

## One-Step Install
- macOS/Linux: run `./install.sh`
- Windows PowerShell: run `.\install.ps1`
- Windows double-click or Command Prompt: run `install.bat`
- The installer checks for Node.js/npm, creates `.env` from `.env.example` if needed, installs npm dependencies, and builds the project.

## Load In Chrome
1. Run `npm run build`.
2. Run `npm run start:api`.
3. Open `chrome://extensions`.
4. Enable `Developer mode`.
5. Click `Load unpacked`.
6. Select `extension/dist`.
7. Reload the extension after any rebuild so Chrome picks up updated host permissions and assets.

## Environment Variables
- `VITE_API_BASE_URL`: API base URL consumed by the extension.
- `APP_STAGE`: Deployment stage name, for example `dev` or `prod`.
- `APP_VERSION`: Application version surfaced by `/health`.
- `APP_AWS_REGION`: AWS deployment region for CDK. Defaults to `ca-central-1`.
- `PROVIDER_CONFIG_SECRET_NAME`: Optional Secrets Manager secret containing provider keys as JSON.
- `DNSTWISTER_API_BASE_URL`: Optional override for the DNSTwister API base URL. Defaults to `https://dnstwister.report/api`.
- `DNSTWISTER_TIMEOUT_MS`: Optional timeout for DNSTwister lookups in milliseconds. Defaults to `10000`.
- `BEDROCK_MODEL_ID`: Bedrock model or inference-profile identifier.
- `BEDROCK_REGION`: AWS region for Bedrock, default `ca-central-1`.
- `OPENPHISH_FEED_URL`: Optional override for the OpenPhish feed URL.
- `PHISHTANK_FEED_URL`: Optional override for the PhishTank feed URL.
- `PHISHTANK_CHECK_URL`: Optional override for the PhishTank direct URL check endpoint.
- `CRTSH_BASE_URL`: Optional override for crt.sh.
- `INTERNET_ARCHIVE_CDX_URL`: Optional override for the Internet Archive CDX API.
- `VT_API_KEY`: Optional VirusTotal API key.
- `ABUSEIPDB_API_KEY`: Optional AbuseIPDB API key.
- `GOOGLE_SAFE_BROWSING_API_KEY`: Optional Safe Browsing API key.

## Security Notes
- The current `keys.txt` file should not be used as a long-term credential store. Rotate any real values and move them into AWS Secrets Manager, SSM, or secure environment variables before deployment.
- Keep all provider secrets server-side. The extension should never embed Bedrock or threat-intel credentials.
- `keys.txt` is ignored by git and is not intended to be committed to GitHub.

## AWS 1.0 Deployment
1. Set `APP_STAGE=dev` or `APP_STAGE=prod`.
2. Export `CDK_DEFAULT_ACCOUNT` and set `APP_AWS_REGION=ca-central-1`.
3. Run `npm run synth` to verify the stack.
4. Deploy the generated stack with `npx cdk deploy CapstoneDomainGuardianStack-$APP_STAGE`.
5. Update `VITE_API_BASE_URL` with the deployed API URL and rebuild the extension.
6. Store provider keys in the generated Secrets Manager secret output by the stack, or provide them through environment variables for local development.
