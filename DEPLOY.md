# Deploy & Run — Capstone Domain Guardian

Two parts: the **API** (AWS Lambda + API Gateway + DynamoDB, via CDK) and the
**extension** (Chrome MV3, built with Vite and pointed at the API).

---

## Provider keys

The analyzer runs with no keys (degraded), but four providers need credentials
for full coverage:

| Key | Provider | Free tier | Where |
|---|---|---|---|
| `VT_API_KEY` | VirusTotal | 500/day | virustotal.com → My API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1,000/day | abuseipdb.com → Account → API |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing | 10,000/day | GCP Console → enable Safe Browsing API → create key |
| `BEDROCK_MODEL_ID` | AWS Bedrock (LLM) | per-token | see Bedrock note below |

Everything else (DNSTwister, RDAP, crt.sh, Internet Archive, OpenPhish,
PhishTank, DNS, TLS, ipwho.is) is keyless.

### Bedrock note (important)

Amazon Nova Lite is **not available in `ca-central-1`**. The LLM step must
target a US region with the cross-region inference profile:

- `BEDROCK_REGION=us-east-1`
- `BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0`

The stack and data storage stay in `ca-central-1`; only the LLM call routes to
`us-east-1`. (Data-residency tradeoff: the analyzed URL + risk factors transit
a US region for that one call. To keep everything in Canada, choose a model
offered in `ca-central-1` — e.g. a Claude model — and set `BEDROCK_REGION`
and `BEDROCK_MODEL_ID` accordingly.)

**Auth:**
- **Local dev** authenticates Bedrock with a bearer API key via the
  `AWS_BEARER_TOKEN_BEDROCK` env var (in `.env`).
- **Prod** authenticates via the Lambda execution role — the stack grants
  `bedrock:InvokeModel` to `AnalyzeFunction`. No bearer key ships into AWS.

---

## Local development

```bash
npm install
cp .env.example .env          # then fill in the four keys (see above)
npm run build:shared
npm run build:api

# terminal 1 — API on http://127.0.0.1:3000
npm run start:api

# terminal 2 — extension build
cd extension && NODE_ENV=production npx vite build
# Chrome → chrome://extensions → Developer mode → Load unpacked → extension/dist
```

`.env` Bedrock block for local dev:
```
BEDROCK_REGION=us-east-1
AWS_BEARER_TOKEN_BEDROCK=<your Bedrock API key>
BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0
```

Verify providers:
```bash
curl -s http://127.0.0.1:3000/health | jq '.providers[] | {provider, status}'
# all should be "ok"
```

---

## Production deploy (AWS)

### Prereqs (one-time)
- AWS CLI v2 installed and configured (`aws configure`) with permissions for
  Lambda, API Gateway, DynamoDB, Secrets Manager, IAM, CloudWatch.
- CDK bootstrap in the target account/region:
  ```bash
  npx --workspace @capstone/api cdk bootstrap aws://<ACCOUNT_ID>/ca-central-1
  ```
- Bedrock model access for Amazon Nova Lite enabled in **us-east-1**
  (AWS Console → switch to N. Virginia → Bedrock → Model access).

### Deploy
```bash
export APP_STAGE=prod
export APP_AWS_REGION=ca-central-1          # stack + data in Canada
export BEDROCK_REGION=us-east-1             # LLM call only
export BEDROCK_MODEL_ID="us.amazon.nova-lite-v1:0"
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export GOOGLE_SAFE_BROWSING_API_KEY="..."

npm run build:shared && npm run build:api
npm --workspace @capstone/api exec -- cdk deploy CapstoneDomainGuardianStack-prod --require-approval never
```

The deploy writes the four provider values into a Secrets Manager secret
(`capstone/prod/provider-config`). Rotate keys later by editing that secret —
no redeploy needed. Note: prod uses the Lambda IAM role for Bedrock, so
`AWS_BEARER_TOKEN_BEDROCK` is **not** needed at deploy time.

Save the **`ApiBaseUrl`** output.

### Verify the deployed API
```bash
BASE="https://<id>.execute-api.ca-central-1.amazonaws.com/prod"
curl -s "$BASE/health" | jq '.providers[] | {provider, status}'
curl -s -X POST "$BASE/analyze" -H "content-type: application/json" \
  -d '{"url":"https://amaz0n-login-support.com","mode":"manual_entry"}' \
  | jq '{verdict, score: .threat_score, brand: .brand_match.brand_name, llm_ms: .timings.llm_ms}'
# non-null llm_ms = Bedrock working in prod
```

### Point the extension at prod
```bash
cd extension
export VITE_API_BASE_URL="https://<id>.execute-api.ca-central-1.amazonaws.com/prod"
NODE_ENV=production npx vite build
# reload extension/dist in chrome://extensions
```

---

## Stack contents

- Lambdas: `AnalyzeFunction` (1024 MB/30 s, has Bedrock grant),
  `AnalyzeFastFunction` (512 MB/5 s), `GenerateLookalikesFunction` (512 MB/15 s),
  `HealthFunction` (256 MB/10 s)
- API Gateway: `GET /health`, `POST /analyze`, `POST /analyze/fast`,
  `POST /generate-lookalikes`
- DynamoDB analysis cache (TTL), Secrets Manager provider config, CloudWatch
  alarms + access logs
- Stack name: `CapstoneDomainGuardianStack-<stage>`

---

## Regenerating bundled data

```bash
npm run build:allowlist     # refresh Tranco top-10k (shared/src/data)
npm run build:confusables   # refresh Unicode confusables map
```

---

## Security

- Never commit `.env` (gitignored). Provider keys live in `.env` locally and in
  Secrets Manager in prod — never in source.
- Restrict the Google Safe Browsing key to that API in the GCP console.
- Rotate any key that has been shared in plaintext.
