# Domain Guardian

Domain Guardian is a free, open source Chrome extension that locates websites designed to impersonate real brands, and detects if they are malicious- before you enter any personal information they may be trying to steal.

Every year, losses from phishing grow at an alarming rate. In 2025, there were an estimated $215.8 million in losses to victims, up 208% from 2024. These websites copy the look of banks, government services, delivery companies, universities, and many more legitimate brands that trick users into believing they are on a legitimate website. In 2025 alone, there were 1.5 million domains used in phishing attacks- a 38% increase from the year prior. Existing tools are not enough to protect users from this specific subset of phishing attacks fuelled by domain lookalikes. Tools like Google Safe Browsing can only flag a domain after it has been reported, while tools like DNSTwister can only provide lists of potential lookalikes without determining if they are malicious. By then, the damage has already been done.

---

## What Problem Domain Guardian Solves

When cybercriminals register lookalike domains such as `paypa1.com` or `rbc-etransfer.com`, these domains are invisible to most security tools for the first days of existence. They have no history or reputation that signals malicious intent until they are reported. Users who visit during this window are completely unprotected.

Domain Guardian closes this gap by analysing how a domain looks, not whether it has been reported before. It checks for character substitutions, suspicious keywords, recent registration dates, and attributes from the content of the domain itself, like credential harvesting forms, among many other signals to produce an instant verdict with no dependence on prior reporting.

---

## Who Is It For

Domain Guardian offers two experiences: an expert mode and a standard mode covering:

- **Everyday users** who want a simple second opinion before clicking a suspicious link.
- **Small businesses and organisations** without the resources to access expensive enterprise security tools.
- **Security analysts** who need a structured breakdown of a suspicious domain and guidance on who to report it to.

---

## What It Does

### Instant Threat Analysis
Paste any URL to get a fast verdict determining if a website is safe or malicious, along with either a simple explanation or the details of a full analysis.

The score is deterministic. Every point comes from a specific piece of evidence across 8 signal categories. An AI model interprets the analysis and provides an easy-to-understand explanation. It never affects or changes the score.

### Lookalike Domain Generator
Already know a legitimate domain you want to protect? Enter it and Domain Guardian generates a list of potential lookalikes an attacker may register, then scores each one so you can see which are most similar and potentially dangerous.

### Brand Impersonation Detection
Domain Guardian recognises when a domain is pretending to be a legitimate brand, covering major banks, payment services, government agencies, streaming platforms, delivery companies, educational institutions, and more. It uses three methods to identify the original brand: a curated catalog, a database of the 10,000 most popular websites globally, and LLM inference.

### Real-Time Navigation Guard
Toggle on live mode and Domain Guardian checks every website you navigate to. If it detects a high-risk site, a full-page warning appears before the website loads- giving you the chance to go back before any damage is done.

### Analyst Reporting
For security professionals, Domain Guardian generates a complete analyst report showing all the evidence behind a verdict, the registrar's abuse contact, the impersonated brand's own security contact, and the correct national cybersecurity authority to report to, all within a single report exportable to JSON and HTML, which can be printed to PDF.

---

## How It Works

1. **Checks the name of the domain**  
   It looks for character substitutions (like `1` instead of `l`), suspicious keywords, and similarity to known brands.

2. **Checks the domain's registration history**  
   If a domain was registered very recently without any prior presence, it can indicate the domain is suspicious.

3. **Checks the content of the page**  
   It looks for fake login forms, external form submissions, and any elements that indicate malicious activity.

4. **Checks external intelligence sources**  
   It queries multiple sources for reputation, presence on blacklists, web archive history, and other indicators.

5. **Produces a threat score from 0 to 100**  
   The score is mapped to 6 levels: Safe, Low, Medium, High, Critical, and Malicious.

6. **Assembles a report**  
   A complete analyst report with detailed evidence and reporting contacts, ready to export.

---

## Getting Started

**Requirements:** Node.js 18+, Google Chrome

```bash
# 1. Install dependencies
npm install

# 2. Build the project
npm run build

# 3. Start the local API
npm run start:api
```

Then load the extension in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/dist` folder

The extension is now ready to use.

---

## Optional: Improving Detection With Free API Keys

Domain Guardian works out of the box without any API keys. Adding the following free keys enables additional intelligence sources and improves accuracy:

| Provider | Free tier | What it adds |
|---|---|---|
| VirusTotal | 500 checks/day | Cross-references 70+ antivirus engines |
| AbuseIPDB | 1,000 checks/day | IP reputation and abuse history |
| Google Safe Browsing | 10,000 checks/day | Google's phishing and malware blocklist |

Add these to a `.env` file in the project root:

```
VT_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
```

---

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

---

## Regenerating Bundled Data

```bash
npm run build:allowlist     # refresh the Tranco top-10k list
npm run build:confusables   # refresh the Unicode confusables map
```

---

## Running Tests

```bash
npm test                # full test suite
npm run eval            # detection accuracy benchmark (precision, recall, F1)
npm run typecheck       # TypeScript type checking
```

The detection accuracy benchmark runs against a hand-labeled dataset of 70 domains and measures precision, recall, and false-positive rate without requiring any API keys or internet access.

---

## Project Structure

```
extension/    Chrome extension: popup, options, warning page, background worker
api/          Backend API: analysis pipeline, scoring engine, AWS infrastructure
shared/       Shared types, schemas, brand data, and detection utilities
tests/        Unit, integration, and accuracy evaluation tests
```

---

## Detection Accuracy

Measured against a 70-domain hand-labeled test set:

| Metric | Result |
|---|---|
| Precision | 1.00 |
| Recall | 0.94 |
| Accuracy | 0.96 |
| False positive rate | 0.00 |

Zero false positives across all legitimate domain groups, canonical domains like `sheridancollege.ca` and `paypal.com` are never incorrectly flagged.

---

## Built By

Group 7 - Jamal Meic, Lily Fulcher, Nathanael Churcher & Damian Ogorek  
INFO49402 Capstone Project - Sheridan College, 2026

GitHub: [github.com/Totimoshix/lookalike](https://github.com/Totimoshix/lookalike)
