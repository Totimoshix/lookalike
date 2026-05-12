# Phase 2 Project Plan

## 1. Purpose

Phase 2 will move the Capstone Domain Guardian add-on from a functional proof of concept into a more complete analyst tool. The goal is not to replace the current workflows, but to close the most visible implementation gaps in detection quality, provider coverage, infrastructure maturity, reporting output, and UI clarity.

This phase is based on the current codebase, including:

- `/Users/jmeic/Documents/Capstone PoC/api/src/services/reputation.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/services/domainIntelligence.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/services/historySignals.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/services/contentAnalysis.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/services/scoring.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/services/reportingContacts.ts`
- `/Users/jmeic/Documents/Capstone PoC/api/src/infra/capstone-stack.ts`
- `/Users/jmeic/Documents/Capstone PoC/extension/src/components/AnalyzeView.tsx`
- `/Users/jmeic/Documents/Capstone PoC/extension/src/components/EvidencePanel.tsx`
- `/Users/jmeic/Documents/Capstone PoC/extension/src/components/LookalikeView.tsx`

## 2. Current State Summary

The current version already supports the core Phase 1 workflow:

- manual URL/domain analysis
- brand override
- deterministic scoring
- analyst-facing evidence display
- JSON export
- DNSTwister-based lookalike generation
- AWS-oriented backend structure

However, several important parts are still partial, heuristic, or operationally immature. Phase 2 should focus on turning those weak points into complete, testable workstreams.

## 3. Major Gaps Identified

### Technical Gaps

- Some external intelligence providers are implemented but depend on local configuration and still produce degraded results when keys or endpoints are missing.
- Infrastructure signals still contain partial or null fields such as `dns_history_changes`, `ip_reputation_score`, and `redirect_count`.
- Content analysis is still mostly heuristic and does not yet provide strong phishing-template or visual-similarity evidence.
- Scoring weights are hand-tuned and not yet calibrated against a formal labeled sample set.
- The test suite covers important units, but not the full analyst workflow end to end.

### Infrastructure Gaps

- The AWS stack is synth-ready, but there is still no full deployment and release workflow for dev/stage/prod.
- Secrets handling, provider readiness, operational dashboards, and alerting need to be hardened for actual use.
- CDK deprecations remain in the infrastructure code and should be cleaned up before a stable release.

### Design Gaps

- The UI shows the data, but not always in the best hierarchy for triage.
- Evidence, diagnostics, and degraded-provider conditions are surfaced, but the difference between "domain risk" and "tooling gap" is still not as clear as it should be.
- Lookalike-generation results are usable, but not yet optimized for analyst review and batch follow-up.

### Reporting Gaps

- Reporting contacts are present, but coverage is still limited.
- There is no structured analyst report output beyond raw JSON.
- There is no takedown/reporting workflow by audience such as registrar, brand, CERT/CSIRT, or internal security team.

## 4. Phase 2 Objectives

Phase 2 should deliver four concrete outcomes:

1. Improve detection depth and evidence quality.
2. Harden the backend and deployment model for stable use.
3. Make the extension easier to use for analyst triage and reporting.
4. Produce reporting outputs that are actionable outside the application.

## 5. Workstream A: Technical Improvements

### A1. Reputation and Threat-Intel Services

Phase 2 will complete and harden the provider layer.

Planned work:

- harden VirusTotal, AbuseIPDB, Google Safe Browsing, PhishTank, and OpenPhish integrations
- make provider behavior predictable under timeouts, bad payloads, rate limits, and upstream outages
- improve provider-specific diagnostics so analysts can see whether a result is valid, degraded, or unavailable
- normalize feed and lookup results into a cleaner common reputation model

Key outcome:

- no reputation signal should appear as a vague placeholder
- every surfaced signal must map to a real provider result, a real failure state, or a deliberate unsupported state

### A2. Infrastructure Intelligence Expansion

The infrastructure evidence layer in `domainIntelligence.ts` is still incomplete.

Planned work:

- implement redirect-chain counting and final-destination classification
- replace `ip_reputation_score: null` with a real IP/host risk model
- expand DNS history signals beyond the current certificate/archive approximation
- improve registrar and RDAP parsing so ownership and registration metadata are more reliable
- strengthen hosting and ASN classification
- add clearer differentiation between unresolved domains, dead domains, parked domains, and live phishing pages

Key outcome:

- infrastructure evidence becomes a dependable scoring input rather than a partial supplement

### A3. Content and Behavioral Detection

The current page analysis in `contentAnalysis.ts` is useful, but still lightweight.

Planned work:

- improve normalized visible-text similarity against matched-brand content
- strengthen favicon, logo, and asset-host reuse detection
- classify form actions more precisely, including exfiltration risk and relay behavior
- expand redirect behavior analysis and suspicious destination classification
- improve detection of phishing page structure and common credential-harvest patterns
- evaluate a visual-similarity layer for screenshots, layout, or favicon hashing if feasible within Phase 2 scope

Key outcome:

- analysts should be able to justify why a page looks suspicious using stronger page evidence, not just domain similarity

### A4. Brand Matching and Scoring Calibration

Brand matching is significantly better than earlier builds, but it still depends on catalog coverage and heuristics.

Planned work:

- expand brand catalog coverage for common consumer, education, finance, retail, cloud, and SaaS targets
- improve typo and confusable-character handling
- keep deterministic brand matching as the default path and limit LLM use to ambiguous cases
- tune weighted scoring using a labeled sample set of benign domains, legitimate brand domains, typosquats, parked domains, and phishing samples
- review false positives and false negatives from the current scoring model

Key outcome:

- scores become more defensible and more consistent across real-world samples

### A5. Testing and Validation

The current test set is a good start, but not sufficient for a stronger release.

Planned work:

- expand integration tests for `/analyze`, not only `/generate-lookalikes`
- add provider fixture tests for successful, degraded, and failed upstream responses
- add UI tests for analyst workflows and degraded-provider messaging
- build a regression corpus for known benign and malicious samples
- define pass/fail acceptance thresholds for match quality and scoring stability

Key outcome:

- Phase 2 features will be measurable, repeatable, and safer to release

## 6. Workstream B: Infrastructure and Operations

### B1. AWS Environment Maturity

The backend is structured for AWS deployment, but operational maturity is not finished.

Planned work:

- formalize dev, test, and prod deployment environments in `ca-central-1`
- finalize Secrets Manager or SSM-based provider configuration
- clean up CDK deprecations in the current stack
- confirm DynamoDB cache retention and lifecycle behavior
- expand CloudWatch alarms, dashboards, and log retention policies
- validate API Gateway throttling and abuse protection for external-facing use

Key outcome:

- the service can be deployed and operated without depending on local developer setup

### B2. Release and Packaging Workflow

The project already has install scripts, but distribution still needs a cleaner operational path.

Planned work:

- define a repeatable release process for the backend and Chrome extension
- package the extension against the deployed API rather than a local-only address
- document environment setup, provider onboarding, and release validation steps
- produce smoke-test scripts for deploy verification

Key outcome:

- other users can install, start, and validate the project with less manual intervention

### B3. Operational Diagnostics

The health endpoint already exposes provider readiness, but this should be expanded into an operational support model.

Planned work:

- make `/health` a true operational readiness endpoint
- add deeper provider diagnostics for configuration, last-success behavior, and failure types
- add internal troubleshooting guidance for common field failures such as DNS failure, TLS failure, or provider timeout

Key outcome:

- operational issues are easier to distinguish from real threat findings

## 7. Workstream C: Design and Analyst Experience

### C1. Triage-Oriented UI Improvements

The current extension renders the data, but the hierarchy can be improved.

Planned work:

- separate high-confidence findings from degraded-provider warnings more clearly
- improve prioritization and grouping of evidence
- make analyst-relevant findings easier to scan at a glance
- improve empty, error, timeout, and degraded-result states
- tighten the layout for repeated use inside the extension popup

Key outcome:

- analysts can identify the core risk quickly without reading every category card

### C2. Lookalike Review Workflow

The DNSTwister workflow works, but it is still basic from an analyst-review perspective.

Planned work:

- improve candidate ranking and display for batch review
- add better analyst summaries for top lookalike candidates
- improve bulk follow-up workflow for analyzing or exporting generated candidates

Key outcome:

- lookalike generation becomes a usable investigation tool, not just a candidate list

### C3. Design Consistency

The extension has been styled to match the Figma direction, but more design cleanup is still needed.

Planned work:

- tighten spacing, responsiveness, and popup-specific rendering behavior
- ensure all states match the intended visual design
- align typography, card hierarchy, and status semantics across all analyst views

Key outcome:

- the interface looks intentional and behaves consistently across analyst tasks

## 8. Workstream D: Reporting and External Use

### D1. Reporting Contact Coverage

The current `reportingContacts.ts` logic provides a foundation but is still narrow.

Planned work:

- expand registrar abuse contacts and portals
- expand brand contact coverage where public security contacts exist
- improve default authority routing for Canadian and broader reporting use cases
- reduce dependency on LLM-generated reporting notes for core reporting information

Key outcome:

- report targets become more accurate and useful in practice

### D2. Structured Analyst Reports

JSON export is useful for machine consumption, but not enough for analyst reporting.

Planned work:

- define a human-readable report format
- add an analyst summary section that can be shared with instructors, supervisors, or investigators
- include evidence snapshots, provider results, and risk explanation in a cleaner exported structure
- support report views tailored to different audiences

Possible report outputs:

- analyst case summary
- registrar takedown summary
- brand impersonation report
- internal security review brief

Key outcome:

- the add-on becomes useful beyond the popup itself

### D3. Reporting Workflow by Audience

Not every report target needs the same information.

Planned work:

- define what should be included for registrars, brands, CERT/CSIRT contacts, and internal teams
- map each report type to the right evidence and escalation path
- ensure the UI and exports support those report paths directly

Key outcome:

- reporting becomes structured, repeatable, and aligned to the recipient

## 9. Proposed Milestone Plan

### Milestone 1: Backend Signal Completion

Focus:

- provider hardening
- infrastructure intelligence completion
- passive-history and redirect improvements
- provider diagnostics cleanup

Primary output:

- a more complete and reliable backend evidence model

### Milestone 2: Detection Quality and Scoring

Focus:

- content-analysis improvements
- stronger phishing-template detection
- brand-matching expansion
- score calibration against sample data

Primary output:

- stronger signal quality and a more defensible threat score

### Milestone 3: Analyst UX and Reporting

Focus:

- triage-oriented UI cleanup
- lookalike-review improvements
- structured report output
- reporting contact and escalation improvements

Primary output:

- a more usable analyst workflow inside and outside the extension

### Milestone 4: Deployment, Validation, and Release

Focus:

- AWS environment maturity
- operational dashboards and alarms
- release packaging
- broader test coverage and smoke validation

Primary output:

- a stable Phase 2 release candidate

## 10. Phase 2 Deliverables

By the end of Phase 2, the project should deliver:

- a hardened analyst backend with stronger provider and infrastructure coverage
- improved phishing-content and lookalike evidence quality
- calibrated scoring with a documented validation set
- a cleaner triage-focused extension UI
- structured reporting outputs beyond raw JSON
- a more mature AWS deployment and release process
- expanded testing across backend, UI, and provider-failure scenarios

## 11. Glaringly Obvious Features Still Missing

These are the most obvious items still not fully implemented in the current build:

- true redirect-count and destination-risk analysis
- a real IP reputation score in the infrastructure model
- deeper passive DNS and ownership-history intelligence
- stronger visual similarity or phishing-template detection
- a human-readable exported analyst report
- broader registrar and brand reporting coverage
- end-to-end UI automation for the extension
- a fully documented production deployment and release workflow
- calibrated scoring based on a maintained sample corpus

## 12. Recommended Delivery Sequence

The most efficient Phase 2 order is:

1. Complete provider hardening and infrastructure intelligence.
2. Upgrade content analysis and scoring calibration.
3. Improve reporting outputs and contact coverage.
4. Polish analyst UI and lookalike review workflows.
5. Finalize AWS deployment, release workflow, and expanded testing.

This order keeps the underlying evidence model stable before significant UI and reporting refinement.

## 13. Definition of Done for Phase 2

Phase 2 should be considered complete when:

- all surfaced signals are backed by real logic or an explicit supported failure state
- degraded provider conditions are clearly distinguishable from actual domain risk
- infrastructure and content evidence are strong enough to support analyst conclusions
- the extension supports clear triage and reporting workflows
- exported reporting is useful to someone outside the application
- the backend can be deployed and validated without relying on a local-only setup
- the project has test coverage for both normal and degraded operating conditions
