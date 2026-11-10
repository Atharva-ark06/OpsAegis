# OpsAegis — Investor Brief

**Document status:** Product narrative for discussion; not a financial forecast, offer, or claim of commercial traction.
**Repository checkpoint:** 10 November 2026.
**Evidence rule:** Only capabilities present in the repository are described as implemented. Live deployment, customer adoption, revenue, market size and performance remain unverified unless separately evidenced.

## 1. Executive summary

OpsAegis is a security operations and incident-governance platform designed to bring security telemetry, findings, investigations and controlled response workflows into one auditable workspace.

It provides a common control plane around security tools rather than attempting to replace every underlying engine. The platform normalizes supported source records, correlates persisted findings, links detections to incidents, preserves investigation context and exposes bounded operational reporting. Its response-orchestration design is human-governed: approval records, dry-run previews and execution ledgers are implemented, while provider-side response execution remains disabled.

## 2. Problem being addressed

Security teams commonly work across separate consoles and disconnected processes for endpoint and SIEM telemetry, threat decisions and vulnerability findings, alert triage and incident ownership, evidence collection and investigation notes, and approval, audit and operational reporting.

This fragmentation can make it harder to preserve provenance, repeat investigations consistently and explain what happened during an incident. These are the product problems OpsAegis is designed to address. Their frequency, financial impact and willingness-to-pay must be validated through customer discovery and pilots.

## 3. Product approach

OpsAegis acts as an integration and workflow layer:

1. **Collect:** bounded, read-only integration paths bring supported records into the platform.
2. **Normalize:** source identity and evidence provenance are retained; repeated records are deduplicated.
3. **Correlate:** deterministic rules evaluate persisted findings and link related activity.
4. **Investigate:** analysts work from an incident timeline with notes and controlled evidence attachments.
5. **Govern:** playbook previews and independent approval records provide a human decision trail.
6. **Measure:** operational reports summarize collection coverage, freshness, failures and incident workflow timing from persisted records.

The platform does not invent alerts or fill missing telemetry with synthetic metrics.

## 4. Current product capabilities

| Area | Repository implementation |
|---|---|
| Application | FastAPI API, React/TypeScript dashboard, PostgreSQL, Redis and Alembic migrations |
| Identity and access | JWT validation, database-backed roles, login throttling and audit logging |
| Integrations | Read-only Wazuh Indexer and Wazuh Manager paths; CrowdSec active decisions and optional bounded alert history; on-demand threat-intelligence adapters |
| Detection | Deterministic correlation over persisted findings, incident linkage and in-app notifications |
| Vulnerability workflow | Authorized-target registry and bounded Nuclei workflow; Shannon external-runner control-plane reference |
| Investigation | Incident timeline, analyst notes, provenance labels, redacted export and bounded binary evidence attachments |
| Governance | Versioned playbook catalogue, dry-run previews, independent approval requests/decisions and a fail-closed execution/compensation ledger |
| Reporting | UTC-windowed operational summary, JSON/CSV exports, trends and audited thresholds |
| Deployment foundation | Local and production-oriented Compose definitions, migrations, worker health checks, backup/restore scripts and CI smoke tests |

These are implementation statements, not claims that every external engine has been connected or validated in a live environment.

## 5. Architecture at a glance

    Wazuh / CrowdSec / approved enrichment sources
                        |
               bounded read-only adapters
                        |
           FastAPI integration and workflow API
                        |
             PostgreSQL  <-->  Redis
                |                 |
        findings / incidents   bounded workers
        audit / evidence       leases / queues
                |
       React / TypeScript authenticated dashboard
                |
       timelines · playbooks · approvals · reports

Nuclei and Shannon have separate execution boundaries and remain gated. The backend does not expose its Docker socket to the Shannon runner. External response actions are not enabled by the playbook catalogue or by an approval record.

## 6. Security and governance posture

The design emphasizes least-privilege integration credentials and backend-only secret handling; bounded requests, timeouts, result limits and collection windows; source provenance and idempotent ingestion; role-gated operations and audit records; independent approval for future high-impact actions; explicit disabled/unknown states rather than false success; and separate scanner/runner execution boundaries.

Known limitations are documented. Evidence attachments are content-sniffed and SHA-256 checked, but this is not a signed immutable chain of custody. Malware scanning, WORM storage and tenant isolation are not claimed.

## 7. Product maturity and evidence

| Maturity layer | Current position |
|---|---|
| Repository implementation | Core application and Phase 5 foundations and Phase 6.1–6.4 software increments are present on main; PR #96 completed the Playbooks and reporting dashboard workflows |
| Automated verification | PR #95 and PR #96 CI/security workflows passed, including backend tests/migrations, frontend tests/build, production Compose smoke test, PowerShell syntax, dependency audit and full-history secret scan |
| Local integration | Must be verified against the operator's local Wazuh lab and OpsAegis stack; agent enrollment alone does not prove OpsAegis ingestion |
| Staging acceptance | Pending real ingestion, worker recovery, evidence-volume restore, reporting validation and independent review |
| Production deployment | Not claimed; TLS termination, host/cloud policy, secret management, monitoring and off-host recovery remain deployment responsibilities |
| Commercial validation | No customer, revenue, retention, conversion or ROI figures are asserted in this brief |

The Phase 5 and Phase 6 evidence registers are deliberately not marked complete by CI results.

## 8. Initial customer and use-case hypotheses

Potential discovery segments—not validated customers or a confirmed market—include small and mid-sized organizations building a formal security operations function, managed security service providers coordinating multiple security tools, lean SOC teams that need repeatable investigations and governance, and security consultancies running authorized assessments and documenting outcomes.

The strongest initial use case to test is an analyst workflow that turns supported security events into traceable findings, correlated detections, incidents and a reviewable investigation record.

## 9. Pilot proposal

A pilot should begin with one organization-owned, disposable or explicitly authorized environment.

1. Discovery: identify the team's existing tools, alert-handling process, permissions and evidence-retention requirements.
2. Read-only connection: connect only approved sources with dedicated least-privilege accounts.
3. Workflow exercise: replay a small set of known test events and trace source → finding → detection → incident → notification.
4. Investigation exercise: add analyst notes and synthetic evidence attachments; verify access controls, integrity checks and restore behavior.
5. Governance exercise: preview a playbook and create/review an approval record without executing a provider action.
6. Measurement review: export a defined UTC report window and reconcile the results against independently recorded source data.

**Pilot success measures to agree before the pilot:** proportion of expected test events ingested and deduplicated; time from source event to persisted finding and correlated incident; analyst time spent assembling investigation context; percentage of incidents with complete provenance and evidence references; report reconciliation error and source freshness; and operator effort to deploy, recover and restore the platform.

No target values should be presented until a pilot baseline and measurement method are agreed.

## 10. Commercial questions to validate

Possible packaging hypotheses include a self-managed deployment for security teams and a managed offering for service providers. Pricing could be explored by protected environment, endpoint band, or analyst workspace, but no pricing model has been validated.

Customer discovery should test which workflow creates enough value to justify adoption, whether buyers prefer self-hosting or managed operations, required integrations and deployment models, security review/data residency/retention requirements, and acceptable pricing metric and procurement cycle.

## 11. Discussion requested

OpsAegis is seeking feedback and potential collaboration around design partners with an authorized test environment, SOC practitioners willing to evaluate the analyst workflow, security architects to review integration and governance boundaries, deployment and evidence-retention guidance, and pilot sponsorship or infrastructure support after scope and success criteria are agreed.

No funding amount, valuation or commercial forecast is stated here; those require validated operating assumptions and a separate financial model.

## 12. Diligence and known limitations

Before a production or commercial commitment, reviewers should examine the Phase 5/6 staging evidence registers and outstanding acceptance gates; production deployment, TLS, host hardening and secret-manager configuration; PostgreSQL plus evidence-volume backup/restore and measured recovery objectives; external egress controls before enabling scanners; the separate Shannon runner boundary and its AGPL-3.0 licensing implications; evidence retention, malware scanning, immutable storage and tenant-isolation requirements; and independent review before any provider-side response adapter is proposed.

## Supporting repository documents

- [Project status](PROJECT_STATUS.md)
- [Phase 5 staging evidence](PHASE5_STAGING_EVIDENCE.md)
- [Phase 6 roadmap](PHASE6_ROADMAP.md)
- [Production deployment](PRODUCTION_DEPLOYMENT.md)
- [Security baseline](SECURITY_BASELINE.md)
- [Demo runbook](INVESTOR_DEMO_RUNBOOK.md)
- [Pitch deck storyboard](INVESTOR_DECK_STORYBOARD.md)
- [Release readiness matrix](RELEASE_READINESS.md)
