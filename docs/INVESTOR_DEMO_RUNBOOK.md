# OpsAegis — Investor / Design-Partner Demo Runbook

**Target duration:** 8–12 minutes.
**Environment:** Local disposable lab or separately authorized staging only.
**Data:** Synthetic events and test identities unless a reviewed evidence reference explicitly authorizes a sanitized staging demonstration.

## Safety rules

- Do not use production customer data in an investor demo.
- Do not expose environment files, credentials, tokens, private keys, raw provider payloads or internal infrastructure identifiers.
- Do not enable Nuclei or Shannon just to make the dashboard look active.
- Do not register, invoke or demonstrate Wazuh isolation/unisolation. Those actions remain disabled and unregistered.
- Do not present seeded or synthetic data as live telemetry.
- Do not restart, stop or modify shared services during a demo without an approved change window.
- If an integration is unavailable, show the truthful unavailable/unknown state rather than manufacturing a green status.

## Pre-demo checklist

- [ ] Confirm the exact Git commit and dashboard build being demonstrated.
- [ ] Confirm local/staging environment is disposable or explicitly authorized.
- [ ] Confirm the API, database, Redis, frontend and required workers are healthy.
- [ ] Confirm integration health states match actual configured endpoints.
- [ ] Confirm test accounts have only the roles needed for the walkthrough.
- [ ] Confirm the dataset contains no customer or sensitive operational data.
- [ ] Confirm report window start/end timestamps are in UTC.
- [ ] Confirm no scanner or response action is enabled.
- [ ] Prepare a fallback screen recording only from a previously validated build; label its date and commit.

## Walkthrough

### 1. Product framing — 1 minute

Explain that OpsAegis coordinates existing security tools and preserves the path from source evidence to analyst decision. It is not positioned as an autonomous containment engine.

### 2. Integration and collection status — 1 minute

Open Overview / Integrations. Explain the difference between a configured endpoint, a successful health check, a successful collection, and evidence of complete ingestion.

A green health indicator is not proof that an event was ingested.

### 3. Detection and incident workflow — 2 minutes

Using an approved synthetic lab event, show the source-linked finding, deterministic detection correlation, linked incident, status history, audit records and analyst ownership.

Do not quote a live detection count or timing unless the exact result has a reviewed evidence reference.

### 4. Investigation workspace — 2 minutes

Show provenance-labelled timeline entries, analyst notes, evidence attachment metadata, access restrictions and digest-verified download behavior.

Use harmless synthetic text/PDF/PNG evidence. Explain that SHA-256 integrity checks are not a signed immutable chain of custody.

### 5. Playbooks and approvals — 2 minutes

Show the versioned investigation playbook catalogue and its action contract. Run a bounded dry-run preview against the synthetic incident. Create an approval request and, using a separate operator account, approve or reject it.

State explicitly: preview is read-only; the requester cannot approve their own request; an approval decision does not dispatch or execute an external action; Wazuh isolation remains disabled and unregistered.

### 6. Operational reporting — 1–2 minutes

Choose a defined UTC window. Show source freshness/coverage, failure/truncation caveats and lifecycle metrics. Export JSON or CSV and reconcile it to the same synthetic dataset or reviewed evidence.

If the window has no records, show the empty state. Do not populate it with fabricated metrics.

### 7. Close — 1 minute

Summarize the pilot question: can OpsAegis reduce manual context assembly while improving traceability and governance in the customer's authorized environment?

Invite feedback on workflow fit, integrations, deployment model and success measures.

## Demo evidence record

After the demo, retain a restricted record containing date/time in UTC and operator; exact Git commit and build identifier; environment alias (not a hostname/IP); synthetic or staging dataset designation; screens/workflows exercised; any unavailable integration or failed step; exported report window and sanitized artifact reference; and follow-up issue/action.

Do not commit raw logs, evidence files, incident content or credentials.

## Stop conditions

Stop the demo and switch to explanation if a service is unhealthy or reports an unknown state; the dataset contains unexpected sensitive information; an approval or action appears capable of dispatching an external command; an evidence attachment fails its integrity check; a report shows truncation or unexplained source gaps; or the environment is not the authorized disposable environment.

## After the demo

- Record feedback as hypotheses and requests, not as customer commitments.
- Open issues only for reproducible defects or agreed follow-up work.
- Update the investor deck only with reviewed screenshots and evidence.
