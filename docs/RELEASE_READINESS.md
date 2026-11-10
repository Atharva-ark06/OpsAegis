# OpsAegis — Release Readiness and Phase Acceptance

**Checkpoint:** 10 November 2026.
**Purpose:** Separate repository implementation, automated verification, local integration, staging acceptance and production readiness.
**Rule:** Do not upgrade a status based on code presence, a mocked test, a green CI run or a successful health endpoint alone.

## Status definitions

| Status | Meaning |
|---|---|
| Implemented | Repository code or an operator procedure exists. |
| CI-tested | The relevant automated workflow completed successfully on the named commit. |
| Local-validated | The workflow was exercised against the named local services and recorded. |
| Staging-validated | The workflow was exercised against the authorized staging environment and independently reviewed evidence was recorded. |
| Production-validated | The intended production deployment was tested and evidence accepted. |
| Pending | Required evidence has not been supplied. |
| Blocked | A safety prerequisite is missing; do not enable the dependent feature. |
| Accepted out of scope | Project owner records an explicit decision reference; not equivalent to a successful test. |

## Repository and CI checkpoint

| Area | Repository state | Verification boundary |
|---|---|---|
| Phase 5 application and deployment foundations | Implemented | CI checks code, migration chain, Compose configuration and ephemeral smoke test |
| Phase 6.1 collection orchestration | Implemented | Real source ingestion and worker recovery still require local/staging evidence |
| Phase 6.2 investigation and evidence attachments | Implemented | Upload/download, integrity, expiry and paired DB/evidence-volume restore require local/staging drill |
| Phase 6.3 playbook framework and dashboard | Implemented | Preview and approval governance are not provider execution |
| Phase 6.4 operational reporting and dashboard | Implemented | Export must be reconciled to independently recorded source data in staging |
| PR #95 | Merged | Branch-head CI/security workflows passed; binary evidence implementation |
| PR #96 | Merged | Branch-head CI/security workflows passed; playbooks and reporting dashboard workflows |
| Production Compose smoke test | CI-tested | Ephemeral CI deployment only; not a live host deployment |
| Secret/dependency checks | CI-tested | Workflow coverage does not prove deployed secrets were rotated or host security |

## Phase acceptance matrix

| Workstream | Repository status | Required next evidence |
|---|---|---|
| Wazuh Manager inventory | Implemented; live validation pending | Sync known disposable agents, including one without alerts; reconcile fields and preservation behavior |
| Wazuh Indexer alerts | Implemented; live validation pending | Collect known lab events, compare source IDs/counts/timestamps and repeat for deduplication |
| Wazuh vulnerability data | Implemented; live validation pending | Sync known CVE/package rows and verify exact agent mapping and analyst-state preservation |
| CrowdSec decisions | Implemented; live validation pending | Collect an approved short-lived test decision twice; verify no mutation and deduplication |
| CrowdSec alert history | Optional; broader machine-account permission risk | Owner approval, dedicated credential, bounded GET-only collection and audit review |
| Redis collection/detection workers | Implemented; live recovery pending | Controlled queue/lease/restart and Redis interruption drills in disposable staging |
| Detection → incident → notification | Automated contract implemented | Trace real authorized lab event through every persisted stage and repeat idempotently |
| Investigation timeline | Implemented | Reconcile source provenance, notes and audit transitions |
| Evidence attachments | Implemented | Access-control, content-type, size, tamper, expiry and paired database/evidence-volume restore tests |
| Playbook preview and approvals | Implemented | Role separation, expiry, audit and no-dispatch verification |
| Provider response execution | Deliberately disabled | Separate threat model, independent approval, provider-specific design and a separately reviewed PR; not a release requirement for the current safe scope |
| Operational report/export | Implemented | Reconcile exact UTC-window JSON/CSV to independently authored expected counts and timing |
| Nuclei execution | Blocked by independent safety gate | Written target authorization, external DNS/IP egress enforcement, metadata/private-range blocking and lease-loss drill |
| Shannon execution | Blocked by separate runner gate | Dedicated disposable VM, isolation/egress/budget controls, license review and written authorization |
| Wazuh isolation/unisolation | Disabled and unregistered | No enablement in this release; any future proposal requires independent threat-model and rollback review |
| PostgreSQL backup/restore | Scripts and runbook implemented | Real archive verification and isolated restore with application-level read-only check |
| Evidence-volume backup/restore | Runbook implemented | Restore DB and binary volume together; verify representative digest and expiry behavior |
| Off-host retention / RPO / RTO | Operator responsibility | Encrypted off-host retention and measured recovery exercise |
| TLS, host hardening, monitoring | Deployment responsibility | Intended staging/production topology review and evidence |
| Investor / customer pilot | Not yet validated | Design partner, agreed scope, baseline, success criteria and reviewed pilot evidence |

## CI evidence

PR #95 and PR #96 each have successful CI/security workflow runs recorded in GitHub Actions. PR #96 run identifiers:
- OpsAegis CI: run 42783923665 (run 333).
- OpsAegis Security Checks: run 42783923701 (run 214).

The PR #96 CI jobs completed successfully for preflight, backend, frontend, runner, PowerShell operations script syntax and production-container smoke test. Security jobs completed successfully for full-history secret scanning and backend/frontend dependency audit.

These checks validate the tested commit and ephemeral CI environment only. They do not validate the user's local Wazuh lab, a persistent staging deployment, external credentials, network egress controls or production operations.

## Required local / staging sequence

1. Verify the local Compose stack and API/worker health without deleting volumes.
2. Verify the dedicated Wazuh Indexer read-only identity and CA trust; do not use the Indexer admin account.
3. Confirm the backend and collection worker resolve the Indexer service over the intended Docker network and use the correct CA path.
4. Collect a bounded, known disposable Wazuh event and reconcile source document → finding → detection → incident → notification.
5. Exercise collection scheduler and worker lease/restart recovery.
6. Exercise evidence upload/download, tamper detection, expiry and paired database/evidence-volume restore.
7. Exercise playbook preview and independent approval; verify that no provider action is dispatched.
8. Export a defined UTC report window and reconcile it against independent expected values.
9. Complete PostgreSQL restore, encrypted off-host retention and measured recovery objectives.
10. Record sanitized evidence references and independent reviewer decisions in the Phase 5 and Phase 6 registers.

Do not restart or recreate shared services without an approved change. Never publish environment files, secrets, private keys, raw security events or private infrastructure identifiers.

## Release decision

**Repository implementation:** Phase 5 foundations and Phase 6.1–6.4 software increments are present.
**Automated CI checkpoint:** PR #95 and PR #96 checks passed.
**Local/staging acceptance:** Pending.
**Production readiness:** Not established.
**Commercial validation:** Not established.

The release gate remains open until the required evidence is recorded and independently reviewed. Do not weaken strict validators or fill evidence fields with illustrative values to obtain a passing result.
