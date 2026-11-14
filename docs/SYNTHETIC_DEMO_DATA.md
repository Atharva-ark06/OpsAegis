# Synthetic demo dataset

OpsAegis includes an opt-in synthetic dataset for local and staging demonstrations. It creates linked records in the same PostgreSQL/SQLite tables consumed by the authenticated application APIs; it does not inject browser-only mock data.

## Safety boundaries

- The seeder refuses to run when `OPS_AEGIS_ENV=production`.
- It requires an existing active administrator and never creates demo accounts or passwords.
- Generated assets, findings, vulnerabilities, detections, incidents, notes and IOCs are explicitly marked with `[DEMO]`, `opsaegis-demo`, or `synthetic: true`.
- IOC domains use the reserved `.invalid` suffix and IP addresses use documentation-only TEST-NET ranges. No real malware sample or live target is included.
- It does not configure provider credentials, claim Wazuh/CrowdSec/other providers are connected, create successful provider collection runs, enable scanners, or execute playbook actions.
- Playbook investigation previews can use the seeded incidents and linked detections. Approval and execution remain governed by the normal operator workflow.

## Seed

From the repository's `backend/` directory, after migrations and first-admin bootstrap:

```powershell
python -m app.seed_demo_data
```

The command is idempotent: if the fixture already exists, it reports that it is present and does not duplicate it.

To remove only this fixture and recreate it:

```powershell
python -m app.seed_demo_data --reset
```

The reset operation targets only records with the fixture's reserved markers. It does not delete normal users, provider data, or records from other sources.

## What is populated

| Application area | Synthetic records |
|---|---|
| Assets | 12 fictional servers, endpoints, network, cloud and application assets |
| Findings | 18 linked security findings with varied severity and workflow status |
| Vulnerabilities | 5 CVE-shaped records linked to findings and assets; scores are illustrative |
| Detections | 5 correlated detections linked to findings and, where applicable, incidents |
| Incidents | 5 investigation cases assigned to the existing administrator, with demo notes |
| Threat Intel | 6 IOC examples with synthetic provider results; no live enrichment is performed |
| Playbooks | Seeded incident/detection context supports the existing investigation dry-run preview |
| Users & roles | Uses only real provisioned accounts; demo users are intentionally not created |
| Integrations | Provider health remains truthful and reflects real configuration. No fake connected/healthy state is inserted |
| Reports / Overview | Existing APIs can aggregate the seeded records; collection metrics remain empty until actual collection runs occur |
| Settings | Uses real runtime configuration; no synthetic configuration is written |

Synthetic CVE references and severity scores are teaching/demo fixtures, not assertions that the named CVEs affect any real system. Do not use this dataset for operational decisions, compliance evidence, or real remediation.

## Removing the fixture

Run the reset command only in a non-production environment. If you want an empty database after the demo, run the reset once and do not run the seed command again.
