# Reference-driven OpsAegis workspace redesign

This change removes the shared analytics dashboard that previously appeared above nearly every non-overview section and replaces it with section-specific information architecture.

## Visual direction mapped from the supplied references

| OpsAegis section | Reference pattern | Implemented direction |
| --- | --- | --- |
| Overview | AiStrike security command dashboard | Command-center summary, severity distribution, remediation state, event activity and affected assets |
| Assets | Group-IB attack-surface management | Inventory totals, environment/type distribution and assets with linked open findings |
| Findings | ConnectSecure vulnerability prioritisation | Severity and workflow distribution, prioritised findings queue and source context |
| Vulnerabilities | AWS Inspector | Dedicated CVE register, CVSS, affected asset/package context, NVD enrichment and remediation status |
| Detections | SOC alert triage | Dedicated detection rules, scheduler, evaluation runs, notifications and detection status |
| Incidents | Juice Lab incident command dashboard | Active/critical case summary, lifecycle/severity profile and investigation activity |
| Integrations | RAD integration catalogue | Real provider/engine state, collection controls, source-specific workspaces and errors |
| Threat Intel | ReliaQuest GreyMatter | IOC enrichment, provider evidence, indicator context and occurrence details |
| Playbooks | Splunk SOAR workflow editor | Playbook catalogue, preview, approvals and guarded execution contracts |
| Users & Roles | CISOPOLIS user management | Provisioned accounts, role controls, activation state and account actions |
| Reports | Existing operational reporting | Authenticated operations report and execution ledger |
| Settings | Existing workspace settings | Actual signed-in account, RBAC role and appearance preference |

## Data integrity rules

- Metrics and distributions in the Overview, Assets, Findings and Incidents workspaces are calculated from authenticated API records.
- No synthetic provider connection state, account, permission, MITRE mapping, MTTR value or risk score is fabricated.
- Vulnerability data remains in the dedicated CVE workflow; a general finding is not silently treated as an exploitable CVE.
- Detections remain signals; incidents remain investigation cases.
- Integrations, Users & Roles and Settings continue to display real runtime/provider/account configuration.
- Sections with dedicated operational components (Vulnerabilities, Detections, Integrations, Threat Intel, Playbooks, Users & Roles, Reports and Settings) no longer receive the unrelated shared analytics bento.

## Responsive behavior

The new metric grids and two-column panels collapse to single-column layouts on narrow screens. Existing application navigation, authentication, API clients and server-enforced RBAC are retained.

## Validation

Run the normal frontend checks from `frontend/`:

```powershell
npm ci
npm test
npm run build
```

The CI workflow remains the source of truth for the branch's automated validation.
