# Data flow and evidence provenance

## High-level lifecycle

1. An authorized operator requests a read-only collection or an allowlisted schedule queues it.
2. The integration adapter contacts the configured upstream service with bounded timeouts and result limits.
3. The adapter validates and normalizes the response into source-labelled records.
4. Source identifiers and deduplication rules prevent repeated collection from creating duplicate findings.
5. Detection evaluation uses persisted findings; it does not invent upstream telemetry.
6. Correlated detections can be investigated through the incident workflow.
7. Analyst triage, notes, status transitions and evidence attachment metadata are persisted and audited.
8. Bounded evidence exports preserve source context while redacting common secret-like fields.

## Provenance rules

- Keep upstream source IDs and source namespaces where supplied.
- Distinguish an upstream event timestamp from the time OpsAegis observed or ingested a record.
- Do not infer that an asset is affected solely because a CVE exists.
- Preserve analyst triage and remediation state during repeat collection.
- Leave asset associations unset when identity matching is ambiguous.
- Treat truncated upstream responses as partial evidence, not a complete inventory.

## Failure semantics

A provider timeout, authentication error, rate limit or missing configuration must remain visible as a failed, skipped or unavailable integration state. It must not be converted into a clean verdict or a zero-risk result.

## Scope limitations

The system's read-only integrations do not block an IP, modify an endpoint, change a firewall, submit a file for scanning or launch an arbitrary URL scan. Playbook approvals are governance records; no provider response action is dispatched by approval alone.

See [integration matrix](INTEGRATION_MATRIX.md), [incident workflow](INCIDENT_WORKFLOW.md) and [release readiness](RELEASE_READINESS.md).
