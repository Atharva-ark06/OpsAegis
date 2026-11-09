# Wazuh isolation implementation gate

**Status: CLOSED — no isolation adapter is implemented, registered, or enabled.**

This increment adds an offline evidence-completeness check only. The merged
Wazuh isolation threat model explicitly records **NOT APPROVED FOR
IMPLEMENTATION OR ENABLEMENT**. That decision remains in force.

## Required operator evidence

Before a separately reviewed change may implement a provider mutation adapter,
an authorized operator and independent security reviewer must record references
for all of the following:

1. Exact deployed Wazuh Manager version and version-specific vendor API reference.
2. Written authorization defining the single disposable staging target and test window.
3. Isolated staging environment and disposable agent.
4. Review proving the service identity has only the minimum required permissions.
5. Independent provider-state verification method and evidence.
6. A separately approved compensation/unisolation drill with verified result.
7. Replay, duplicate-delivery, concurrency, timeout and worker-loss test evidence.
8. Audit/log/API redaction review and an independent security reviewer.

Use evidence identifiers or internal review references only. Never place
credentials, JWTs, private keys, raw provider responses, or personal data in
this register or in source control.

## Offline gate implementation

The new isolation readiness module provides an immutable evidence-reference
structure and a fail-closed completeness validator. Missing, blank, untrimmed,
non-string, or oversized references keep the gate closed. The validator
performs no network requests and does not contact Wazuh.

A complete register means only that references were supplied. It does **not**
authenticate those references, prove that the tests were performed, establish
the deployed Wazuh API behavior, grant authorization, or enable an adapter.
A trusted operator/security review must independently verify every artifact.

## Explicit non-scope

- No Wazuh active-response, isolate, or unisolate request is implemented.
- No API route, worker, queue consumer, dispatch path, or adapter registration is added.
- No configuration switch can enable isolation.
- No live Wazuh calls, production changes, or deployment actions are performed.
- wazuh.agent_isolate remains enabled=false and adapter_registered=false.

Do not proceed to provider mutation implementation until the threat-model hard
stops are cleared and the evidence has been independently reviewed. Unisolation
and recovery remain a separate subsequent increment.
