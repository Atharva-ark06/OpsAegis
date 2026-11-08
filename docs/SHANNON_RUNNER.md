# Shannon isolated runner deployment

PR #8 introduced the OpsAegis control-plane adapter. PR #9 adds a separate bridge reference implementation under runner/shannon-bridge/; it is not bundled into the OpsAegis backend or docker-compose stack.

## Trust boundary

Shannon is an autonomous exploitation engine. Its official CLI reads application source and launches ephemeral Docker workers. Treat the runner VM and its Docker daemon as a high-trust, disposable security-testing boundary. Never mount the Docker socket into the bridge API container, expose Docker API access to OpsAegis, or co-locate the runner with the OpsAegis Docker host.

The bridge is disabled by default. It requires a dedicated VM, exact allowlists for staging target hostnames and source repositories, an independently enforced egress proxy and host firewall, DNS/IP enforcement on every connection and redirect, DNS-rebinding protection, pinned CLI, one concurrent job, bounded runtime, model-provider cost limits and written authorization.

See runner/shannon-bridge/README.md for deployment steps. Keep execution disabled until infrastructure controls are independently verified.

## Official Shannon compatibility

The official KeygraphHQ/Shannon README documents the CLI workflow as npx @keygraph/shannon start -u <target> -r <repo>, with Docker required for ephemeral workers and Node.js 22+ for the recommended npx workflow. It writes workspace reports and supports SARIF. This adapter pins CLI version 3.5.0 rather than floating latest. The official v3.5.0 release is dated 2026-10-27.

Shannon is AGPL-3.0-only. No Shannon source is copied into OpsAegis. Review obligations and commercial licensing before redistribution or network-service use.

## Bridge limitations and proof semantics

The reference bridge accepts only the fixed authorized-staging profile and exact preconfigured target/repository pairs. It does not expose arbitrary commands, flags, paths, mounts or target URLs. Its SARIF importer fails closed and requires explicit proof metadata plus an in-scope affected URL. If the official pinned CLI output does not contain those properties, findings are not forwarded. Do not infer exploitation proof from title, severity or description.

The initial bridge uses in-memory job state and supports one job at a time. It has no durable queue, cancellation, retry, HA, artifact download or complete Markdown/PDF report parser. CI validates API policy and proof gating only; it does not run Shannon or claim a live pentest.

## Validation checklist

- [ ] Deploy on a dedicated disposable VM; never co-locate with OpsAegis.
- [ ] Verify host firewall denies direct egress and internal/metadata destinations.
- [ ] Verify proxy enforces host and resolved-IP allowlists per request and redirect, including DNS-rebinding defenses.
- [ ] Confirm only the staging target, required provider endpoints, and pinned package/container registries are reachable.
- [ ] Confirm no Docker socket/API is exposed to OpsAegis or the bridge HTTP container.
- [ ] Confirm model key is runner-only and has budget limits.
- [ ] Obtain written authorization and take a disposable staging snapshot.
- [ ] Run one authorized staging assessment and inspect raw SARIF/Markdown/PDF before enabling finding sync.
- [ ] Verify deduplication and analyst triage preservation in OpsAegis.
