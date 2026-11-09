# OpsAegis isolated Wazuh staging lab

**Purpose:** Reproducible, local-only Wazuh environment for later OpsAegis integration and response-adapter validation.  
**Pinned vendor release:** Wazuh Docker `v4.14.10` (Manager, Indexer, Dashboard and disposable agent).  
**Live OpsAegis staging validation:** NOT PERFORMED by this scaffold.  
**Isolation / unisolation adapter:** NOT IMPLEMENTED, NOT REGISTERED, NOT ENABLED.

This lab is a preparation step. Starting containers or seeing an enrolled agent does not prove that OpsAegis collection, alert ingestion, reporting, recovery, isolation or unisolation works.

## 1. Safety model

- Uses the official Wazuh Docker repository at the exact `v4.14.10` tag.
- Uses one Manager, one Indexer, one Dashboard and one disposable containerized Wazuh agent.
- Publishes the Manager, Indexer and Dashboard ports on host loopback only. Dashboard host port is `8443`; manager API is `55000`; indexer API is `9200`.
- The disposable agent has no published host ports and joins the same private Compose network as the manager.
- Does not attach a production OpsAegis deployment, production endpoint, or real user agent.
- Does not issue active-response, isolate, unisolate, shell, scan, or other provider mutation requests.
- Does not change any production configuration or commit generated certificates, credentials, volumes, or vendor runtime files.
- The upstream Wazuh single-node stack uses vendor-provided default lab credentials. Keep this lab on a trusted local machine, never expose its ports, and rotate credentials before any broader network use. Never reuse these credentials elsewhere.

## 2. Host prerequisites

The Wazuh vendor single-node Docker guide specifies a Linux/WSL2 host, Docker Engine or Docker Desktop with Compose v2, Git, at least 4 CPU cores, 8 GB RAM and 50 GB free disk. The Indexer requires `vm.max_map_count=262144` in the Linux kernel used by Docker. Windows users must use Docker Desktop with WSL2 and set the value inside the relevant WSL2 environment.

Official vendor instructions:
- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh Docker v4.14.10 release tag](https://github.com/wazuh/wazuh-docker/tree/v4.14.10)

Do not run this stack alongside another Wazuh Docker stack on the same Docker host: vendor stacks share container ports and resource names.

## 3. Start on Windows PowerShell 7

From the OpsAegis repository root:

```powershell
pwsh -NoProfile -File .\ops\wazuh-staging\Start-WazuhLab.ps1
```

The script:
1. Checks Git, Docker and Compose v2.
2. Clones the official Wazuh Docker repository at the exact `v4.14.10` tag into the ignored `ops/wazuh-staging/runtime/` directory. It refuses to overwrite an existing checkout.
3. Rewrites only the six expected upstream host-port mappings to loopback bindings; it fails closed if the pinned vendor file differs.
4. Generates the vendor self-signed certificates using the pinned release's certificate-generator Compose file.
5. Validates the merged Compose configuration before starting the stack.
6. Starts the central components and the disposable `opsaegis-disposable-agent`.

The runtime checkout, generated certificates and vendor config are local-only and ignored by Git.

## 4. Verify the disposable agent

Allow the Manager, Indexer and agent time to initialize, then run:

```powershell
pwsh -NoProfile -File .\ops\wazuh-staging\Test-WazuhLab.ps1
```

The check prints Compose service state and verifies that the Manager's local `agent_control -l` inventory lists `opsaegis-disposable-agent` as Active. If it is not active yet, inspect the local container logs and retry after startup; do not treat a running container alone as a successful enrollment.

Dashboard:
- URL: `https://localhost:8443`
- The vendor self-signed certificate causes a browser trust warning. This is expected for the isolated lab; do not disable TLS verification in OpsAegis.

Manager API and Indexer API are bound to `127.0.0.1` only. The API account and password are present in the downloaded, ignored vendor Compose file. Read them locally when configuring a disposable OpsAegis test instance; do not paste credentials into chat, issues, PRs, logs, or tracked files.

## 5. Stop and reset

Stop containers but preserve local volumes:

```powershell
pwsh -NoProfile -File .\ops\wazuh-staging\Stop-WazuhLab.ps1
```

To permanently remove the lab's Docker volumes, pass the explicit switch and type the confirmation phrase when prompted:

```powershell
pwsh -NoProfile -File .\ops\wazuh-staging\Stop-WazuhLab.ps1 -RemoveVolumes
```

The script does not delete the ignored runtime checkout or generated certificates. Review and remove `ops/wazuh-staging/runtime/` manually only after the containers are stopped and the evidence you need has been sanitized and stored in an approved location.

## 6. What this lab enables next

After the lab is running, a separately reviewed OpsAegis staging exercise can:

1. Confirm the actual Manager and Indexer versions and record the exact deployed OpsAegis commit.
2. Configure a dedicated test API identity and CA trust without disabling TLS verification.
3. Exercise read-only Manager inventory and Indexer alert/vulnerability collection.
4. Generate known, benign lab telemetry and reconcile expected versus observed findings, detections and incidents.
5. Validate report metrics against independently authored expectations and run the Phase 6 evidence validators.
6. Exercise Redis/worker interruption and recovery in the disposable environment.
7. Record sanitized evidence and obtain independent review; keep the evidence register pending until this has actually happened.

This PR does not automatically connect OpsAegis to the lab or claim that the above steps passed. The operator must supply local configuration and execute the authorized drill.

## 7. Wazuh isolation and unisolation remain a separate gate

The lab is a prerequisite, not permission to add provider mutation. Before a separate adapter PR:
- Independently verify the deployed Wazuh API behavior for the exact pinned version and the minimum permissions required for isolate, unisolate and state verification.
- Obtain written authorization naming the disposable agent and test window.
- Provision a dedicated least-privilege service identity through local secret handling.
- Complete independent review of the existing threat model and approval/idempotency/ledger binding.
- Test timeout, unknown outcome, duplicate/replay, concurrency, worker loss, audit persistence, separate unisolation approval and independent provider-state verification.
- Keep the adapter disabled if the provider cannot enforce least privilege or reliably verify the target state.

No adapter, mutation endpoint, dispatcher, queue consumer, active-response request, isolation, unisolation or automatic compensation is added by this PR. Production use is explicitly out of scope.
