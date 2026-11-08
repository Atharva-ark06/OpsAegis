# OpsAegis Shannon isolated bridge

A separate reference runner for the OpsAegis Shannon control-plane adapter. It invokes the official CLI at a pinned version and forwards only SARIF results carrying explicit exploitation proof metadata. The importer fails closed: ordinary SARIF without properties.proof and properties.affected_url is not forwarded.

## Mandatory deployment boundary

- Deploy on a dedicated, disposable Linux VM with no production credentials or route to production/internal networks.
- The VM Docker daemon is root-equivalent. The runner OS account therefore has a powerful trust boundary; use a disposable VM and never expose its Docker API or socket to OpsAegis.
- Run the bridge API as a dedicated unprivileged OS account. Install Docker Engine, Node.js 22+, npm/npx, Git and Python on the dedicated VM. Do not containerize the bridge with a mounted Docker socket.
- A host firewall must deny direct egress to private, loopback, link-local, metadata, management and production networks. Permit outbound only through an authenticated egress proxy.
- The proxy/firewall must enforce hostname and resolved-IP allowlists on every connection and redirect, defend against DNS rebinding, and allow only the approved staging origin plus required model-provider and package/container registries. Proxy environment variables alone are NOT an egress security boundary.
- Never co-locate the runner with the OpsAegis Docker host. Shannon actively exploits applications and can mutate state.
- Use disposable staging data, snapshots, written authorization, one concurrent scan and strict time/cost budgets.
- Shannon OSS is AGPL-3.0-only. Review obligations and commercial licensing before redistribution or network-service use.

## Installation

1. Create a dedicated Linux VM and OS account with a dedicated work directory.
2. Install Docker Engine on that VM only, plus Node.js 22+, npm/npx, Git and Python 3.12+.
3. Copy this directory to the VM and install requirements in a virtual environment.
4. Generate a bridge token of at least 32 random characters.
5. Configure .env using .env.example. Set exact target host and source repository allowlists; no wildcards.
6. Pin SHANNON_CLI_VERSION=3.5.0. Never use latest.
7. Keep SHANNON_BRIDGE_ENABLED=false until firewall, proxy, DNS-rebinding controls, model-provider limits and written staging authorization are independently verified.
8. Only then set SHANNON_EGRESS_POLICY_ACKNOWLEDGED=true and SHANNON_BRIDGE_ENABLED=true.
9. Run behind a private HTTPS reverse proxy. Restrict inbound traffic to the OpsAegis backend network. Do not expose port 8090 publicly.

Run the service:

    python -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --host 127.0.0.1 --port 8090

The service process needs access to Docker on this dedicated VM because the official Shannon CLI starts ephemeral worker containers. That access is effectively root-equivalent; the VM is the isolation boundary. Never grant this access to the OpsAegis backend.

## API

- GET /health: readiness and fail-closed blocker.
- POST /v1/scans: authenticated fixed-profile dispatch.
- GET /v1/scans/{job_id}: status and proof-gated SARIF findings.

The service keeps job state in process memory. Restart loses scan status and active task state. This first version is for a controlled single-job validation environment, not HA or unattended production. Durable queueing, cancellation, retry, artifact download and full Markdown/PDF parsing are not implemented.

The SARIF importer requires explicit properties.proof and properties.affected_url and checks the affected hostname. If the pinned Shannon output does not contain these extension properties, findings are not forwarded. Do not weaken the gate or infer proof from a title/description. Implement a version-specific parser only after inspecting actual report artifacts from an authorized disposable staging run.

## Tests

    pip install -r requirements.txt
    pytest -q

CI does not run Shannon and no live pentest is claimed.
