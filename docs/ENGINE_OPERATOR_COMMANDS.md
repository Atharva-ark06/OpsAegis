# Nuclei and Shannon operator commands

This quick reference covers standalone CLI setup and use. These commands do not install scanners inside the OpsAegis API container and do not enable the OpsAegis dispatch adapters.

## Nuclei v3.4.10

Install Go, then install the pinned CLI:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10
nuclei -version
nuclei -update-templates
```

Run a bounded scan against an explicitly authorized HTTPS staging target:

```bash
nuclei -u https://staging.example.com \
  -severity info,low,medium,high,critical \
  -rl 5 -timeout 10 -retries 1 \
  -jsonl -o nuclei-results.jsonl
```

The OpsAegis Nuclei integration uses a dedicated isolated worker, pinned templates and a fixed safe profile. It is not enabled by installing this CLI on a developer workstation.

## Shannon v3.5.0

Prerequisites: Node.js 22+ and Docker Engine running on a dedicated isolated assessment host.

Check prerequisites:

```bash
node --version
docker --version
```

Run the pinned Shannon CLI against an approved staging URL and its corresponding source repository:

```bash
npx @keygraph/shannon@3.5.0 start \
  -u https://staging.example.com \
  -r https://github.com/your-org/your-app
```

Shannon performs real exploitation and launches disposable Docker workers. Never use it against production or systems without written authorization. Keep the runner isolated, enforce destination allowlists at the network layer, and apply model-provider budget limits.

## OpsAegis integration requirements

- Nuclei: provision the dedicated `nuclei-worker`, verify enforced outbound DNS/IP allowlists, then configure `NUCLEI_ENABLED=true` and `NUCLEI_WORKER_ENABLED=true` only after staging validation.
- Shannon: deploy the bridge on a separate isolated host, configure HTTPS `SHANNON_RUNNER_URL` and `SHANNON_RUNNER_TOKEN` on the API service, and enable only after egress, authorization and runner health checks pass.
- Local CLI output is not automatically imported into OpsAegis. The adapters require their corresponding isolated services and validated result-sync paths.
