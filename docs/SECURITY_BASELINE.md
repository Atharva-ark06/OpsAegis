# Security Baseline

- Never commit .env files, credentials, tokens, private keys or customer evidence.
- Replace development credentials before use outside a local workstation.
- Development ports are bound to loopback by default.
- Disable interactive API documentation in production.
- Never expose engine credentials to frontend code.
- Run Nuclei and Shannon only against explicitly authorized targets.
- Isolate scan workers and apply network egress restrictions, timeouts and resource quotas.
- Restrict Shannon to owned lab/staging environments in the initial release.
- Require authorization and audit logging for disruptive actions such as blocking.
- Use least-privilege service credentials for each integration.
