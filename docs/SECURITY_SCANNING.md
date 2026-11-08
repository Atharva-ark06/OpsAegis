# Security scanning in CI

OpsAegis runs three automated supply-chain checks on pull requests and pushes to \`main\`.

## Secret detection

The full-history Gitleaks job checks the complete Git history (\`fetch-depth: 0\`) for committed credentials, tokens and private keys. A finding must be treated as a possible compromise:

1. Identify the affected provider and credential owner without copying the secret into an issue or chat.
2. Revoke or rotate the credential at the provider immediately. Removing it from the current file does not invalidate a leaked key.
3. Remove the secret from tracked files and replace it with an environment variable or managed secret.
4. Review provider access logs and usage from the exposure window.
5. If repository history contains a live credential, coordinate a history rewrite only after rotation and contributor coordination. Force-pushing history is disruptive and does not replace rotation.

Gitleaks can produce false positives. Suppress only a verified non-secret with a narrow, documented rule; never add a broad path or regex exclusion to make a check green.

## Python dependency audit

\`pip-audit --strict\` checks the declared backend and Shannon bridge dependency sets against the Python vulnerability database. A failing audit blocks the security workflow. Review the advisory, affected version range and available fixed version before updating dependencies. Run backend tests, migration checks and runner tests after any upgrade.

The project currently does not commit a frontend npm lockfile. This workflow therefore does not claim reproducible frontend dependency resolution or perform an npm audit. Add and maintain a reviewed lockfile before enabling a meaningful locked frontend audit.

## GitHub Dependency Review availability

The GitHub Dependency Review action is not enabled in this repository because its dependency graph feature is currently unavailable. The workflow does not call that action or claim to provide its PR-level diff analysis. Enable the repository dependency graph in GitHub Settings if you want to add that additional check later.

## What a green result means

A green security workflow means these automated checks did not identify a blocking issue in the scanned history/dependency metadata at that commit. It does not prove that:
- credentials were never exposed outside the scanned Git history;
- a previously exposed key has been revoked or rotated;
- runtime configuration, container images or deployed hosts are secure;
- every transitive dependency is free of unknown vulnerabilities;
- the application has passed penetration testing or a full security review.

Review findings promptly and record remediation. Never paste raw secret values into CI logs, issues, pull requests or diagnostic reports.
