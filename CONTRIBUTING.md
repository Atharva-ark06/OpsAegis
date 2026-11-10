# Contributing to OpsAegis

Thanks for helping improve OpsAegis. Changes should be reviewable, tested and aligned with the project's security boundaries.

## Before changing code

1. Read the relevant architecture and integration documentation.
2. Check open issues and pull requests to avoid duplicate work.
3. Keep changes focused; separate unrelated refactors.
4. Never include credentials, production data, evidence attachments or private keys.

## Branch workflow

Use a descriptive branch name, for example:

```text
feat/wazuh-inventory-filter
fix/incident-timeline-empty-state
docs/railway-operations-guide
```

Create the branch from the current default branch. Do not commit directly to `main`.

## Commit messages

Prefer small, meaningful commits that explain one coherent change:

```text
feat(incidents): preserve assignment during status updates
fix(frontend): show collection error state
docs(railway): clarify private API routing
test(auth): cover inactive-user rejection
```

Do not create empty commits, repetitive one-line edits or artificial commit padding. Commit history should make the review easier, not harder.

## Pull request checklist

- [ ] Explain the user-visible or operational problem.
- [ ] Describe the implementation and any security impact.
- [ ] Include screenshots only when they add value; redact secrets and internal identifiers.
- [ ] Add or update tests for behavior changes.
- [ ] Run backend tests and/or frontend tests/build as relevant.
- [ ] Validate migrations and production Compose when configuration changes.
- [ ] Update docs and environment templates when behavior/configuration changes.
- [ ] Confirm no secrets, local databases, logs or generated artifacts are included.
- [ ] State what was not tested, especially external integrations and production behavior.

## Security-sensitive changes

Authentication, authorization, provider credentials, evidence handling, scanner execution, network egress and response actions require extra scrutiny. Never enable Nuclei or Shannon by default. Do not add provider response execution without a separate threat model, explicit authorization, independent approval and audit design.

## Review and merge

Open a pull request against `main`, wait for required checks and request review. The repository owner performs the merge. A successful merge may trigger Railway deployments for services watching `main`; verify the deployment commit and terminal status rather than assuming it is live.
