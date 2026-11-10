# Roles and permissions

OpsAegis applies authorization in the API. Frontend visibility is a usability aid, not an enforcement boundary.

| Capability | Viewer | Analyst | Administrator |
|---|---:|---:|---:|
| View operational workspace and records | Yes | Yes | Yes |
| Read integration health and collection history | Restricted by endpoint policy | Yes | Yes |
| Queue allowlisted manual collection | No | Yes | Yes |
| Change collection schedules | No | No | Yes |
| Update finding triage | No | Yes | Yes |
| Assign and transition incidents | No | Yes | Yes |
| Add investigation notes and evidence | No | Yes | Yes |
| Manage users and roles | No | No | Yes |
| Register authorized scan targets | No | No | Yes |
| Dispatch gated Shannon assessment | No | No | Yes |
| Approve/reject playbook requests | No | Per workflow policy | Per workflow policy |

The exact API endpoint policy is authoritative and may be stricter than this high-level summary. Always verify the relevant route dependency before changing a permission.

## Account safeguards

- First-admin bootstrap requires a separate secret and is not public self-registration.
- Passwords are hashed server-side and must meet the configured minimum length.
- User listing and role changes require an administrator session.
- The last active administrator cannot be demoted or deactivated.
- An administrator cannot deactivate their own account.
- Deactivated accounts must not retain active access.

## Change guidance

Permission changes should include tests for both allowed and denied roles. Add negative tests for unauthenticated users, viewers and inactive accounts. Never rely only on disabling or hiding a frontend control.
