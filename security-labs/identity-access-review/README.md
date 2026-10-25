# Identity Security — Access Review Lab

A read-only Python proof of concept that detects review candidates in **synthetic identity records**.

## Run
From the repository root: `python3 security-labs/identity-access-review/review.py`.

## Input model
Each fictional identity contains `id`, `active` (bool), `roles` (list of role names), `mfa` (bool), and `last_login` (ISO date). The example uses a fixed as-of date for reproducibility. No Okta or Entra credentials are used.

## Review policies
| Finding | Rule | Analyst action |
|---|---|---|
| Stale active account | No recorded login in 90+ days | Confirm business need and sign-in coverage before disabling |
| Privileged role without MFA | Member of defined privileged role set with `mfa=false` | Validate effective MFA controls and plan remediation |
| Multiple privileged roles | Two or more roles from defined privileged set | Review least privilege and separation of duties |

The script emits machine-readable JSON, validates data types and duplicate IDs, and ignores disabled accounts.

## Limitations and governance
This is a **decision-support report, not an automated enforcement tool**. Role names and the MFA boolean are intentionally simplified. Real solutions must account for inherited roles, PIM activations, conditional access, service accounts, authentication methods, app scope and permission lineage. A last-login timestamp may not cover noninteractive authentications. Review findings with an identity owner; do not remove access automatically.

## Tests
`python3 -m unittest discover -s security-labs/identity-access-review -v`. Includes false-positive, duplicate-ID, date and privilege-boundary cases.
