"""Offline, explainable identity access-review checks for synthetic accounts."""
from datetime import date
import json

PRIVILEGED_ROLES = frozenset({
    "Global Administrator", "Super Administrator", "Privileged Role Administrator",
    "Security Administrator", "Application Administrator", "Groups Administrator"
})


def review(accounts, today=None, stale_days=90):
    """Find stale active accounts and privileges; never change an account."""
    if isinstance(stale_days, bool) or not isinstance(stale_days, int) or stale_days < 1:
        raise ValueError("stale_days must be a positive integer")
    today = today or date.today()
    findings = []
    seen = set()
    for account in accounts:
        user = account["id"]
        if not user or user in seen:
            raise ValueError("Account IDs must be nonempty and unique")
        seen.add(user)
        active = account["active"]
        if not isinstance(active, bool) or not isinstance(account["mfa"], bool):
            raise ValueError("active and mfa must be booleans")
        roles = set(account["roles"])
        last_login = date.fromisoformat(account["last_login"])
        age = (today - last_login).days
        if age < 0:
            raise ValueError("Future login date")
        if not active:
            continue
        if age >= stale_days:
            findings.append({"account": user, "finding": "stale_active_account",
                             "age_days": age})
        elevated = sorted(roles & PRIVILEGED_ROLES)
        if elevated and not account["mfa"]:
            findings.append({"account": user, "finding": "privileged_without_mfa",
                             "roles": elevated})
        if len(elevated) >= 2:
            findings.append({"account": user, "finding": "multiple_privileged_roles",
                             "roles": elevated})
    return sorted(findings, key=lambda x: (x["account"], x["finding"]))


SAMPLE = [
    {"id": "lab-admin-001", "active": True, "roles": ["Global Administrator"],
     "mfa": False, "last_login": "2025-01-01"},
    {"id": "lab-user-002", "active": True, "roles": ["Reader"],
     "mfa": True, "last_login": "2026-01-10"},
    {"id": "lab-former-003", "active": False, "roles": [],
     "mfa": False, "last_login": "2024-01-01"}
]

if __name__ == "__main__":
    print(json.dumps(review(SAMPLE, today=date(2026, 2, 1)), indent=2))
