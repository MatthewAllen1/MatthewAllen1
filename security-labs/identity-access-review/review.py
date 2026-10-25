"""Offline identity governance checks using fictional account records."""
from datetime import date
import json


def review(accounts, today=None, stale_days=90):
    today = today or date.today()
    findings = []
    seen = set()
    for account in accounts:
        user = account["id"]
        if user in seen:
            raise ValueError("Duplicate account id")
        seen.add(user)
        active = account["active"]
        roles = set(account["roles"])
        last_login = date.fromisoformat(account["last_login"])
        age = (today - last_login).days
        if age < 0:
            raise ValueError("Future login date")
        if active and age >= stale_days:
            findings.append({"account": user, "finding": "stale_active_account", "age_days": age})
        if active and roles.intersection({"Global Administrator", "Super Administrator"}) and not account["mfa"]:
            findings.append({"account": user, "finding": "privileged_without_mfa"})
        if active and len(roles) >= 3:
            findings.append({"account": user, "finding": "multiple_privileged_roles", "role_count": len(roles)})
    return sorted(findings, key=lambda x: (x["account"], x["finding"]))


SAMPLE = [
    {"id": "lab-admin-001", "active": True, "roles": ["Global Administrator"], "mfa": False, "last_login": "2025-01-01"},
    {"id": "lab-user-002", "active": True, "roles": ["Reader"], "mfa": True, "last_login": "2026-01-10"},
    {"id": "lab-former-003", "active": False, "roles": [], "mfa": False, "last_login": "2024-01-01"}
]

if __name__ == "__main__":
    print(json.dumps(review(SAMPLE, today=date(2026, 2, 1)), indent=2))
