"""Simple deterministic detections for synthetic authentication events."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def analyze(events, window_minutes=10, min_users=3, failure_threshold=5):
    """Detect shared-source password spraying and per-user failure bursts.

    Input: iterable of {timestamp (ISO-8601), user, ip, result}.
    Output: sorted findings; timestamps must be UTC-offset-aware.
    """
    parsed = []
    for event in events:
        when = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError("Authentication timestamps must have timezone offsets")
        if event["result"] not in ("success", "failure"):
            raise ValueError("result must be success or failure")
        parsed.append((when.astimezone(timezone.utc), event["user"], event["ip"], event["result"]))
    parsed.sort()
    findings = set()
    for i, (start, user, ip, result) in enumerate(parsed):
        if result != "failure":
            continue
        relevant = [e for e in parsed[i:] if e[0] < start + timedelta(minutes=window_minutes) and e[3] == "failure"]
        same_ip = [e for e in relevant if e[2] == ip]
        if len({e[1] for e in same_ip}) >= min_users:
            findings.add(("password_spray", ip, start.isoformat()))
        same_user = [e for e in relevant if e[1] == user]
        if len(same_user) >= failure_threshold:
            findings.add(("repeated_failures", user, start.isoformat()))
    return [{"rule": rule, "subject": subject, "window_start": time} for rule, subject, time in sorted(findings)]


SAMPLE = [
    {"timestamp": f"2026-01-01T12:0{i}:00Z", "user": f"user{i}@example.invalid",
     "ip": "192.0.2.10", "result": "failure"} for i in range(4)
]


if __name__ == "__main__":
    print(json.dumps(analyze(SAMPLE), indent=2))
