"""Offline authentication anomaly detector for synthetic JSONL events.

Design: deterministic sliding windows, per-subject cooldown, no external calls.
These alerts indicate suspicious patterns, NOT confirmed compromise.
"""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("All timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def analyze(events, window_minutes=10, min_users=3, failure_threshold=5):
    """Return possible spray/burst findings over a sliding time window.

    events: {"timestamp": ISO8601, "user": str, "ip": str,
             "result": "success"|"failure"}.
    A matching subject is suppressed for one window after an alert.
    """
    if any(isinstance(n, bool) or not isinstance(n, int) or n < 1
           for n in (window_minutes, min_users, failure_threshold)):
        raise ValueError("Thresholds and window_minutes must be positive integers")

    parsed = []
    for event in events:
        if event["result"] not in ("success", "failure"):
            raise ValueError("result must be 'success' or 'failure'")
        if not event["ip"] or not event["user"]:
            raise ValueError("ip and user are required")
        parsed.append((_timestamp(event["timestamp"]), str(event["user"]),
                       str(event["ip"]), event["result"]))
    parsed.sort(key=lambda e: (e[0], e[1], e[2], e[3]))

    delta = timedelta(minutes=window_minutes)
    source_failures = defaultdict(deque)
    identity_failures = defaultdict(deque)
    last_alert = {}
    findings = []

    for when, user, ip, result in parsed:
        if result != "failure":
            continue

        source = source_failures[ip]
        source.append((when, user))
        while source and source[0][0] < when - delta:
            source.popleft()

        identity = identity_failures[user]
        identity.append((when, ip))
        while identity and identity[0][0] < when - delta:
            identity.popleft()

        patterns = (
            ("possible_password_spray", ip, len({item[1] for item in source}),
             min_users, "T1110.003"),
            ("repeated_authentication_failures", user, len(identity),
             failure_threshold, "T1110"),
        )
        for rule, subject, observed, threshold, technique in patterns:
            key = (rule, subject)
            if observed < threshold:
                continue
            if key in last_alert and when - last_alert[key] < delta:
                continue
            last_alert[key] = when
            findings.append({
                "rule": rule,
                "subject": subject,
                "timestamp": when.isoformat(),
                "observed": observed,
                "threshold": threshold,
                "mitre_attack": technique,
                "status": "needs_investigation",
            })
    return findings


SAMPLE = [
    {"timestamp": f"2026-01-01T12:0{i}:00Z",
     "user": f"lab-user-{i}@example.invalid",
     "ip": "192.0.2.10", "result": "failure"} for i in range(4)
]


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic auth event triage")
    parser.add_argument("--input", type=Path, help="Optional JSONL event file")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--min-users", type=int, default=3)
    parser.add_argument("--failure-threshold", type=int, default=5)
    args = parser.parse_args()

    if args.input:
        if args.input.stat().st_size > 5_000_000:
            parser.error("Input must be 5 MB or less (demonstration limit)")
        with args.input.open(encoding="utf-8") as handle:
            events = [json.loads(line) for line in handle if line.strip()]
    else:
        events = SAMPLE

    try:
        findings = analyze(events, args.window_minutes, args.min_users,
                           args.failure_threshold)
    except (KeyError, ValueError, TypeError) as exc:
        parser.error(f"Invalid event data: {exc}")
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
