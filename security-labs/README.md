# Security Engineering Labs

Four original, self-contained Python learning projects using **synthetic data**, no credentials, and no calls to production services. These are portfolio demonstrations, not commercial security tools. Each uses only the Python standard library.

| Project | Capability | Try it |
|---|---|---|
| [Authentication Detection](./authentication-detection/) | Detect password spraying and unusual sign-in activity | `python security-labs/authentication-detection/detect.py` |
| [Identity Access Review](./identity-access-review/) | Flag stale accounts, excessive privilege and weak MFA | `python security-labs/identity-access-review/review.py` |
| [Vulnerability Prioritization](./vulnerability-prioritization/) | Rank remediation using KEV, exposure, severity, and business criticality | `python security-labs/vulnerability-prioritization/prioritize.py` |
| [File Integrity Monitoring](./file-integrity-monitor/) | Detect changes, deletions and additions in a local directory using SHA-256 | `python security-labs/file-integrity-monitor/monitor.py --help` |

Run from the repository root with Python 3.10+. Run tests via `python -m unittest discover -s security-labs -p 'test_*.py'`.

## Design and ethics

- Original demonstration code; no third-party source copied.
- No employer data, live telemetry, employee identifiers, infrastructure details, or proprietary rules.
- Synthetic data and simple heuristics cannot establish real-world detection accuracy.
- Extend with test fixtures, packaging, CI, and additional validation before any production usage.
- Defensive/educational use only.
