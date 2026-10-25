# File Integrity Monitoring — Local SHA-256 Lab

**Goal:** Detect basic additions, deletions and changes within a lab directory.

## Quick start

Create a directory containing **only your own, non-sensitive example files**, then run:

```bash
python3 security-labs/file-integrity-monitor/monitor.py ./sample-dir ./baseline.json --init
python3 security-labs/file-integrity-monitor/monitor.py ./sample-dir ./baseline.json
```

The checker creates a baseline on the first command and exits with code `1` when drift is found. The comparison checks file content using SHA-256 and returns JSON lists of added, deleted and modified relative paths.

## Why it's useful
File hashing provides a simple, explainable integrity signal and is a starting point for understanding intrusion detection, configuration drift and forensic change review.

## Threat model and limitations
This is an educational **point-in-time snapshot**, not continuous monitoring or a tamper-proof baseline. A compromised local administrator can alter both files and the baseline. Protect the baseline outside the watched directory with independent access controls. Hashing does not establish who changed a file, whether the change was malicious, or what content changed. The script skips symlinks and does not scan network storage or registry entries.

Avoid running on sensitive, large, or production directories; this example reads file contents for hashing.

## Tests
`python3 -m unittest discover -s security-labs/file-integrity-monitor -v`.
