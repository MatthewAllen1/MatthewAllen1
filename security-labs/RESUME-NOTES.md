# How to present this portfolio accurately

These examples are **personal demonstration projects** and should be described as engineering artifacts, not employer results or production security controls.

## Resume-ready project descriptions (only after verifying tests)

**Security Detection Lab — Python, Log Analysis, MITRE ATT&CK**
- Built an offline Python detector that normalizes fictional authentication events, correlates failed sign-ins using sliding windows, and emits explainable JSON findings associated with MITRE ATT&CK techniques.
- Added regression tests for threshold behavior, out-of-order records, false positives, and malformed inputs; used CI for automatic verification.

**Identity Access Review — Python, IAM**
- Developed a read-only identity hygiene review proof of concept that flags stale active accounts, missing MFA on defined privileged roles, and overlapping administrative assignments.
- Designed deterministic fixtures and tests to distinguish privileged from ordinary read-only assignments.

**Risk-Based Vulnerability Triage — Python**
- Implemented a transparent, **illustrative** prioritization model for synthetic findings using severity, simulated known exploitation, exposure and business criticality.
- Documented assumptions, input constraints, and limits; did not claim validated risk reductions or live exploit intelligence.

**File Integrity Monitoring — Python, SHA-256**
- Created a baseline-and-compare lab for detecting local changes, additions, and deletions using SHA-256 digests.

## Interview discussion prompts

Be ready to explain (1) an edge case you tested, (2) a false positive you intentionally avoid, (3) how you would integrate the design with authenticated real-world data, (4) how you would evaluate its detection accuracy, and (5) why you restricted scope to offline synthetic data.

Do not claim production usage, security certification, measured performance improvements, or external project authorship unless you can substantiate them.
