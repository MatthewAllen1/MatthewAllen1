# Architecture and design decisions

## Scope

Each lab runs locally using Python's standard library. They deliberately avoid identity-provider connectivity, network scanning, external telemetry services and write access to production resources. They are designed as explainable engineering exercises rather than packaged enterprise applications.

## Data flows

| Lab | Input | Processing | Output | Side effects |
|---|---|---|---|---|
| Authentication | Synthetic JSONL events | UTC validation, time windows, deduplication, thresholds | JSON findings | Reads a local file only |
| Identity | In-memory fictional accounts | State checks, privileged-role intersection, inactivity rules | JSON findings | None |
| Vulnerability | In-memory invented findings | Range/type validation, weighted scoring, stable sort | Ranked JSON | None |
| File integrity | Files in explicit sample directory | Stream SHA-256 hashes, compare with baseline | JSON differences | Creates baseline only in `--init` mode |

## Security considerations

**Trust boundaries.** Local inputs are untrusted. Validate field values before making classifications. Offline tools do not have an authorization or credential model; add those controls before connecting production APIs.

**False positives.** Shared egress IPs, imperfect login telemetry, nested roles, stale inventory metadata and authorized file changes can all produce benign findings. Every project is human-in-the-loop by design.

**Reproducibility.** Examples are deterministic, use synthetic test fixtures, and rely on the standard library. The CI workflow compiles and executes tests and safe smoke commands without injecting secrets.

**Operational gaps.** Production versions would require logging, performance testing, telemetry contracts, rate limiting, privacy retention rules, structured error reporting, metrics, alert lifecycle management, threat modeling, and security review.

## Validation evidence

Automated checks run through [GitHub Actions](../.github/workflows/security-labs-ci.yml), including positive detection tests, negative controls, malformed-input validation and sorting/immutability checks. See the run history for actual pass/fail results; having a workflow file is not itself proof that the workflow passed.

## Suggested next iteration

Create a separate, dedicated repository per mature project with a versioned CLI contract, threat model, release process, fixtures, and test coverage. Integrations with real APIs should only be added after permission scoping and risk review.
