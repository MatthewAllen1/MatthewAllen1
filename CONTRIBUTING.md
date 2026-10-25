# Contributing

Feedback, reproducible bug reports, and focused improvements are welcome.

1. Open an issue outlining the problem, expected behavior, and safe reproduction steps.
2. Work in a feature branch; keep commits focused and explain risk/reasoning.
3. Add or update a unit test covering the changed behavior.
4. Run `python3 -m unittest discover -s security-labs -p 'test_*.py' -v` before proposing a PR.
5. Keep all fixtures synthetic. Never include private logs, production secrets, employee records, or company-specific configurations.
6. Credit reused code and adhere to its license. Do not submit generated or copied material as your own work without review and attribution.

Project work is educational, with correctness and clear limitations prioritized over inflated claims.
