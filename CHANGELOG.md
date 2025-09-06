# Changelog

All notable changes to DepGuard Lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-09-06

### Added
- Initial release of DepGuard Lite
- Multi-format dependency parsing (requirements.txt, pyproject.toml, poetry.lock, package.json, etc.)
- OSV API integration for vulnerability detection
- CVSS scoring and severity classification
- License detection and risk analysis
- GPL/copyleft license flagging
- Markdown, JSON, HTML, CSV, and SARIF report formats
- Vulnerability caching with TTL
- PR comment formatting
- CLI with Typer and Rich output

### Security
- Rate limiting for OSV API calls
- Graceful handling of API timeouts and errors
