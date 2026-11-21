# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-21

### Added
- Published to PyPI.

## [0.1.0] - 2026-11-21

### Added
- IAM evaluator (Allow/Deny, NotAction/NotResource, wildcards, permission boundaries, `iam:PassedToService`) with probe ARNs for resources a principal does not own.
- Checks ACIA-001..005 (cross-agent memory, runtime, code interpreter, image and identity-secret access), ACIA-010/011 (code-interpreter privilege escalation), ACIA-020 (starter-toolkit default roles), ACIA-021 (confused-deputy trust), ACIA-030 (live: PUBLIC-network code interpreters with roles).
- Offline (`--gaad`), live (`--live`, boto3) and single-policy (`--policy`) modes; text and JSON output.
