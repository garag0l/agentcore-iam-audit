# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **ACIA-006** (high): an agent execution role can mint workload access tokens for *other* agents' workload identities and call `GetResourceOauth2Token` / `GetResourceApiKey` with them, which pulls those agents' tool credentials from the token vault. This is the credential step in Zenity Labs' AgentCorruption chain. The pre-2025-12-09 starter-toolkit role is flagged; the current one is not.

## [0.1.2] - 2026-11-21

### Added
- Composite **GitHub Action** (`action.yml`): run the audit with
  `uses: garag0l/agentcore-iam-audit@v0.1.2` from a GAAD export, a single
  execution-role policy, or live AWS credentials. Inputs are passed through env
  vars (no template injection), and an end-to-end CI job runs the action against
  the committed fixtures.

### Changed
- Build: the package version is single-sourced from `__init__.py` (hatchling
  dynamic version), so it can no longer drift from the release tag.

## [0.1.1] - 2026-11-21

### Added
- Published to PyPI.

## [0.1.0] - 2026-11-21

### Added
- IAM evaluator (Allow/Deny, NotAction/NotResource, wildcards, permission boundaries, `iam:PassedToService`) with probe ARNs for resources a principal does not own.
- Checks ACIA-001..005 (cross-agent memory, runtime, code interpreter, image and identity-secret access), ACIA-010/011 (code-interpreter privilege escalation), ACIA-020 (starter-toolkit default roles), ACIA-021 (confused-deputy trust), ACIA-030 (live: PUBLIC-network code interpreters with roles).
- Offline (`--gaad`), live (`--live`, boto3) and single-policy (`--policy`) modes; text and JSON output.
