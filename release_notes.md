# Release notes

- Verify built-in daily log rotation and configurable retention (`logrotation`, issue #6).
- Add DEBUG diagnostics for profile-field presence, type, option names, and agent version.
- Require Git at startup to report the agent tag or commit hash, with a clear
  installation error when Git is missing.
- Log a bounded Nmap command preview at `INFO` and the exact command at `DEBUG`.
- Support optional profile-level `nmap_additional_params` while preserving legacy
  job defaults and agent-managed scan arguments.
