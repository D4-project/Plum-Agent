# Release notes

- Add independent `nmap_scanparallel` and `masscan_scanparallel` limits,
  configurable with `-s --nmap-scanparallel N --masscan-scanparallel M`.
  `scanparallel` / `-scanparallel` provides the fallback per scanner (default 1),
  not a total ceiling. Explicit scanner limits always take priority.

- Skip unresolved Masscan hostnames with a warning and scan remaining targets.
  If none remain, submit an empty result instead of returning the job to the queue.

- Warn instead of aborting when a Masscan source IP is assigned to a kernel
  interface. Keep setup warnings visible with `-s` even when `debug: none`.

- Require nmap2json 2611.5. Nonzero response TTL values are excluded from
  host and port hashes.

- Report independently available Masscan IPv4 and IPv6 families and matching
  banner source addresses. Run family-specific jobs from Island after
  migrations 33 and 34.

- Use YAML verbosity by default. `-v` enables Nmap and Masscan process
  output, and `-vv` adds full debugging. Routine scanner progress uses
  debug logging and scanner failures remain errors.

- Require nmap2json 2611.4: mark only Masscan reports with `engine: masscan`.
  Nmap reports stay unchanged; engine metadata is excluded from content hashes.

- Report optional targeted-port totals when Island requests them. Count Masscan
  resolved target/port pairs and Nmap XML host/port metadata, including targets
  with no response. Keep older Island submissions unchanged.

- Preserve full received banners, consistent escapes and volatile-date hash
  masking through the published nmap2json 2611.4 dependency.

- Configure a dedicated Masscan banner source with --masscan-ip. Announce it at
  startup, warn about local kernel addresses, and require it for banner jobs.

- Add Masscan execution with startup discovery, Linux raw-socket capability
  checks, optional banner detection, local hostname resolution and Nmap-compatible
  JSON conversion. Announce Nmap/Masscan capabilities so Island dispatches only
  compatible jobs; existing UID and Nmap behavior remain unchanged.
- Preserve requested FQDNs and available PTR names in Masscan JSON only for
  resolved IPs with an open port. Skip PTR lookups for other resolved IPs.
- Reject missing or incompatible nmap2json installations at startup before
  registering the agent with Island.
- Use the UTC job receipt time when a Masscan report has no host start time.
- Use the legacy Nmap protocol on controllers that predate scanner capabilities.
- Return interrupted jobs to Island for complete retry and report a successful
  zero-byte Masscan result as an empty capture list.
- Verify built-in daily log rotation and configurable retention (`logrotation`, issue #6).
- Add DEBUG diagnostics for profile-field presence, type, option names, and agent version.
- Require Git at startup to report the agent tag or commit hash, with a clear
  installation error when Git is missing.
- Log a bounded Nmap command preview at `INFO` and the exact command at `DEBUG`.
- Support optional profile-level `nmap_additional_params` while preserving legacy
  job defaults and agent-managed scan arguments.
