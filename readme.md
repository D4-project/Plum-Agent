<div align="center">
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_logo.png"   style="width:25%;" />

<h1> Proactive Land Uncovering & Monitoring</h1><h1>Pathogen Agent</h1>
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_overview.png" />
</div>
<p>
<center>
*Beta version*
</center>
</p>

## Description
This this tool is the working agent designed to work with Plum-Island

## Technical requirements
Python 3.10 or >
Git installed at runtime and a Git checkout, so the agent can report its tag or
commit hash.

### Supported scanners

Configure the dedicated banner source with `python src/agent.py -s --masscan-ip ADDRESS`.
Reserve an unused address on the local subnet outside the kernel's interfaces.
The agent checks its format and local assignment. The operator must verify that
the address is unused and reachable on the network. Restart the agent to announce
it to Island. Clear it with `--masscan-ip ""`. Masscan uses `--source-ip` for banner
jobs, which must use the same address family. Without this setting, the agent
receives Masscan port checks only. No firewall configuration is required by Plum.

Nmap and Masscan. At startup, the agent enables every supported executable found
on `PATH` unless it is explicitly disabled in the configuration. It exits before
requesting work when no scanner remains available.

With an Island version that predates Masscan support, the agent uses Nmap only.
Nmap must be installed and enabled in the agent configuration. Restart the agent
after upgrading Island so it can detect the new scanner protocol.

## Installation
Installation should stay simple.

### Setup
sudo apt-get install nmap masscan
git clone https://github.com/D4-project/Plum-Agent.git  
cd Plum-Agent  
python -m venv .venv  
source .venv/bin/activate  
pip install -r requirements.txt   

Run the agent as a normal service account. Masscan needs raw-socket access on
Linux; grant it to the executable instead of running the whole agent as root:

```bash
sudo setcap cap_net_raw=eip /usr/bin/masscan
getcap /usr/bin/masscan
```

The agent verifies this at startup and prints the command for the executable it
actually found when the capability is missing.

### nmap2json dependency

Plum-Agent and current Plum-Island require `nmap2json>=2611.4`. The agent checks
this minimum version and the hostname conversion API before registering or
requesting jobs. Version 2611.4 is published on PyPI. Install the requirements
in the agent virtual environment:

```bash
python -m pip install -r requirements.txt
python -m pip check
```

Versions older than 2611.4 do not meet this minimum. Preserve complete received
banners; existing Nmap truncation cannot be reversed. Masscan's FTP parser removes
carriage returns before producing XML; retain its output without adding bytes.
Island derives the standard `banner` and observed `http-headers` fields for
search and tagging. Volatile protocol clocks are masked only before hashing.
Existing historical hashes are not migrated automatically.

### Scan activity counters

Updated Island job responses request `report_target_count: true`. The agent then
reports `PORTS_TARGETED` with the completed result, including nonresponding targets.
Masscan counts the union of its already resolved targets and requested TCP ports;
Nmap uses the XML host total and scaninfo port counts. These are intended
IP/transport/port pairs, not packet counts. No extra DNS lookup or scan is issued.
Missing Nmap metadata or an unsuccessful Nmap exit leaves the count unknown.
The optional field is omitted for older controllers, preserving compatibility.
Restart the agent after updating its code. Older agents keep working with a new
Island: completed jobs and open ports are counted, while targeted ports show unknown.

### Configuration
cd src  
python agent.py -s -island *HOSTOFISLAND* -agentkey *XXXTHETOKENKEYXXXX* 

Optional GMT scan window:
```yaml
scanhours: 14-16
```

Or from the command line:
```bash
python agent.py -s -scanhours 14-16
```

Optional parallel scan jobs:
```yaml
scanparallel: 4
```

Or from the command line:
```bash
python agent.py -s -scanparallel 4
```

Optional daily log retention:
```yaml
logrotation: 30
```

Or from the command line:
```bash
python agent.py -s -logrotation 30
```

Installed tools are enabled by default. Disable one without changing the agent
identity or UID:

```yaml
nmap_disabled: true
# masscan_disabled: true
```

Masscan defaults to 1,000 packets per second. The local operator may change the
limit without changing profiles on Island:

```yaml
masscan_rate: 5000
```

With Masscan enabled, the agent resolves hostname jobs locally, scans every
distinct returned address and converts Masscan XML through `nmap2json`. The
profile's **Detect protocol** option adds `--banners`; without it, Masscan only
reports port state. Interrupted jobs are returned to Island and restart from the
beginning on the next compatible agent.

Choose the output mode in `src/config/config.yaml`:
```yaml
debug: none
```

`none` (default) logs errors only. `info` adds job summaries and a shortened
command preview. `debug` adds scanner output, full commands, Nmap script traces
and agent diagnostics. On the command line, `-v` shows agent status, errors and
Nmap and Masscan process output. `-vv` enables full debug. Both options override the
YAML mode. Existing `debug: false` and `debug: true` values still select `none`
and `debug` respectively.

### Profile-level Nmap parameters

Queued jobs may include optional `nmap_additional_params`, for example:

```json
{"nmap_additional_params": "--min-hostgroup 32 --host-timeout 5m"}
```

The agent tokenizes this string with shell-style quoting, then passes each token
directly to Nmap as an argv item. It never invokes a shell. Values are limited to
4096 characters. Shell-control syntax, the `--` option terminator, malformed
quoting, and parameters that replace agent-managed ports, XML output, or NSE
selection are rejected before Nmap starts.

Profile values override matching agent defaults. Both `--option value` and
`--option=value` forms are supported. Missing, `null`, and empty values retain the
agent defaults, so jobs from older Plum-Island versions remain compatible. Removing
the field from a profile rolls behavior back to those defaults. Updated
Plum-Island responses remain compatible with older agents because the field is
additive.

### Nmap command logging

In info and debug modes, before each scan starts, the agent logs an `INFO`
command preview capped at 132 characters. Longer commands end with a truncation marker containing the full
character count. When debug is enabled, a separate `DEBUG` record contains the
complete executable and final argv. Arguments use shell-safe quoting for
reproduction, but the scan still executes the original argv list without invoking
a shell. Both records include the shortened job UID so commands remain attributable
during parallel scans.

When debug is enabled, troubleshooting diagnostics also report active
`APP_VERSION`, whether `nmap_additional_params` reached the agent, its type,
and parsed option names. Raw profile values are excluded from these diagnostics.
A missing field means legacy defaults are expected; a present field with defaults
still active indicates payload shape, queue, or deployment-version mismatch.

Command records are unredacted. Do not place passwords, tokens, or other secrets in
Nmap arguments such as `--script-args`; `INFO` may expose their preview and
`DEBUG` exposes the complete command. Restrict access to the log directory and
configure `logrotation` to match the required retention period. Rolling back to a
release before this feature removes both records without changing scan behavior.

### Execution
python agent -d 

### Help
```bash
$ ./agent.py --help
usage: agent.py [-h] (-o | -d | -s) [-island ISLAND] [-agentkey AGENTKEY] [-ipext IPEXT]
                [-scanhours SCANHOURS] [-scanparallel SCANPARALLEL]
                [-logrotation LOGROTATION] [-v]

Plum Discovery Agent

options:
  -h, --help          show this help message and exit
  -o, --once          Run Once
  -d, --daemon        Run Endlessly
  -s, --setup         Setup configuration only
  -island ISLAND      Hostname or IP of the Plum Island controller
  -agentkey AGENTKEY  Agent Key
  -ipext IPEXT        Force External IP
  -scanhours SCANHOURS
                      GMT scan window in HH-HH format, example 14-16
  -scanparallel SCANPARALLEL
                      Maximum scan jobs to run in parallel, 0 for standby
  -logrotation LOGROTATION
                      Daily log retention in days, default 30
  -v, --verbose       -v: scanner output, -vv: full debug (overrides config)
```

Masscan host reports carry `"engine": "masscan"` through nmap2json 2611.4.
Nmap output is unchanged. Island searches `engine:masscan` / `engine:nmap`;
unmarked reports default to Nmap, without migrating or rewriting history.
Engine provenance does not change deduplication hashes.

Nmap is deliberately not marked because it is the historical default: explicitly
marking it would require a backfill and redundant index memberships for millions
of existing reports. Island searches Nmap as candidate UIDs minus marked Masscan
UIDs, with no engine migration or history rewrite. Historical Masscan reports
without a marker are also considered Nmap by this rule.
