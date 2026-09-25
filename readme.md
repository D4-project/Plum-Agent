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

### Agent supported
nmap

## Installation
Installation should stay simple.

### Setup
sudo apt-get install nmap  
git clone https://github.com/D4-project/Plum-Agent.git  
cd Plum-Agent  
python -m venv .venv  
source .venv/bin/activate  
pip install -r requirements.txt   

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

Choose the output mode in `src/config/config.yaml`:
```yaml
debug: none
```

`none` (default) logs the scan target, start, and completion without Nmap output.
`info` adds Nmap stdout/stderr and a shortened command preview. `debug` adds
DEBUG diagnostics, the full command, and verbose Nmap output (`-v` and
`-script-trace`). Use `-v` for info or `-vv` for debug on the command line;
either overrides the YAML mode for that invocation. Existing `debug: false`
and `debug: true` values still mean `none` and `debug` respectively.

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

Command records are unredacted. Do not place passwords, tokens, or other secrets in
Nmap arguments such as `--script-args`; `INFO` may expose their preview and
`DEBUG` exposes the complete command. Restrict access to the log directory and
configure `logrotation` to match the required retention period. Rolling back to a
release before this feature removes both records without changing scan behavior.

### Execution
python agent -d 

## Docker

### Quick start

```bash
cp .env.example .env          # fill in PLUM_ISLAND and PLUM_AGENT_KEY
docker compose up -d
```

The container runs the agent in daemon mode. Three named volumes persist state across restarts:

| Volume | Path inside container | Contents |
|--------|-----------------------|----------|
| `plum_config` | `/app/src/config` | Agent UUID and saved configuration |
| `plum_log` | `/app/src/log` | `agent.log` |
| `plum_nse_cache` | `/app/src/nse_cache` | Controller-managed NSE scripts |

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PLUM_ISLAND` | Yes | URL of the Plum-Island controller (e.g. `http://island:5000`) |
| `PLUM_AGENT_KEY` | Yes | API key issued by Plum-Island |
| `PLUM_EXT_IP` | No | Force the external IP reported to the controller (useful in air-gapped setups) |
| `PLUM_VERBOSE` | No | Set to `1` to enable debug output |

### Networking — connecting to Plum-Island

Plum-Agent and Plum-Island run as separate Docker Compose stacks and are therefore on isolated networks by default. A shared external network is required so the agent container can reach the Island webapp.

**One-time setup (run once on the host):**

```bash
docker network create plum_net
```

**Plum-Island** — add the network to its `docker-compose.yml`:

```yaml
services:
  webapp:
    networks:
      - plum_net
    # ... rest of service definition

networks:
  plum_net:
    external: true
```

**Plum-Agent** — already configured in this repo's `docker-compose.yml`. Set `PLUM_ISLAND` to the Island's service name on the shared network:

```bash
PLUM_ISLAND=http://webapp:5000
```

Then restart both stacks:

```bash
# in Plum-Island directory
docker compose up -d

# in Plum-Agent directory
docker compose up -d
```

### Capabilities

The container requests `NET_RAW` and `NET_ADMIN` so nmap can perform SYN scans.
These capabilities are declared in `docker-compose.yml` and are required for proper operation.

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
  -v, --verbose       -v: info, -vv: debug (overrides config)
```
