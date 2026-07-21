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

Before each scan starts, the agent logs a single `INFO` command preview capped at
132 characters. Longer commands end with a truncation marker containing the full
character count. With `-v/--verbose`, a separate `DEBUG` record contains the
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
  -v, --verbose       Enable debug output
```
