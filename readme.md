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
usage: agent.py [-h] (-o | -d | -s) [-island ISLAND] [-agentkey AGENTKEY] [-ipext IPEXT] [-v]

Plum Discovery Agent

options:
  -h, --help          show this help message and exit
  -o, --once          Run Once
  -d, --daemon        Run Endlessly
  -s, --setup         Setup configuration only
  -island ISLAND      Hostname or IP of the Plum Island controller
  -agentkey AGENTKEY  Agent Key
  -ipext IPEXT        Force External IP
  -v, --verbose       Enable debug output
```
