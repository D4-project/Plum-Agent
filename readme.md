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

### Execution
python agent -d 

### Help
```bash
$ ./agent.py --help
usage: agent.py [-h] (-o | -d | -s) [-island ISLAND] [-agentkey AGENTKEY] [-ipext IPEXT]
                [-scanhours SCANHOURS] [-scanparallel SCANPARALLEL] [-v]

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
  -v, --verbose       Enable debug output
```
