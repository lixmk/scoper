# Scoper: A script for hostname enumeration
## Usage
scoper.py is designed to enumerate hostnames for in-scope IP addresses. It uses several different methods to do so:
* Nmap reverse DNS lookup
* Masscan port 443 then carves Cnames and subjectAltNames
* Bing IP Search
* Crt.sh certificate transperency
* Fierce DNS scanner

Each method can be turned on individually with the appropriate switch, or `-a` can be used to enable all. All output is saved to a directory. Primarily inscope-hostnames.txt, and inscope-ips.txt.
### Arguements
* `-i`, `--filein`: File with IP Addresses, accepts many formats
* `-d`, `--domains`: Additional domain to search. Not required
* `-n`, `--nmap`: Executes Nmap Reverse DNS lookup. Not required
* `-m`, `--mass`: Executes masscan for port 443 against all IPs, then pulls names from SSL certs. Not required
* `-b`, `--bing`: Bing IP search against each IP. Can take a while for a lot of IPs. Results are either great or terrible. Not required
* `-c`, `--crtsh`: Searches crt.sh (certificate transparency) for all previously identified base domains. Pretty quick with decent results. Not required
* `-f`, `--fierce`: Executes fierce DNS bruteforcer against all previously identified base domains. This can take a while. Results can be worth it though. Not required.
* `-t`, `--timeout`: Change default socket timeout. Defaults to 10. Not sure this is working right. Not required.
* `-o`, `--outdir`: Output directory to create. Default `./scoper/`. Not required.
* `-a`, `--execall`: Executes all tests. Same as -n -m -b -c -f. Not required.

## Installation & Requirements
scoper.py relies on two external tools, masscan and fierce. These can be installed with apt-get:
```
apt-get update && apt-get -y install fierce masscan python-libnmap
```
All scripts use Python 2.7. Python requirements can be installed with:
```
pip install -r requirements.txt
```
One of the requirements installed with the above command is python-masscan. python-masscan, but default, prints a debug message for each time a scan is initated. It's very annoying. I've included a patch to disable the debug messages and keep output clean. Additionally, an older version is used because the latest version (at the time of testing) wasn't building.
```
patch -b /usr/local/lib/python2.7/dist-packages/masscan/masscan.py ./files/masscan.diff
```
