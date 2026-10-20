# netrip

A lightweight, Python-based network enumeration tool for Linux. Uses Nmap to discover local IPv4 hosts and collect available hostnames, MAC addresses, and vendors.

## Requirements

- Python 3.10+
- Nmap
- Linux `ip` utility (`iproute2`)

## Usage

```bash
sudo python3 main.py
sudo python3 main.py -vvv
```

Verbosity: `-v` warnings, `-vv` informational messages, `-vvv` debug output. Without a flag, only errors appear in the console; the log file retains debug output.

## Project structure

```text
main.py             CLI and logging
lib/network.py      Local interface, gateway, and subnet detection
lib/discovery.py    Nmap host discovery and reverse DNS
lib/inventory.py    JSON scan snapshots
output/             Logs and scans (Git-ignored)
```

## Output and security

- Displays host details with the last three MAC address octets masked.
- Saves timestamped JSON snapshots under `output/scans/` containing **full** device identifiers.
- Writes diagnostic logs to `output/logs/netrip.log`.
- Restricts new snapshot files to `0600` and the scan directory to `0700`. Running under `sudo` typically makes these files root-owned.

Only scan networks you own or are authorized to assess. Network and DNS detection currently assume one usable default IPv4 route; reverse DNS uses the detected gateway as the resolver.
