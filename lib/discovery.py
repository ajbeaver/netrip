#!/usr/bin/python3
import ipaddress
import logging
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from .network import NetworkInfo

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class DiscoveredHost:
    address: ipaddress.IPv4Address
    hostname: str | None
    mac: str | None
    vendor: str | None
    status: str

class DiscoveryError(Exception):
    """Raised when host discovery fails."""

def run_nmap(
    target: ipaddress.IPv4Network,
    dns_servers: list[ipaddress.IPv4Address] | None = None,
) -> str:
    """Run Nmap host discovery with optional reverse DNS resolution."""
    command = ["nmap", "-sn", "-R", "-oX", "-"]
    if dns_servers:
        command.extend([
            "--dns-servers",
            ",".join(str(server) for server in dns_servers),
        ])
    command.append(str(target))

    logger.debug("Executing: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )
        logger.debug(
            "Nmap completed successfully; received %d bytes",
            len(result.stdout),
        )
        return result.stdout
    except FileNotFoundError as exc:
        raise DiscoveryError("Nmap is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError("Nmap discovery timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise DiscoveryError(
            f"Nmap failed: {exc.stderr.strip()}"
        ) from exc

def parse_nmap_xml(xml_output: str) -> list[DiscoveredHost]:
    """Parse active IPv4 hosts from Nmap XML output."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise DiscoveryError("Invalid Nmap XML output") from exc

    if root.tag != "nmaprun":
        raise DiscoveryError("Unexpected Nmap XML document")

    hosts = []

    for host in root.findall("host"):
        status_element = host.find("status")
        if status_element is None:
            continue

        status = status_element.get("state", "unknown")
        if status != "up":
            continue

        ipv4 = None
        mac = None
        vendor = None
        hostname = None

        for item in host.findall("address"):
            address_type = item.get("addrtype")
            if address_type == "ipv4":
                ipv4 = item.get("addr")
            elif address_type == "mac":
                mac = item.get("addr")
                vendor = item.get("vendor")

        hostname_element = host.find("./hostnames/hostname")
        if hostname_element is not None:
            hostname = hostname_element.get("name")

        if not ipv4:
            logger.warning("Skipping active host without IPv4 address")
            continue

        try:
            address = ipaddress.IPv4Address(ipv4)
        except ipaddress.AddressValueError:
            logger.warning("Skipping host with invalid IPv4 address")
            continue

        hosts.append(
            DiscoveredHost(
                address=address,
                hostname=hostname,
                mac=mac,
                vendor=vendor,
                status=status,
            )
        )

    logger.info("Discovered %d active hosts", len(hosts))
    logger.debug(
        "Parsed metadata: %d MAC addresses, %d vendors, %d hostnames",
        sum(bool(host.mac) for host in hosts),
        sum(bool(host.vendor) for host in hosts),
        sum(bool(host.hostname) for host in hosts),
    )
    return hosts

def discover_hosts(
    network: NetworkInfo,
    dns_servers: list[ipaddress.IPv4Address] | None = None,
) -> list[DiscoveredHost]:
    """Discover active IPv4 hosts on the selected network."""
    logger.info("Starting host discovery on %s", network.network)

    # Use the explicitly supplied DNS servers, or the gateway by default.
    resolvers = dns_servers if dns_servers is not None else [network.gateway]

    logger.debug(
        "DNS resolvers: %s",
        ", ".join(str(server) for server in resolvers) or "system defaults",
    )

    xml_output = run_nmap(network.network, resolvers)
    hosts = parse_nmap_xml(xml_output)

    logger.debug("Host discovery completed successfully")
    return hosts
