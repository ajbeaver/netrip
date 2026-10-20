#!/usr/bin/python3
import json
import logging
import subprocess
import ipaddress
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    address: ipaddress.IPv4Address
    gateway: ipaddress.IPv4Address
    network: ipaddress.IPv4Network

class NetworkError(Exception):
    """Raised when network configuration cannot be determined."""

def run_ip_command(*args):
    """Execute iproute2 and return its JSON output."""
    command = ["ip", "-j", "-4", *args]
    logger.debug("Executing: %s", " ".join(command))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return json.loads(result.stdout)
    except FileNotFoundError as exc:
        raise NetworkError("ip utility not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise NetworkError("ip command timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise NetworkError(
            f"ip command failed: {exc.stderr.strip()}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise NetworkError("Invalid JSON returned by ip") from exc

def get_network_info():
    """Discover the default IPv4 network configuration."""
    logger.info("Detecting local network configuration")
    routes = run_ip_command("route", "show", "default")
    routes = [
        route for route in routes
        if route.get("dst") == "default"
        and route.get("gateway")
        and route.get("dev")
    ]
    if not routes:
        raise NetworkError("No usable default IPv4 route found")
    if len(routes) > 1:
        raise NetworkError(
            "Multiple default IPv4 routes found; automatic selection is ambiguous"
        )

    route = routes[0]
    interface = route["dev"]
    gateway = ipaddress.IPv4Address(route["gateway"])

    logger.debug("Default interface: %s", interface)
    logger.debug("Default gateway: %s", gateway)

    addresses = run_ip_command("address", "show", "dev", interface)
    candidates = []
    for device in addresses:
        for address in device.get("addr_info", []):
            if address.get("family") == "inet":
                candidates.append(address)

    if len(candidates) != 1:
        raise NetworkError(
            f"Expected one IPv4 address on {interface}, found {len(candidates)}"
        )

    address = candidates[0]
    ipv4_interface = ipaddress.IPv4Interface(
        f"{address['local']}/{address['prefixlen']}"
    )

    info = NetworkInfo(
        interface=interface,
        address=ipv4_interface.ip,
        gateway=gateway,
        network=ipv4_interface.network,
    )

    logger.info("Interface: %s", info.interface)
    logger.info("Address: %s", info.address)
    logger.info("Gateway: %s", info.gateway)
    logger.info("Network: %s", info.network)
    return info

def validate_target(target: str, network: NetworkInfo) -> ipaddress.IPv4Address:
    """Validate an explicit IPv4 host within the detected local network."""
    logger.debug("Validating inspection target: %s", target)

    try:
        address = ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError as exc:
        raise NetworkError(
            f"Invalid IPv4 target: {target}"
        ) from exc

    if not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise NetworkError(
            f"Unsupported inspection address: {address}"
        )

    if address not in network.network:
        raise NetworkError(
            f"Target {address} is outside local network {network.network}"
        )

    if network.network.prefixlen <= 30:
        if address in (network.network.network_address, network.network.broadcast_address):
            raise NetworkError(
                f"Target {address} is a network or broadcast address"
            )

    logger.info("Validated inspection target: %s", address)
    return address
