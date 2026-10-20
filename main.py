#!/usr/bin/python3
import argparse
import logging
import sys
from pathlib import Path
from lib.network import get_network_info, validate_target, NetworkError
from lib.discovery import discover_hosts, DiscoveryError
from lib.inventory import create_snapshot, save_snapshot, InventoryError
from lib.inspection import inspect_host, InspectionError

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "output" / "logs"
LOG_FILE = LOG_DIR / "netrip.log"
VERSION = "0.1.0"

def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

def banner():
    clear_screen()
    print("=== netrip ===")
    print("version:", VERSION, "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description="netrip - Network reconnaissance utility"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )
    parser.add_argument(
        "--inspect",
        metavar="IPv4",
        help="Inspect TCP services on a local IPv4 host"
    )
    return parser.parse_args()

def configure_logging(verbosity):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    levels = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
    }
    console_level = levels[min(verbosity, 3)]

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(console_level)

    log_file = logging.FileHandler(LOG_FILE)
    log_file.setLevel(logging.DEBUG)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[console, log_file],
    )

def redact_mac(mac):
    """Hide the device-specific portion of a MAC address."""
    if not mac:
        return "N/A"
    parts = mac.split(":")
    if len(parts) != 6 or any(
        len(part) != 2 or any(char not in "0123456789abcdefABCDEF" for char in part)
        for part in parts
    ):
        return "REDACTED"
    return ":".join(parts[:3] + ["XX"] * 3)

def print_hosts(hosts):
    """Display discovered hosts with partially redacted MAC addresses."""
    print(f"\nDiscovered {len(hosts)} active hosts\n")
    print(
        f"{'IPv4':<16} "
        f"{'Hostname':<28} "
        f"{'MAC Address':<18} "
        f"Manufacturer"
    )
    print("-" * 85)
    for host in sorted(hosts, key=lambda h: h.address):
        print(
            f"{str(host.address):<16} "
            f"{(host.hostname or 'Unknown'):<28.28} "
            f"{redact_mac(host.mac):<18} "
            f"{host.vendor or 'Unknown'}"
        )

def print_inspection(result):
    """Display open TCP services for a selected host."""
    print(f"\nInspection target : {result.address}")
    print(f"Host status       : {result.status}")
    print(f"Open TCP ports    : {len(result.services)}\n")

    if not result.services:
        print("No open TCP services detected.")
        return

    print(
        f"{'Port':<10} "
        f"{'State':<10} "
        f"{'Service':<18} "
        f"Product / Version"
    )
    print("-" * 75)

    for service in result.services:
        port = f"{service.port}/{service.protocol}"
        name = service.service or "Unknown"
        product = " ".join(
            part for part in (service.product, service.version) if part
        ) or "Unknown"

        print(
            f"{port:<10} "
            f"{service.state:<10} "
            f"{name:<18.18} "
            f"{product}"
        )

def main():
    args = parse_args()
    configure_logging(args.verbose)

    banner()
    logger.info("Starting netrip")
    logger.debug("Verbosity level: %d", args.verbose)

    try:
        network = get_network_info()
    except NetworkError as exc:
        logger.error("Network detection failed: %s", exc)
        return 1

    print(f"Interface : {network.interface}")
    print(f"Address   : {network.address}")
    print(f"Gateway   : {network.gateway}")
    print(f"Network   : {network.network}")

    if args.inspect is not None:
        try:
            target = validate_target(args.inspect, network)
        except NetworkError as exc:
            logger.error("Invalid inspection target: %s", exc)
            return 1

        try:
            result = inspect_host(target)
        except InspectionError as exc:
            logger.error("Host inspection failed: %s", exc)
            return 1

        print_inspection(result)
        logger.info("Host inspection completed")
        return 0

    logger.debug("Entering host discovery")

    try:
        hosts = discover_hosts(network)
    except DiscoveryError as exc:
        logger.error("Host discovery failed: %s", exc)
        return 1

    logger.debug("Discovery returned %d hosts", len(hosts))
    print_hosts(hosts)

    try:
        snapshot = create_snapshot(network, hosts)
        saved_path = save_snapshot(snapshot)
    except InventoryError as exc:
        logger.error("Inventory persistence failed: %s", exc)
        return 1

    logger.info("Inventory saved to %s", saved_path)
    logger.info("Network enumeration completed")
    return 0

if __name__ == "__main__":
    sys.exit(main())
