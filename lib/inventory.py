#!/usr/bin/python3
import json
import logging
import os
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from .network import NetworkInfo
from .discovery import DiscoveredHost
from .inspection import InspectionResult

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"
SCAN_DIR = OUTPUT_DIR / "scans"
INSPECTION_DIR = OUTPUT_DIR / "inspections"

class InventoryError(Exception):
    """Raised when inventory creation or persistence fails."""

def create_snapshot(
    network: NetworkInfo,
    hosts: list[DiscoveredHost],
) -> dict:
    """Create a serializable record of a completed network scan."""
    timestamp = datetime.now(timezone.utc)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp.isoformat(),
        "network": {
            "interface": network.interface,
            "address": str(network.address),
            "gateway": str(network.gateway),
            "subnet": str(network.network),
        },
        "discovery": {
            "method": "nmap-host-discovery",
            "host_count": len(hosts),
            "hosts": [
                {
                    **asdict(host),
                    "address": str(host.address),
                }
                for host in sorted(hosts, key=lambda h: h.address)
            ],
        },
    }
    logger.debug(
        "Created network snapshot with %d hosts (schema v%d)",
        len(hosts),
        SCHEMA_VERSION,
    )
    return snapshot

def save_snapshot(snapshot: dict, directory: Path = SCAN_DIR) -> Path:
    """Save a new JSON snapshot without overwriting existing files."""
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)

        timestamp = datetime.fromisoformat(snapshot["timestamp"])
        filename = timestamp.strftime("%Y-%m-%dT%H%M%S.%fZ")
        filename += f"-{secrets.token_hex(4)}.json"
        destination = directory / filename

        content = json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(content)

        logger.info("Saved snapshot: %s", destination)
        return destination
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InventoryError(f"Unable to save snapshot: {exc}") from exc

def create_inspection_snapshot(result: InspectionResult) -> dict:
    """Create a serializable record of a completed host inspection."""
    timestamp = datetime.now(timezone.utc)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "type": "host_inspection",
        "timestamp": timestamp.isoformat(),
        "target": {
            "address": str(result.address),
            "status": result.status,
        },
        "scan": {
            "method": "nmap-tcp-service-detection",
            "technique": "tcp-connect",
            "port_selection": "nmap-default-top-1000-tcp",
            "service_detection": True,
            "open_port_count": len(result.services),
            "services": [
                asdict(service)
                for service in sorted(result.services, key=lambda s: s.port)
            ],
        },
    }
    logger.debug(
        "Created inspection snapshot for %s with %d open ports",
        result.address,
        len(result.services),
    )
    return snapshot

def save_inspection_snapshot(snapshot: dict) -> Path:
    """Persist a host inspection under the restricted inspection directory."""
    if snapshot.get("type") != "host_inspection":
        raise InventoryError("Invalid inspection snapshot type")
    return save_snapshot(snapshot, directory=INSPECTION_DIR)
