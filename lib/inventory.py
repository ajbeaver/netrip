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

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
SCAN_DIR = Path(__file__).resolve().parent.parent / "output" / "scans"

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
        "Created snapshot with %d hosts (schema v%d)",
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

        logger.info("Saved scan snapshot: %s", destination)
        return destination
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InventoryError(f"Unable to save snapshot: {exc}") from exc
