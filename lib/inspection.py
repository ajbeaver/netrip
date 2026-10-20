#!/usr/bin/python3
import ipaddress
import logging
import queue
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

SCAN_TIMEOUT = 300
PROGRESS_INTERVAL = 5

@dataclass(frozen=True)
class ServiceInfo:
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None

@dataclass(frozen=True)
class InspectionResult:
    address: ipaddress.IPv4Address
    status: str
    services: list[ServiceInfo]

class InspectionError(Exception):
    """Raised when targeted host inspection fails."""

def run_nmap(target: ipaddress.IPv4Address) -> str:
    """Run Nmap and report progress while preserving XML results."""
    with tempfile.TemporaryDirectory(prefix="netrip-") as temp_dir:
        xml_path = Path(temp_dir) / "scan.xml"
        command = [
            "nmap",
            "-sT",
            "-sV",
            "--stats-every", f"{PROGRESS_INTERVAL}s",
            "-oX", str(xml_path),
            str(target),
        ]

        logger.debug("Executing: %s", " ".join(command))
        messages = queue.Queue()
        started = time.monotonic()

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise InspectionError("Nmap is not installed") from exc
        except OSError as exc:
            raise InspectionError(f"Unable to start Nmap: {exc}") from exc

        def read_output():
            try:
                for line in process.stdout:
                    messages.put(line.rstrip())
            finally:
                process.stdout.close()
                messages.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()

        print(f"\n[SCAN] Inspecting {target}", flush=True)
        print("[SCAN] Starting TCP service discovery...", flush=True)

        output = []
        finished_reading = False
        last_update = started

        try:
            while not finished_reading or process.poll() is None:
                now = time.monotonic()
                elapsed = now - started

                if elapsed >= SCAN_TIMEOUT:
                    raise subprocess.TimeoutExpired(command, SCAN_TIMEOUT)

                try:
                    line = messages.get(timeout=0.5)
                except queue.Empty:
                    line = ""

                if line is None:
                    finished_reading = True
                    continue

                if line:
                    output.append(line)
                    logger.debug("Nmap: %s", line)

                    if line.startswith("Stats:"):
                        print(f"[SCAN] {line}", flush=True)
                        last_update = time.monotonic()
                    elif "Timing:" in line:
                        print(f"[SCAN] {line.strip()}", flush=True)
                        last_update = time.monotonic()

                now = time.monotonic()
                if now - last_update >= PROGRESS_INTERVAL:
                    elapsed = int(now - started)
                    print(
                        f"[SCAN] Running... {elapsed}s elapsed",
                        flush=True,
                    )
                    last_update = now

            reader.join(timeout=1)
            return_code = process.wait(timeout=5)

            if return_code != 0:
                details = "\n".join(output[-5:])
                raise InspectionError(
                    f"Nmap failed (exit {return_code}): {details}"
                )

            try:
                xml_output = xml_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise InspectionError(
                    f"Unable to read Nmap XML: {exc}"
                ) from exc

            elapsed = time.monotonic() - started
            print(f"[SCAN] Completed in {elapsed:.1f}s", flush=True)
            logger.debug("Received %d bytes of XML", len(xml_output))
            return xml_output

        except subprocess.TimeoutExpired as exc:
            raise InspectionError(
                f"Nmap inspection exceeded {SCAN_TIMEOUT}s"
            ) from exc
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            reader.join(timeout=1)

def parse_nmap_xml(
    xml_output: str,
    target: ipaddress.IPv4Address,
) -> InspectionResult:
    """Parse the target's status and open TCP services."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise InspectionError("Invalid Nmap XML output") from exc

    if root.tag != "nmaprun":
        raise InspectionError("Unexpected Nmap XML document")

    for host in root.findall("host"):
        addresses = [
            address.get("addr")
            for address in host.findall("address")
            if address.get("addrtype") == "ipv4"
        ]
        if str(target) not in addresses:
            continue

        status_element = host.find("status")
        status = (
            status_element.get("state", "unknown")
            if status_element is not None
            else "unknown"
        )

        services = []
        for port_element in host.findall("./ports/port"):
            protocol = port_element.get("protocol")
            if protocol != "tcp":
                continue

            try:
                port = int(port_element.get("portid", ""))
            except ValueError:
                logger.warning("Skipping invalid TCP port entry")
                continue

            if not 1 <= port <= 65535:
                logger.warning("Skipping out-of-range TCP port: %d", port)
                continue

            state_element = port_element.find("state")
            if state_element is None:
                continue

            state = state_element.get("state", "unknown")
            if state != "open":
                continue

            service_element = port_element.find("service")
            services.append(
                ServiceInfo(
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=(
                        service_element.get("name")
                        if service_element is not None
                        else None
                    ),
                    product=(
                        service_element.get("product")
                        if service_element is not None
                        else None
                    ),
                    version=(
                        service_element.get("version")
                        if service_element is not None
                        else None
                    ),
                )
            )

        services.sort(key=lambda item: item.port)
        logger.info(
            "Inspected %s: status=%s, open TCP ports=%d",
            target,
            status,
            len(services),
        )
        return InspectionResult(
            address=target,
            status=status,
            services=services,
        )

    raise InspectionError(
        f"Nmap returned no host record for target {target}"
    )

def inspect_host(target: ipaddress.IPv4Address) -> InspectionResult:
    """Inspect a validated IPv4 host and return its open services."""
    logger.info("Starting service inspection of %s", target)
    xml_output = run_nmap(target)
    result = parse_nmap_xml(xml_output, target)
    logger.debug("Service inspection completed successfully")
    return result
