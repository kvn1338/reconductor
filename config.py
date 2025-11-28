#!/usr/bin/env python3
"""
Configuration module for reconductor
Handles all configuration and default values
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration for the scanner"""

    # Input/Output
    targets_file: str
    output_dir: str = "scan_results"
    state_file: str = None  # Will be auto-generated if None

    # Scan mode options
    hosts_only: bool = False  # Stop after host discovery
    ports_only: bool = False  # Stop after port discovery (no service scan)

    # Parallelism
    max_nmap_workers: int = 1
    max_nuclei_workers: int = 1

    # Timeouts (in minutes)
    host_discovery_timeout: int = 30
    port_scan_timeout: int = 60
    service_scan_timeout: int = 60
    nuclei_timeout: int = 60

    # Nmap parameters
    top_ports: int = 1000
    min_rate: int = 500
    max_retries: int = 3

    # Host discovery parameters
    host_discovery_min_rate: int = 1000
    host_discovery_min_hostgroup: int = 512
    host_discovery_max_rtt_timeout: str = "200ms"

    # Service scan parameters
    version_intensity: int = 2

    # Resume mode
    resume: bool = False

    def __post_init__(self):
        """Initialize computed values and validate parameters"""
        if self.state_file is None:
            targets_basename = Path(self.targets_file).stem
            self.state_file = f"{self.output_dir}/{targets_basename}_state.json"

        # Validate scan mode flags
        if self.hosts_only and self.ports_only:
            raise ValueError("Cannot use both --hosts-only and --ports-only")

        # Validate output directory
        output_path = Path(self.output_dir)
        if output_path.exists() and not output_path.is_dir():
            raise ValueError(
                f"output_dir '{self.output_dir}' exists but is not a directory"
            )

        # Validate state file path
        state_path = Path(self.state_file)
        if state_path.exists() and not state_path.is_file():
            raise ValueError(f"state_file '{self.state_file}' exists but is not a file")

        # Ensure state file parent directory is valid
        state_parent = state_path.parent
        if state_parent.exists() and not state_parent.is_dir():
            raise ValueError(
                f"state_file parent path '{state_parent}' is not a directory"
            )

        # Validate parameters
        if not 1 <= self.max_nmap_workers <= 100:
            raise ValueError("max_nmap_workers must be between 1 and 100")
        if not 1 <= self.max_nuclei_workers <= 100:
            raise ValueError("max_nuclei_workers must be between 1 and 100")
        if not 1 <= self.host_discovery_timeout <= 1440:
            raise ValueError(
                "host_discovery_timeout must be between 1 and 1440 minutes"
            )
        if not 1 <= self.port_scan_timeout <= 1440:
            raise ValueError("port_scan_timeout must be between 1 and 1440 minutes")
        if not 1 <= self.service_scan_timeout <= 1440:
            raise ValueError("service_scan_timeout must be between 1 and 1440 minutes")
        if not 1 <= self.nuclei_timeout <= 1440:
            raise ValueError("nuclei_timeout must be between 1 and 1440 minutes")
        if not 1 <= self.top_ports <= 65535:
            raise ValueError("top_ports must be between 1 and 65535")
        if not 1 <= self.min_rate <= 100000:
            raise ValueError("min_rate must be between 1 and 100000")
        if not 1 <= self.host_discovery_min_rate <= 100000:
            raise ValueError("host_discovery_min_rate must be between 1 and 100000")
        if not 1 <= self.host_discovery_min_hostgroup <= 8192:
            raise ValueError("host_discovery_min_hostgroup must be between 1 and 8192")
        if not 0 <= self.version_intensity <= 9:
            raise ValueError("version_intensity must be between 0 and 9")

        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)


# Nmap command templates
NMAP_HOST_DISCOVERY_TEMPLATE = [
    "nmap",
    "-vvv",
    "-n",
    "-sn",
    "-PE",
    "-PM",
    "-PP",
    "--min-hostgroup",
    "{min_hostgroup}",
    "--min-rate",
    "{min_rate}",
    "--max-retries",
    "{max_retries}",
    "--max-rtt-timeout",
    "{max_rtt_timeout}",
    "-oA",
    "{output_base}",
    "{target}",
]

NMAP_PORT_DISCOVERY_TEMPLATE = [
    "nmap",
    "-n",
    "-Pn",
    "-sS",
    "--min-rate",
    "{min_rate}",
    "--max-retries",
    "{max_retries}",
    "--top-ports",
    "{top_ports}",
    "-oX",
    "{output_file}",
    "-iL",
    "{input_file}",
]

NMAP_SERVICE_SCAN_TEMPLATE = [
    "nmap",
    "-n",
    "-Pn",
    "-sV",
    "--version-intensity",
    "{version_intensity}",
    "-iL",
    "{input_file}",
    "-p",
    "{ports}",
    "-oA",
    "{output_base}",
]

NUCLEI_SCAN_TEMPLATE = [
    "nuclei",
    "-list",
    "{input_file}",
    "-markdown-export",
    "{markdown_dir}/",
    "-json-export",
    "{json_file}",
]

# Alternative: Use target URLs (IP:PORT) instead of just IPs
NUCLEI_SCAN_URLS_TEMPLATE = [
    "nuclei",
    "-list",
    "{urls_file}",
    "-markdown-export",
    "{markdown_dir}/",
    "-json-export",
    "{json_file}",
]
