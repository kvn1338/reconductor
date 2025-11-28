#!/usr/bin/env python3
"""
Utility functions for reconductor
Handles IP validation, subnet splitting, network operations, and command execution
"""

import asyncio
import ipaddress
import os
import re
import xml.etree.ElementTree as ET
from typing import List, Tuple


def is_valid_target(target: str) -> bool:
    """
    Validate if the input is a valid IP address or CIDR subnet.
    Checks that octets are in range 0-255 and properly formatted.

    Args:
        target: IP address or CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        True if valid, False otherwise
    """
    # Check basic format first
    ip_regex = r"^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$"
    if not re.match(ip_regex, target):
        return False

    # Extract IP part (before any CIDR notation)
    ip_part = target.split("/")[0]

    # Validate each octet is in range 0-255
    octets = ip_part.split(".")
    for octet in octets:
        # Check for empty or invalid octets
        if not octet or len(octet) == 0:
            return False

        # Check for leading zeros (except "0" itself)
        if len(octet) > 1 and octet[0] == "0":
            return False

        try:
            octet_int = int(octet)
            if octet_int > 255:
                return False
        except ValueError:
            return False

    return True


def sanitize_target_name(target: str) -> str:
    """
    Sanitize target to create a valid directory name.
    Replace '.' with '_' and '/' with '-'
    Remove any potential shell metacharacters for safety

    Args:
        target: IP network string

    Returns:
        Sanitized string safe for use as directory name
    """
    # First do basic replacements
    sanitized = target.replace(".", "_").replace("/", "-")

    # Remove or replace any shell metacharacters
    # Keep only alphanumeric, underscore, and hyphen
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)

    return sanitized


def split_into_24_subnets(target: str) -> List[str]:
    """
    Split a target network into /24 subnets.

    If the target is larger than /24 (e.g., /16, /20), split it into multiple /24s.
    If the target is already /24 or smaller, return it as-is.

    Args:
        target: IP network string (e.g., "10.0.0.0/16" or "192.168.1.0/24")

    Returns:
        List of network strings, each /24 or the original if already /24 or smaller

    Examples:
        "10.0.0.0/16" -> ["10.0.0.0/24", "10.0.1.0/24", ..., "10.0.255.0/24"] (256 subnets)
        "10.0.0.0/20" -> ["10.0.0.0/24", "10.0.1.0/24", ..., "10.0.15.0/24"] (16 subnets)
        "10.0.0.0/24" -> ["10.0.0.0/24"] (unchanged)
        "10.0.0.0/25" -> ["10.0.0.0/25"] (unchanged, smaller than /24)
    """
    try:
        network = ipaddress.IPv4Network(target, strict=False)

        # If prefix is /24 or larger (smaller subnet), return as-is
        if network.prefixlen >= 24:
            return [str(network)]

        # Split into /24 subnets
        subnets_24 = list(network.subnets(new_prefix=24))
        return [str(subnet) for subnet in subnets_24]

    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        print(f"Error parsing network '{target}': {e}")
        return []


def extract_live_hosts(gnmap_file: str) -> List[str]:
    """
    Extract live host IPs from nmap gnmap output file.

    Args:
        gnmap_file: Path to the .gnmap file

    Returns:
        List of IP addresses that are up
    """
    try:
        with open(gnmap_file, "r") as f:
            live_hosts = [line.split()[1] for line in f if "Status: Up" in line]
        return live_hosts
    except FileNotFoundError:
        print(f"Error: Could not find {gnmap_file}")
        return []
    except Exception as e:
        print(f"Error extracting live hosts from {gnmap_file}: {e}")
        return []


def extract_open_ports_from_xml(xml_file: str) -> str:
    """
    Extract open ports from nmap XML output and return as comma-separated string.

    Equivalent to: cat open-ports.xml | grep portid | grep open | cut -d '"' -f 4 | sort -nu | paste -sd ","

    Args:
        xml_file: Path to the nmap XML output file

    Returns:
        Comma-separated string of unique port numbers, or empty string if none found
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        ports = set()
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                portid = port.get("portid")
                if portid:
                    ports.add(int(portid))

        if ports:
            # Sort and return as comma-separated string
            return ",".join(str(p) for p in sorted(ports))
        return ""

    except FileNotFoundError:
        print(f"Error: Could not find {xml_file}")
        return ""
    except ET.ParseError as e:
        print(f"Error parsing XML file {xml_file}: {e}")
        return ""
    except Exception as e:
        print(f"Error extracting ports from {xml_file}: {e}")
        return ""


def extract_ip_port_combinations_from_xml(xml_file: str) -> List[str]:
    """
    Extract IP:PORT combinations from nmap XML output for nuclei targeting.

    Args:
        xml_file: Path to the nmap XML output file

    Returns:
        List of strings in format "IP:PORT" (e.g., ["192.168.1.1:80", "192.168.1.1:443"])
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        targets = []

        # Iterate through each host
        for host in root.findall(".//host"):
            # Get the IP address
            address_elem = host.find(".//address[@addrtype='ipv4']")
            if address_elem is None:
                continue
            ip = address_elem.get("addr")
            if not ip:
                continue

            # Get all open ports for this host
            ports = host.findall(".//port")
            for port in ports:
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    portid = port.get("portid")
                    if portid:
                        targets.append(f"{ip}:{portid}")

        return targets

    except FileNotFoundError:
        print(f"Error: Could not find {xml_file}")
        return []
    except ET.ParseError as e:
        print(f"Error parsing XML file {xml_file}: {e}")
        return []
    except Exception as e:
        print(f"Error extracting IP:PORT from {xml_file}: {e}")
        return []


async def run_command(
    cmd: List[str], cwd: str = None, timeout: int = None, output_prefix: str = ""
) -> Tuple[int, bool]:
    """
    Run a shell command asynchronously and return the return code.
    Streams output in real-time with optional prefix.

    Args:
        cmd: Command and arguments as list
        cwd: Working directory
        timeout: Timeout in seconds (None for no timeout)
        output_prefix: Prefix to add to each output line (e.g., target name)

    Returns:
        Tuple of (return_code, timed_out)
    """
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
        )

        # Stream output in real-time with overall timeout for the entire command
        async def stream_output():
            try:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    output = line.decode().rstrip()
                    if output_prefix:
                        print(f"[{output_prefix}] {output}")
                    else:
                        print(output)
            except Exception as e:
                print(f"Error reading output: {e}")
                raise

        try:
            # Apply timeout to entire command execution, not per-line
            await asyncio.wait_for(
                asyncio.gather(stream_output(), process.wait()), timeout=timeout
            )
            return process.returncode, False

        except asyncio.TimeoutError:
            timeout_min = timeout // 60 if timeout else 0
            print(f"\n⚠️  Command timed out after {timeout_min}min, terminating...")
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=10)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
            return -1, True

    except Exception as e:
        print(f"Error running command: {e}")
        return -1, False

    finally:
        # Ensure process is cleaned up if still running
        if process is not None and process.returncode is None:
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass  # Best effort cleanup


def check_root_privileges() -> bool:
    """
    Check if running with sufficient privileges for SYN scan.

    Returns:
        True if running as root, False otherwise
    """
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root!")
        print("   SYN scan (-sS) requires root/sudo privileges.")
        print(
            "   nmap will fall back to TCP connect scan (-sT) which is slower and more detectable."
        )
        print()
        return False
    return True


def format_command(template: List[str], **kwargs) -> List[str]:
    """
    Format a command template with provided arguments.

    Args:
        template: Command template with {placeholder} strings
        **kwargs: Values to substitute into placeholders

    Returns:
        Formatted command as list
    """
    return [arg.format(**kwargs) for arg in template]


def save_list_to_file(items: List[str], filepath: str) -> bool:
    """
    Save a list of strings to a file, one per line.

    Args:
        items: List of strings to save
        filepath: Path to output file

    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, "w") as f:
            f.write("\n".join(items) + "\n")
        return True
    except Exception as e:
        print(f"Error saving to {filepath}: {e}")
        return False


def print_header(message: str, char: str = "=", width: int = 60):
    """
    Print a formatted header.

    Args:
        message: Header text
        char: Character to use for the border
        width: Width of the header
    """
    print(char * width)
    print(message)
    print(char * width)
