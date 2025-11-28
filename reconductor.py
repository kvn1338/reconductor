#!/usr/bin/env python3
"""
reconductor - Network Reconnaissance Conductor
A modular, queue-based scanner using nmap and nuclei with automatic state management and resumability.

Usage:
    sudo ./reconductor.py targets.txt
    sudo ./reconductor.py --max-nmap 2 --max-nuclei 2 --top-ports 1000 targets.txt
    sudo ./reconductor.py --resume --output-dir results targets.txt
"""

import argparse
import asyncio
import sys
from pathlib import Path

from config import ScanConfig
from scanner import ScanOrchestrator
from state import ScanState
from utils import (
    check_root_privileges,
    is_valid_target,
    print_header,
    sanitize_target_name,
    split_into_24_subnets,
)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="reconductor - Network reconnaissance conductor with nmap and nuclei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo %(prog)s targets.txt
  sudo %(prog)s --max-nmap 2 --max-nuclei 2 --top-ports 1000 targets.txt
  sudo %(prog)s --resume --output-dir results targets.txt
  sudo %(prog)s --timeout 120 --top-ports 576 targets.txt

Notes:
  - Requires root/sudo for SYN scans (-sS)
  - Automatically splits subnets larger than /24 into /24 chunks
  - State is automatically saved for resumability
  - Top ports: 576 covers ~90%% of services, 1000 is default
  - See https://nmap.org/book/performance-port-selection.html
        """,
    )

    # Required arguments
    parser.add_argument(
        "targets_file",
        help="File containing one IP address or subnet per line",
    )

    # Output options
    parser.add_argument(
        "--output-dir",
        "-o",
        default="scan_results",
        help="Directory to store scan results (default: scan_results)",
    )

    # Parallelism options
    parser.add_argument(
        "--max-nmap",
        type=int,
        default=1,
        help="Maximum concurrent nmap workers (default: 1)",
    )
    parser.add_argument(
        "--max-nuclei",
        type=int,
        default=1,
        help="Maximum concurrent nuclei workers (default: 1)",
    )

    # Timeout options (in minutes)
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in minutes for service scans (default: 60)",
    )
    parser.add_argument(
        "--host-timeout",
        type=int,
        default=30,
        help="Timeout in minutes for host discovery (default: 30)",
    )
    parser.add_argument(
        "--nuclei-timeout",
        type=int,
        default=60,
        help="Timeout in minutes for nuclei scans (default: 60)",
    )

    # Scan options
    parser.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        help="Number of top ports to scan (default: 1000). Note: 576 covers ~90%% of services",
    )
    parser.add_argument(
        "--min-rate",
        type=int,
        default=500,
        help="Minimum packet rate for port/service scans (default: 500)",
    )
    parser.add_argument(
        "--host-min-rate",
        type=int,
        default=1000,
        help="Minimum packet rate for host discovery (default: 1000)",
    )
    parser.add_argument(
        "--version-intensity",
        type=int,
        default=2,
        choices=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        help="nmap version detection intensity 0-9 (default: 2)",
    )

    # Resume option
    parser.add_argument(
        "--resume",
        "-r",
        action="store_true",
        help="Resume from previous state (load state file and continue incomplete scans)",
    )

    # Advanced options
    parser.add_argument(
        "--no-split",
        action="store_true",
        help="Don't split larger subnets into /24 chunks (not recommended)",
    )

    args = parser.parse_args()

    # Validation
    if args.max_nmap < 1:
        parser.error("--max-nmap must be at least 1")
    if args.max_nuclei < 1:
        parser.error("--max-nuclei must be at least 1")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 minute")
    if args.top_ports < 1:
        parser.error("--top-ports must be at least 1")

    return args


def load_targets(targets_file: str, split_subnets: bool = True) -> list:
    """
    Load and process targets from file.

    Args:
        targets_file: Path to targets file
        split_subnets: Whether to split large subnets into /24s

    Returns:
        List of target strings
    """
    if not Path(targets_file).exists():
        print(f"Error: Targets file '{targets_file}' not found")
        sys.exit(1)

    raw_targets = []
    with open(targets_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # Skip empty lines and comments
                raw_targets.append(line)

    if not raw_targets:
        print(f"Error: No targets found in '{targets_file}'")
        sys.exit(1)

    print(f"Loaded {len(raw_targets)} target(s) from {targets_file}")

    if not split_subnets:
        return raw_targets

    # Split into /24 subnets
    print("\nSplitting targets into /24 subnets...")
    expanded_targets = []

    for target in raw_targets:
        if not is_valid_target(target):
            print(f"  ⚠️  Skipping invalid target: {target}")
            continue

        subnets = split_into_24_subnets(target)
        if not subnets:
            print(f"  ⚠️  Could not parse target: {target}")
            continue

        if len(subnets) == 1:
            print(f"  ✓ {target}")
        else:
            print(f"  ✓ {target} → {len(subnets)} /24 subnets")
        expanded_targets.extend(subnets)

    print(f"\nTotal subnets to scan: {len(expanded_targets)}")
    return expanded_targets


def initialize_state(config: ScanConfig, targets: list) -> ScanState:
    """
    Initialize or load scan state.

    Args:
        config: Scan configuration
        targets: List of targets to scan

    Returns:
        ScanState object
    """
    state = ScanState(config.state_file)

    if config.resume:
        print(f"\nResume mode: Loading state from {config.state_file}")
        state.print_summary()

        # Add any new targets that aren't in the state
        existing_targets = set(state.targets.keys())
        new_targets = [t for t in targets if t not in existing_targets]

        if new_targets:
            print(f"\nFound {len(new_targets)} new target(s) not in previous state")
            for target in new_targets:
                directory = f"{config.output_dir}/{sanitize_target_name(target)}"
                Path(directory).mkdir(parents=True, exist_ok=True)
                state.add_target(target, directory)
    else:
        print("\nInitializing fresh scan state...")
        # Add all targets to state
        for target in targets:
            directory = f"{config.output_dir}/{sanitize_target_name(target)}"
            Path(directory).mkdir(parents=True, exist_ok=True)
            state.add_target(target, directory)

        print(f"Added {len(targets)} target(s) to scan queue")

    return state


async def main():
    """Main entry point"""
    print_header("reconductor - Network Reconnaissance Conductor", char="=", width=70)

    args = parse_arguments()

    # Check for root privileges
    if not check_root_privileges():
        response = input("Continue without root privileges? [y/N] ")
        if response.lower() not in ["y", "yes"]:
            print("Exiting...")
            sys.exit(0)
        print()

    # Load targets
    targets = load_targets(args.targets_file, split_subnets=not args.no_split)

    if not targets:
        print("Error: No valid targets to scan")
        sys.exit(1)

    # Create configuration
    config = ScanConfig(
        targets_file=args.targets_file,
        output_dir=args.output_dir,
        max_nmap_workers=args.max_nmap,
        max_nuclei_workers=args.max_nuclei,
        host_discovery_timeout=args.host_timeout,
        port_scan_timeout=args.timeout,
        service_scan_timeout=args.timeout,
        nuclei_timeout=args.nuclei_timeout,
        top_ports=args.top_ports,
        min_rate=args.min_rate,
        host_discovery_min_rate=args.host_min_rate,
        version_intensity=args.version_intensity,
        resume=args.resume,
    )

    # Initialize state
    state = initialize_state(config, targets)

    # Print configuration
    print_header("Scan Configuration", char="-", width=70)
    print(f"Output directory: {config.output_dir}")
    print(f"State file: {config.state_file}")
    print(
        f"Workers: {config.max_nmap_workers} nmap + {config.max_nuclei_workers} nuclei"
    )
    print(f"Top ports: {config.top_ports}")
    print(
        f"Timeouts: host={args.host_timeout}min, scan={args.timeout}min, nuclei={args.nuclei_timeout}min"
    )
    print(
        f"Min rates: host={config.host_discovery_min_rate}pps, scan={config.min_rate}pps"
    )
    print("-" * 70)
    print()

    # Create and start orchestrator
    orchestrator = ScanOrchestrator(config, state)

    print_header("Starting Scan", char="=", width=70)
    print()

    try:
        await orchestrator.start()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user (Ctrl+C)")
        print("State has been saved. You can resume with --resume flag")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Print final summary
    print()
    print_header("Scan Complete", char="=", width=70)
    state.print_summary()

    stats = state.get_statistics()
    if stats["failed"] > 0:
        print(f"\n⚠️  {stats['failed']} target(s) failed. Check logs for details.")
        sys.exit(1)
    else:
        print("\n✅ All targets scanned successfully!")
        sys.exit(0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(130)
