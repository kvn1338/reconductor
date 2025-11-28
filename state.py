#!/usr/bin/env python3
"""
State management module for reconductor
Tracks scan progress and enables resumability
"""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set


class ScanStage(Enum):
    """Stages of scanning for a target"""

    PENDING = "pending"
    HOST_DISCOVERY = "host_discovery"
    HOST_DISCOVERY_COMPLETE = "host_discovery_complete"
    NO_HOSTS_FOUND = "no_hosts_found"
    PORT_DISCOVERY = "port_discovery"
    PORT_DISCOVERY_COMPLETE = "port_discovery_complete"
    NO_PORTS_FOUND = "no_ports_found"
    SERVICE_SCAN = "service_scan"
    SERVICE_SCAN_COMPLETE = "service_scan_complete"
    NUCLEI_SCAN = "nuclei_scan"  # Logical stage for queuing nuclei scans
    NUCLEI_QUEUED = "nuclei_queued"
    NUCLEI_RUNNING = "nuclei_running"
    NUCLEI_COMPLETE = "nuclei_complete"
    NUCLEI_FAILED = "nuclei_failed"
    COMPLETE = "complete"
    COMPLETE_HOSTS_ONLY = "complete_hosts_only"  # Completed in hosts-only mode
    COMPLETE_PORTS_ONLY = "complete_ports_only"  # Completed in ports-only mode
    FAILED = "failed"


@dataclass
class TargetState:
    """State information for a single target"""

    target: str
    stage: str
    directory: str
    live_hosts: List[str] = None
    open_ports: str = None  # Comma-separated port list
    target_urls: List[str] = None  # IP:PORT combinations for nuclei
    nuclei_status: str = None  # Track nuclei separately
    started_at: str = None
    completed_at: str = None
    error: str = None

    def __post_init__(self):
        if self.live_hosts is None:
            self.live_hosts = []
        if self.target_urls is None:
            self.target_urls = []
        if self.started_at is None:
            self.started_at = datetime.utcnow().isoformat()

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        """Create from dictionary"""
        return cls(**data)


class ScanState:
    """Manages the state of all targets in a scan"""

    def __init__(self, state_file: str):
        self.state_file = state_file
        self.targets: Dict[str, TargetState] = {}
        self.metadata = {
            "created_at": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat(),
            "version": "1.0",
        }
        # Stage index for O(1) lookups instead of O(n) scans
        self._stage_index: Dict[str, Set[str]] = {}
        self._queued_targets: Set[str] = set()  # Track what's been queued
        self._load_if_exists()
        self._rebuild_stage_index()

    def _load_if_exists(self):
        """Load state from file if it exists"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    self.metadata = data.get("metadata", self.metadata)
                    targets_data = data.get("targets", {})
                    self.targets = {
                        target: TargetState.from_dict(state)
                        for target, state in targets_data.items()
                    }
                print(f"Loaded state from {self.state_file}")
                print(f"  Total targets: {len(self.targets)}")
            except Exception as e:
                print(f"Warning: Could not load state file: {e}")
                print("Starting with fresh state")

    def _rebuild_stage_index(self):
        """Rebuild the stage index from current targets"""
        self._stage_index.clear()
        for target, state in self.targets.items():
            stage = state.stage
            if stage not in self._stage_index:
                self._stage_index[stage] = set()
            self._stage_index[stage].add(target)

    def save(self):
        """Save state to file"""
        try:
            self.metadata["last_updated"] = datetime.utcnow().isoformat()
            data = {
                "metadata": self.metadata,
                "targets": {
                    target: state.to_dict() for target, state in self.targets.items()
                },
            }
            # Write to temp file first, then rename (atomic operation)
            temp_file = f"{self.state_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(temp_file, self.state_file)
        except Exception as e:
            print(f"Error saving state: {e}")

    def add_target(self, target: str, directory: str):
        """Add a new target to track"""
        if target not in self.targets:
            stage = ScanStage.PENDING.value
            self.targets[target] = TargetState(
                target=target,
                stage=stage,
                directory=directory,
            )
            # Update index
            if stage not in self._stage_index:
                self._stage_index[stage] = set()
            self._stage_index[stage].add(target)
            self.save()

    def update_stage(self, target: str, stage: ScanStage, error: str = None):
        """Update the stage of a target"""
        if target in self.targets:
            # Update stage index
            old_stage = self.targets[target].stage
            if old_stage in self._stage_index:
                self._stage_index[old_stage].discard(target)
            if stage.value not in self._stage_index:
                self._stage_index[stage.value] = set()
            self._stage_index[stage.value].add(target)

            # Update target state
            self.targets[target].stage = stage.value
            if error:
                self.targets[target].error = error
            if stage in [
                ScanStage.COMPLETE,
                ScanStage.FAILED,
                ScanStage.NO_HOSTS_FOUND,
                ScanStage.NO_PORTS_FOUND,
            ]:
                self.targets[target].completed_at = datetime.utcnow().isoformat()
            self.save()

    def set_live_hosts(self, target: str, hosts: List[str]):
        """Set the list of live hosts for a target"""
        if target in self.targets:
            self.targets[target].live_hosts = hosts
            self.save()

    def set_open_ports(self, target: str, ports: str):
        """Set the open ports for a target"""
        if target in self.targets:
            self.targets[target].open_ports = ports
            self.save()

    def set_target_urls(self, target: str, urls: List[str]):
        """Set the IP:PORT combinations for nuclei targeting"""
        if target in self.targets:
            self.targets[target].target_urls = urls
            self.save()

    def set_nuclei_status(self, target: str, status: str):
        """Set the nuclei status for a target"""
        if target in self.targets:
            self.targets[target].nuclei_status = status
            self.save()

    def get_targets_by_stage(self, stage: ScanStage) -> List[str]:
        """Get all targets currently at a specific stage (O(1) with index)"""
        return list(self._stage_index.get(stage.value, set()))

    def get_targets_ready_for_stage(self, stage: ScanStage) -> List[str]:
        """Get targets that are ready to proceed to a specific stage and haven't been queued yet"""
        ready = []
        if stage == ScanStage.HOST_DISCOVERY:
            ready = self.get_targets_by_stage(ScanStage.PENDING)
        elif stage == ScanStage.PORT_DISCOVERY:
            ready = self.get_targets_by_stage(ScanStage.HOST_DISCOVERY_COMPLETE)
        elif stage == ScanStage.SERVICE_SCAN:
            ready = self.get_targets_by_stage(ScanStage.PORT_DISCOVERY_COMPLETE)
        elif stage == ScanStage.NUCLEI_SCAN:
            # Nuclei runs AFTER service scan completes to avoid interference
            # Running nuclei during nmap -sV causes timing issues and false negatives
            # Only queue targets that have finished service scan and haven't started nuclei
            service_complete = self.get_targets_by_stage(
                ScanStage.SERVICE_SCAN_COMPLETE
            )
            ready = [
                t for t in service_complete if self.targets[t].nuclei_status is None
            ]

        # Filter out already-queued targets to prevent duplicates
        return [t for t in ready if t not in self._queued_targets]

    def mark_queued(self, target: str):
        """Mark a target as queued to prevent duplicate queueing"""
        self._queued_targets.add(target)

    def mark_dequeued(self, target: str):
        """Mark a target as dequeued (processing started)"""
        self._queued_targets.discard(target)

    def is_target_complete(self, target: str) -> bool:
        """Check if a target is truly complete (all stages including nuclei)"""
        if target not in self.targets:
            return False

        state = self.targets[target]
        stage = state.stage

        # Terminal stages
        if stage in [
            ScanStage.COMPLETE.value,
            ScanStage.COMPLETE_HOSTS_ONLY.value,
            ScanStage.COMPLETE_PORTS_ONLY.value,
            ScanStage.FAILED.value,
            ScanStage.NO_HOSTS_FOUND.value,
            ScanStage.NO_PORTS_FOUND.value,
        ]:
            return True

        # For service scan complete, check if nuclei is also done
        if stage == ScanStage.SERVICE_SCAN_COMPLETE.value:
            nuclei_status = state.nuclei_status
            if nuclei_status in [
                ScanStage.NUCLEI_COMPLETE.value,
                ScanStage.NUCLEI_FAILED.value,
                None,
            ]:
                return True

        return False

    def get_target_state(self, target: str) -> Optional[TargetState]:
        """Get the state of a specific target"""
        return self.targets.get(target)

    def get_incomplete_targets(self) -> List[str]:
        """Get all targets that haven't completed successfully"""
        return [
            target
            for target in self.targets.keys()
            if not self.is_target_complete(target)
        ]

    def get_statistics(self) -> Dict:
        """Get statistics about the scan state"""
        stats = {
            "total": len(self.targets),
            "by_stage": {},
            "completed": 0,
            "failed": 0,
            "no_hosts": 0,
            "no_ports": 0,
            "in_progress": 0,
            "nuclei_status": {},
        }

        for state in self.targets.values():
            stage = state.stage
            stats["by_stage"][stage] = stats["by_stage"].get(stage, 0) + 1

            if stage in [
                ScanStage.COMPLETE.value,
                ScanStage.COMPLETE_HOSTS_ONLY.value,
                ScanStage.COMPLETE_PORTS_ONLY.value,
            ]:
                stats["completed"] += 1
            elif stage == ScanStage.FAILED.value:
                stats["failed"] += 1
            elif stage == ScanStage.NO_HOSTS_FOUND.value:
                stats["no_hosts"] += 1
            elif stage == ScanStage.NO_PORTS_FOUND.value:
                stats["no_ports"] += 1
            elif stage != ScanStage.PENDING.value:
                stats["in_progress"] += 1

            # Track nuclei status separately
            if state.nuclei_status:
                stats["nuclei_status"][state.nuclei_status] = (
                    stats["nuclei_status"].get(state.nuclei_status, 0) + 1
                )

        return stats

    def print_summary(self):
        """Print a summary of the scan state"""
        stats = self.get_statistics()
        print("\n" + "=" * 60)
        print("SCAN STATE SUMMARY")
        print("=" * 60)
        print(f"Total targets: {stats['total']}")
        print(f"Completed: {stats['completed']}")
        print(f"Failed: {stats['failed']}")
        print(f"No hosts found: {stats['no_hosts']}")
        print(f"No ports found: {stats['no_ports']}")
        print(f"In progress: {stats['in_progress']}")
        print(f"Pending: {stats['by_stage'].get(ScanStage.PENDING.value, 0)}")
        print("\nStage breakdown:")
        for stage, count in sorted(stats["by_stage"].items()):
            print(f"  {stage}: {count}")
        if stats["nuclei_status"]:
            print("\nNuclei status:")
            for status, count in sorted(stats["nuclei_status"].items()):
                print(f"  {status}: {count}")
        print("=" * 60 + "\n")

    def get_scan_summary(self) -> Dict:
        """
        Get detailed scan summary with host/port counts and timing.

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            "total_targets": len(self.targets),
            "total_hosts": 0,
            "total_ports": 0,
            "hosts_with_ports": 0,
            "duration": None,
            "start_time": None,
            "end_time": None,
        }

        # Count hosts and ports
        for target_state in self.targets.values():
            if target_state.live_hosts:
                summary["total_hosts"] += len(target_state.live_hosts)

            if target_state.open_ports:
                # Count ports (format: "22,80,443")
                port_count = len(target_state.open_ports.split(","))
                summary["total_ports"] += port_count
                summary["hosts_with_ports"] += 1

        # Calculate duration
        if self.metadata.get("created_at"):
            from datetime import datetime

            try:
                start = datetime.fromisoformat(self.metadata["created_at"])
                summary["start_time"] = start

                if self.metadata.get("last_updated"):
                    end = datetime.fromisoformat(self.metadata["last_updated"])
                    summary["end_time"] = end
                    summary["duration"] = (end - start).total_seconds()
            except:
                pass

        return summary

    def print_scan_summary(self):
        """Print detailed scan summary with host/port counts"""
        summary = self.get_scan_summary()
        stats = self.get_statistics()

        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Scanned {summary['total_targets']} target(s)")
        print(f"Found {summary['total_hosts']} live host(s)")
        print(
            f"Found {summary['total_ports']} open port(s) across {summary['hosts_with_ports']} host(s)"
        )

        if summary["duration"] is not None:
            duration_min = int(summary["duration"] / 60)
            duration_sec = int(summary["duration"] % 60)
            print(f"Duration: {duration_min}m {duration_sec}s")

        print(
            f"\nResults: ✅ {stats['completed']} complete | "
            f"❌ {stats['failed']} failed | "
            f"⚠️  {stats['no_hosts']} no hosts | "
            f"⚠️  {stats['no_ports']} no ports"
        )
        print("=" * 70 + "\n")
