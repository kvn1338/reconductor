#!/usr/bin/env python3
"""
Unit tests for state.py module
Tests state management, persistence, and stage transitions
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state import ScanStage, ScanState, TargetState


class TestScanStage(unittest.TestCase):
    """Test ScanStage enum"""

    def test_all_stages_exist(self):
        """Test that all expected stages are defined"""
        expected_stages = [
            "PENDING",
            "HOST_DISCOVERY",
            "HOST_DISCOVERY_COMPLETE",
            "NO_HOSTS_FOUND",
            "PORT_DISCOVERY",
            "PORT_DISCOVERY_COMPLETE",
            "NO_PORTS_FOUND",
            "SERVICE_SCAN",
            "SERVICE_SCAN_COMPLETE",
            "NUCLEI_SCAN",
            "NUCLEI_QUEUED",
            "NUCLEI_RUNNING",
            "NUCLEI_COMPLETE",
            "NUCLEI_FAILED",
            "COMPLETE",
            "COMPLETE_HOSTS_ONLY",
            "COMPLETE_PORTS_ONLY",
            "FAILED",
        ]
        for stage in expected_stages:
            with self.subTest(stage=stage):
                self.assertTrue(hasattr(ScanStage, stage), f"Missing stage: {stage}")

    def test_stage_values(self):
        """Test that stage values are lowercase with underscores"""
        for stage in ScanStage:
            self.assertEqual(
                stage.value, stage.name.lower(), f"Stage {stage.name} has wrong value"
            )


class TestTargetState(unittest.TestCase):
    """Test TargetState dataclass"""

    def test_create_minimal_target(self):
        """Test creating target with minimal required fields"""
        target = TargetState(
            target="192.168.1.0/24",
            stage=ScanStage.PENDING.value,
            directory="/tmp/test",
        )
        self.assertEqual(target.target, "192.168.1.0/24")
        self.assertEqual(target.stage, "pending")
        self.assertEqual(target.directory, "/tmp/test")

    def test_target_defaults(self):
        """Test that optional fields have correct defaults"""
        target = TargetState(
            target="10.0.0.1", stage=ScanStage.PENDING.value, directory="/tmp"
        )
        self.assertEqual(target.live_hosts, [])
        self.assertEqual(target.target_urls, [])
        self.assertIsNone(target.open_ports)
        self.assertIsNone(target.nuclei_status)
        self.assertIsNone(target.completed_at)
        self.assertIsNone(target.error)
        self.assertIsNotNone(target.started_at)  # Auto-set

    def test_target_to_dict(self):
        """Test converting target to dictionary"""
        target = TargetState(
            target="192.168.1.1", stage="pending", directory="/tmp/test"
        )
        d = target.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["target"], "192.168.1.1")
        self.assertEqual(d["stage"], "pending")

    def test_target_from_dict(self):
        """Test creating target from dictionary"""
        data = {
            "target": "10.0.0.1",
            "stage": "pending",
            "directory": "/tmp/test",
            "live_hosts": ["10.0.0.1"],
            "open_ports": "22,80,443",
            "target_urls": ["10.0.0.1:80"],
            "nuclei_status": None,
            "started_at": "2024-01-01T00:00:00",
            "completed_at": None,
            "error": None,
        }
        target = TargetState.from_dict(data)
        self.assertEqual(target.target, "10.0.0.1")
        self.assertEqual(target.live_hosts, ["10.0.0.1"])
        self.assertEqual(target.open_ports, "22,80,443")


class TestScanState(unittest.TestCase):
    """Test ScanState class"""

    def setUp(self):
        """Create temporary state file for each test"""
        self.test_dir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.test_dir, "test_state.json")

    def tearDown(self):
        """Clean up temporary files"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_new_state(self):
        """Test creating a new state instance"""
        state = ScanState(self.state_file)
        self.assertEqual(len(state.targets), 0)
        self.assertIsNotNone(state.metadata)
        self.assertIn("created_at", state.metadata)

    def test_add_target(self):
        """Test adding a target to state"""
        state = ScanState(self.state_file)
        state.add_target("192.168.1.0/24", "/tmp/test")

        self.assertEqual(len(state.targets), 1)
        self.assertIn("192.168.1.0/24", state.targets)
        target = state.targets["192.168.1.0/24"]
        self.assertEqual(target.stage, ScanStage.PENDING.value)

    def test_add_duplicate_target(self):
        """Test that adding duplicate target is handled"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test1")
        state.add_target("10.0.0.1", "/tmp/test2")

        # Should not duplicate
        self.assertEqual(len(state.targets), 1)

    def test_update_stage(self):
        """Test updating target stage"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        state.update_stage("10.0.0.1", ScanStage.HOST_DISCOVERY)
        target = state.targets["10.0.0.1"]
        self.assertEqual(target.stage, ScanStage.HOST_DISCOVERY.value)

    def test_set_live_hosts(self):
        """Test setting live hosts for a target"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.0/24", "/tmp/test")

        hosts = ["10.0.0.1", "10.0.0.10", "10.0.0.50"]
        state.set_live_hosts("10.0.0.0/24", hosts)

        target = state.targets["10.0.0.0/24"]
        self.assertEqual(target.live_hosts, hosts)

    def test_set_open_ports(self):
        """Test setting open ports for a target"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        state.set_open_ports("10.0.0.1", "22,80,443,3306")
        target = state.targets["10.0.0.1"]
        self.assertEqual(target.open_ports, "22,80,443,3306")

    def test_set_target_urls(self):
        """Test setting target URLs for nuclei"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        urls = ["10.0.0.1:80", "10.0.0.1:443", "10.0.0.1:8080"]
        state.set_target_urls("10.0.0.1", urls)

        target = state.targets["10.0.0.1"]
        self.assertEqual(target.target_urls, urls)

    def test_set_nuclei_status(self):
        """Test setting nuclei status"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        state.set_nuclei_status("10.0.0.1", ScanStage.NUCLEI_RUNNING.value)
        target = state.targets["10.0.0.1"]
        self.assertEqual(target.nuclei_status, "nuclei_running")

    def test_mark_queued_dequeued(self):
        """Test queue tracking"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        # Initially not queued
        self.assertNotIn("10.0.0.1", state._queued_targets)

        # Mark as queued
        state.mark_queued("10.0.0.1")
        self.assertIn("10.0.0.1", state._queued_targets)

        # Mark as dequeued
        state.mark_dequeued("10.0.0.1")
        self.assertNotIn("10.0.0.1", state._queued_targets)

    def test_get_targets_by_stage(self):
        """Test getting targets by stage"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")
        state.add_target("target3", "/tmp/test3")

        state.update_stage("target2", ScanStage.HOST_DISCOVERY)
        state.update_stage("target3", ScanStage.HOST_DISCOVERY)

        pending = state.get_targets_by_stage(ScanStage.PENDING)
        discovering = state.get_targets_by_stage(ScanStage.HOST_DISCOVERY)

        self.assertEqual(len(pending), 1)
        self.assertIn("target1", pending)
        self.assertEqual(len(discovering), 2)
        self.assertIn("target2", discovering)
        self.assertIn("target3", discovering)

    def test_get_targets_ready_for_stage_host_discovery(self):
        """Test getting targets ready for host discovery"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")

        ready = state.get_targets_ready_for_stage(ScanStage.HOST_DISCOVERY)
        self.assertEqual(len(ready), 2)

    def test_get_targets_ready_for_stage_port_discovery(self):
        """Test getting targets ready for port discovery"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")

        state.update_stage("target1", ScanStage.HOST_DISCOVERY_COMPLETE)

        ready = state.get_targets_ready_for_stage(ScanStage.PORT_DISCOVERY)
        self.assertEqual(len(ready), 1)
        self.assertIn("target1", ready)

    def test_get_targets_ready_for_nuclei(self):
        """Test getting targets ready for nuclei scan"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")
        state.add_target("target3", "/tmp/test3")

        # target1: service scan complete, no nuclei status
        state.update_stage("target1", ScanStage.SERVICE_SCAN_COMPLETE)

        # target2: service scan complete, but nuclei already running
        state.update_stage("target2", ScanStage.SERVICE_SCAN_COMPLETE)
        state.set_nuclei_status("target2", ScanStage.NUCLEI_RUNNING.value)

        # target3: still in service scan
        state.update_stage("target3", ScanStage.SERVICE_SCAN)

        ready = state.get_targets_ready_for_stage(ScanStage.NUCLEI_SCAN)

        # Only target1 should be ready (service complete + no nuclei status)
        self.assertEqual(len(ready), 1)
        self.assertIn("target1", ready)

    def test_prevent_duplicate_queuing(self):
        """Test that queued targets are not returned again"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test")

        # First call: target is ready
        ready = state.get_targets_ready_for_stage(ScanStage.HOST_DISCOVERY)
        self.assertEqual(len(ready), 1)

        # Mark as queued
        state.mark_queued("target1")

        # Second call: should not return queued target
        ready = state.get_targets_ready_for_stage(ScanStage.HOST_DISCOVERY)
        self.assertEqual(len(ready), 0)

    def test_get_incomplete_targets(self):
        """Test getting incomplete targets"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")
        state.add_target("target3", "/tmp/test3")

        state.update_stage("target2", ScanStage.COMPLETE)

        incomplete = state.get_incomplete_targets()
        self.assertEqual(len(incomplete), 2)
        self.assertIn("target1", incomplete)
        self.assertIn("target3", incomplete)

    def test_is_target_complete(self):
        """Test checking if target is complete"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test")

        # Initially not complete
        self.assertFalse(state.is_target_complete("target1"))

        # Mark as complete
        state.update_stage("target1", ScanStage.COMPLETE)
        self.assertTrue(state.is_target_complete("target1"))

    def test_terminal_stages(self):
        """Test that terminal stages are recognized as complete"""
        state = ScanState(self.state_file)
        terminal_stages = [
            ScanStage.COMPLETE,
            ScanStage.COMPLETE_HOSTS_ONLY,
            ScanStage.COMPLETE_PORTS_ONLY,
            ScanStage.FAILED,
            ScanStage.NO_HOSTS_FOUND,
            ScanStage.NO_PORTS_FOUND,
        ]

        for stage in terminal_stages:
            with self.subTest(stage=stage):
                target = f"target_{stage.value}"
                state.add_target(target, "/tmp/test")
                state.update_stage(target, stage)
                self.assertTrue(state.is_target_complete(target))

    def test_get_statistics(self):
        """Test getting state statistics"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test1")
        state.add_target("target2", "/tmp/test2")
        state.add_target("target3", "/tmp/test3")

        state.update_stage("target1", ScanStage.COMPLETE)
        state.update_stage("target2", ScanStage.FAILED)
        state.update_stage("target3", ScanStage.HOST_DISCOVERY)

        stats = state.get_statistics()

        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["completed"], 1)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["in_progress"], 1)

    def test_save_state(self):
        """Test saving state to file"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")
        state.update_stage("10.0.0.1", ScanStage.HOST_DISCOVERY_COMPLETE)
        state.set_live_hosts("10.0.0.1", ["10.0.0.1"])

        state.save()

        # Verify file exists
        self.assertTrue(os.path.exists(self.state_file))

        # Verify JSON is valid
        with open(self.state_file, "r") as f:
            data = json.load(f)

        self.assertIn("metadata", data)
        self.assertIn("targets", data)
        self.assertIn("10.0.0.1", data["targets"])

    def test_load_state(self):
        """Test loading state from file"""
        # Create initial state
        state1 = ScanState(self.state_file)
        state1.add_target("10.0.0.1", "/tmp/test")
        state1.update_stage("10.0.0.1", ScanStage.HOST_DISCOVERY_COMPLETE)
        state1.set_live_hosts("10.0.0.1", ["10.0.0.1"])
        state1.save()

        # Load state in new instance
        state2 = ScanState(self.state_file)

        # Verify data was loaded
        self.assertEqual(len(state2.targets), 1)
        self.assertIn("10.0.0.1", state2.targets)
        target = state2.targets["10.0.0.1"]
        self.assertEqual(target.stage, "host_discovery_complete")
        self.assertEqual(target.live_hosts, ["10.0.0.1"])

    def test_atomic_save(self):
        """Test that save is atomic (uses temp file)"""
        state = ScanState(self.state_file)
        state.add_target("test", "/tmp/test")

        # Save multiple times rapidly
        for i in range(10):
            state.update_stage("test", ScanStage.HOST_DISCOVERY)
            state.save()

        # File should still be valid
        state2 = ScanState(self.state_file)
        self.assertEqual(len(state2.targets), 1)

    def test_stage_index_rebuild(self):
        """Test that stage index is rebuilt on load"""
        state1 = ScanState(self.state_file)
        state1.add_target("target1", "/tmp/test1")
        state1.add_target("target2", "/tmp/test2")
        state1.update_stage("target1", ScanStage.HOST_DISCOVERY)
        state1.save()

        # Load in new instance
        state2 = ScanState(self.state_file)

        # Stage index should work
        discovering = state2.get_targets_by_stage(ScanStage.HOST_DISCOVERY)
        self.assertEqual(len(discovering), 1)
        self.assertIn("target1", discovering)

    def test_update_stage_with_error(self):
        """Test updating stage with error message"""
        state = ScanState(self.state_file)
        state.add_target("target1", "/tmp/test")

        state.update_stage("target1", ScanStage.FAILED, error="Connection timeout")

        target = state.targets["target1"]
        self.assertEqual(target.stage, "failed")
        self.assertEqual(target.error, "Connection timeout")

    def test_get_target_state(self):
        """Test getting target state"""
        state = ScanState(self.state_file)
        state.add_target("10.0.0.1", "/tmp/test")

        target = state.get_target_state("10.0.0.1")
        self.assertIsNotNone(target)
        self.assertEqual(target.target, "10.0.0.1")

        # Non-existent target
        target = state.get_target_state("nonexistent")
        self.assertIsNone(target)

    def test_multiple_targets_workflow(self):
        """Test a realistic workflow with multiple targets"""
        state = ScanState(self.state_file)

        # Add multiple targets
        targets = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]
        for target in targets:
            state.add_target(target, f"/tmp/{target.replace('/', '_')}")

        # Simulate scan progression
        for target in targets:
            # Host discovery
            state.update_stage(target, ScanStage.HOST_DISCOVERY)
            state.update_stage(target, ScanStage.HOST_DISCOVERY_COMPLETE)
            state.set_live_hosts(target, [f"{target.split('/')[0]}"])

            # Port discovery
            state.update_stage(target, ScanStage.PORT_DISCOVERY)
            state.update_stage(target, ScanStage.PORT_DISCOVERY_COMPLETE)
            state.set_open_ports(target, "22,80,443")

            # Service scan
            state.update_stage(target, ScanStage.SERVICE_SCAN)
            state.update_stage(target, ScanStage.SERVICE_SCAN_COMPLETE)

            # Complete
            state.update_stage(target, ScanStage.COMPLETE)

        # Verify all complete
        stats = state.get_statistics()
        self.assertEqual(stats["completed"], 3)
        self.assertEqual(stats["in_progress"], 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions"""

    def setUp(self):
        """Create temporary state file for each test"""
        self.test_dir = tempfile.mkdtemp()
        self.state_file = os.path.join(self.test_dir, "test_state.json")

    def tearDown(self):
        """Clean up temporary files"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_corrupted_state_file(self):
        """Test loading corrupted state file"""
        # Write invalid JSON
        with open(self.state_file, "w") as f:
            f.write("not valid json {{{")

        # Should create new state instead of crashing
        state = ScanState(self.state_file)
        self.assertEqual(len(state.targets), 0)

    def test_empty_state_file(self):
        """Test loading empty state file"""
        # Create empty file
        Path(self.state_file).touch()

        state = ScanState(self.state_file)
        self.assertEqual(len(state.targets), 0)

    def test_update_nonexistent_target(self):
        """Test updating nonexistent target"""
        state = ScanState(self.state_file)

        # Should not crash
        state.update_stage("nonexistent", ScanStage.COMPLETE)
        state.set_live_hosts("nonexistent", ["1.2.3.4"])
        state.set_open_ports("nonexistent", "80")

    def test_very_large_target_list(self):
        """Test handling many targets"""
        state = ScanState(self.state_file)

        # Add 1000 targets
        for i in range(1000):
            state.add_target(f"10.0.{i // 256}.{i % 256}", f"/tmp/test{i}")

        self.assertEqual(len(state.targets), 1000)

        # Test that lookups are still fast
        ready = state.get_targets_ready_for_stage(ScanStage.HOST_DISCOVERY)
        self.assertEqual(len(ready), 1000)


if __name__ == "__main__":
    unittest.main()
