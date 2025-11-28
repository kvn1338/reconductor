#!/usr/bin/env python3
"""
Scanner module for reconductor
Implements queue-based parallel scanning with nmap and nuclei
"""

import asyncio
from pathlib import Path
from typing import List

from config import (
    NMAP_HOST_DISCOVERY_TEMPLATE,
    NMAP_PORT_DISCOVERY_TEMPLATE,
    NMAP_SERVICE_SCAN_TEMPLATE,
    NUCLEI_SCAN_TEMPLATE,
    ScanConfig,
)
from state import ScanStage, ScanState
from utils import (
    extract_ip_port_combinations_from_xml,
    extract_live_hosts,
    extract_open_ports_from_xml,
    format_command,
    print_header,
    run_command,
    save_list_to_file,
)


class ScanWorker:
    """Base class for scan workers"""

    def __init__(self, worker_id: int, config: ScanConfig, state: ScanState):
        self.worker_id = worker_id
        self.config = config
        self.state = state
        self.active = True

    async def run(self, queue: asyncio.Queue):
        """Main worker loop - override in subclasses"""
        raise NotImplementedError


class NmapWorker(ScanWorker):
    """Worker for nmap scans (host discovery, port discovery, service scan)"""

    async def run(self, queue: asyncio.Queue):
        """Process nmap tasks from the queue"""
        print(f"[NmapWorker-{self.worker_id}] Started")

        while self.active:
            try:
                # Get task from queue with timeout
                task = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # Check if queue is empty and no more tasks are coming
                if queue.empty():
                    await asyncio.sleep(1)
                continue

            try:
                target = task["target"]
                stage = task["stage"]

                # Mark as dequeued now that we're processing
                self.state.mark_dequeued(target)

                if stage == "host_discovery":
                    await self._do_host_discovery(target)
                elif stage == "port_discovery":
                    await self._do_port_discovery(target)
                elif stage == "service_scan":
                    await self._do_service_scan(target)

            except Exception as e:
                print(f"[NmapWorker-{self.worker_id}] Error processing {target}: {e}")
                self.state.update_stage(target, ScanStage.FAILED, error=str(e))
            finally:
                queue.task_done()

        print(f"[NmapWorker-{self.worker_id}] Stopped")

    async def _do_host_discovery(self, target: str):
        """Perform host discovery scan"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            print(f"[NmapWorker-{self.worker_id}] Target {target} not found in state")
            return

        print_header(f"[{target}] Host Discovery", char="-", width=50)
        self.state.update_stage(target, ScanStage.HOST_DISCOVERY)

        directory = target_state.directory
        output_base = f"{directory}/hosts"

        cmd = format_command(
            NMAP_HOST_DISCOVERY_TEMPLATE,
            min_hostgroup=self.config.host_discovery_min_hostgroup,
            min_rate=self.config.host_discovery_min_rate,
            max_retries=self.config.max_retries,
            max_rtt_timeout=self.config.host_discovery_max_rtt_timeout,
            output_base=output_base,
            target=target,
        )

        timeout = self.config.host_discovery_timeout * 60  # Convert to seconds
        ret, timed_out = await run_command(cmd, timeout=timeout, output_prefix=target)

        if ret != 0:
            error_msg = "timed out" if timed_out else f"exit code {ret}"
            print(f"[{target}] Host discovery failed: {error_msg}")
            self.state.update_stage(
                target, ScanStage.FAILED, error=f"Host discovery {error_msg}"
            )
            return

        # Extract live hosts
        gnmap_file = f"{output_base}.gnmap"
        live_hosts = extract_live_hosts(gnmap_file)

        if not live_hosts:
            print(f"[{target}] No live hosts found")
            self.state.set_live_hosts(target, [])
            self.state.update_stage(target, ScanStage.NO_HOSTS_FOUND)
            return

        print(f"[{target}] Found {len(live_hosts)} live host(s)")

        # Save live hosts to file
        ips_file = f"{directory}/ips.txt"
        if not save_list_to_file(live_hosts, ips_file):
            self.state.update_stage(
                target, ScanStage.FAILED, error="Could not save live hosts"
            )
            return

        self.state.set_live_hosts(target, live_hosts)
        self.state.update_stage(target, ScanStage.HOST_DISCOVERY_COMPLETE)
        print(f"[{target}] Host discovery complete")

    async def _do_port_discovery(self, target: str):
        """Perform port discovery scan (fast, no version detection)"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            return

        if not target_state.live_hosts:
            print(f"[{target}] No live hosts, skipping port discovery")
            self.state.update_stage(target, ScanStage.NO_HOSTS_FOUND)
            return

        print_header(f"[{target}] Port Discovery", char="-", width=50)
        self.state.update_stage(target, ScanStage.PORT_DISCOVERY)

        directory = target_state.directory
        ips_file = f"{directory}/ips.txt"
        output_file = f"{directory}/open-ports.xml"

        cmd = format_command(
            NMAP_PORT_DISCOVERY_TEMPLATE,
            min_rate=self.config.min_rate,
            max_retries=self.config.max_retries,
            top_ports=self.config.top_ports,
            output_file=output_file,
            input_file=ips_file,
        )

        timeout = self.config.port_scan_timeout * 60
        ret, timed_out = await run_command(cmd, timeout=timeout, output_prefix=target)

        if ret != 0:
            error_msg = "timed out" if timed_out else f"exit code {ret}"
            print(f"[{target}] Port discovery failed: {error_msg}")
            self.state.update_stage(
                target, ScanStage.FAILED, error=f"Port discovery {error_msg}"
            )
            return

        # Extract open ports
        ports = extract_open_ports_from_xml(output_file)

        if not ports:
            print(f"[{target}] No open ports found")
            self.state.set_open_ports(target, "")
            self.state.update_stage(target, ScanStage.NO_PORTS_FOUND)
            return

        print(f"[{target}] Found open ports: {ports}")
        self.state.set_open_ports(target, ports)

        # Extract IP:PORT combinations for nuclei targeting
        target_urls = extract_ip_port_combinations_from_xml(output_file)
        if target_urls:
            print(
                f"[{target}] Extracted {len(target_urls)} IP:PORT combinations for nuclei"
            )
            self.state.set_target_urls(target, target_urls)

            # Save target URLs to file for nuclei
            urls_file = f"{directory}/target_urls.txt"
            if save_list_to_file(target_urls, urls_file):
                print(f"[{target}] Saved target URLs to {urls_file}")

        self.state.update_stage(target, ScanStage.PORT_DISCOVERY_COMPLETE)
        print(f"[{target}] Port discovery complete")

    async def _do_service_scan(self, target: str):
        """Perform detailed service scan with version detection"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            return

        if not target_state.open_ports:
            print(f"[{target}] No open ports, skipping service scan")
            self.state.update_stage(target, ScanStage.NO_PORTS_FOUND)
            return

        print_header(f"[{target}] Service Scan", char="-", width=50)
        self.state.update_stage(target, ScanStage.SERVICE_SCAN)

        directory = target_state.directory
        ips_file = f"{directory}/ips.txt"
        output_base = f"{directory}/service_scan"

        cmd = format_command(
            NMAP_SERVICE_SCAN_TEMPLATE,
            version_intensity=self.config.version_intensity,
            input_file=ips_file,
            ports=target_state.open_ports,
            output_base=output_base,
        )

        timeout = self.config.service_scan_timeout * 60
        ret, timed_out = await run_command(cmd, timeout=timeout, output_prefix=target)

        if ret != 0:
            error_msg = "timed out" if timed_out else f"exit code {ret}"
            print(f"[{target}] Service scan failed: {error_msg}")
            self.state.update_stage(
                target, ScanStage.FAILED, error=f"Service scan {error_msg}"
            )
            return

        self.state.update_stage(target, ScanStage.SERVICE_SCAN_COMPLETE)
        print(f"[{target}] Service scan complete")

        # Check if target can be marked complete (if nuclei is done or not needed)
        self._check_and_mark_complete(target)

    def _check_and_mark_complete(self, target: str):
        """Check if target is fully complete (service scan + nuclei both done)"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            return

        # If service scan is complete and nuclei is done (or failed, or wasn't needed)
        if target_state.stage == ScanStage.SERVICE_SCAN_COMPLETE.value:
            nuclei_status = target_state.nuclei_status
            if nuclei_status in [
                ScanStage.NUCLEI_COMPLETE.value,
                ScanStage.NUCLEI_FAILED.value,
            ]:
                self.state.update_stage(target, ScanStage.COMPLETE)
                print(f"[{target}] All scans complete")


class NucleiWorker(ScanWorker):
    """Worker for nuclei vulnerability scans"""

    async def run(self, queue: asyncio.Queue):
        """Process nuclei tasks from the queue"""
        print(f"[NucleiWorker-{self.worker_id}] Started")

        while self.active:
            try:
                task = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if queue.empty():
                    await asyncio.sleep(1)
                continue

            try:
                target = task["target"]

                # Mark as dequeued now that we're processing
                self.state.mark_dequeued(target)

                await self._do_nuclei_scan(target)
            except Exception as e:
                print(f"[NucleiWorker-{self.worker_id}] Error processing {target}: {e}")
                # Mark nuclei as failed but don't fail the entire target
                self.state.set_nuclei_status(target, ScanStage.NUCLEI_FAILED.value)
                # Check if we can mark target complete now
                self._check_target_completion(target)
            finally:
                queue.task_done()

        print(f"[NucleiWorker-{self.worker_id}] Stopped")

    async def _do_nuclei_scan(self, target: str):
        """Perform nuclei vulnerability scan"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            return

        # Check if we have target URLs (IP:PORT combinations)
        if not target_state.target_urls:
            print(f"[{target}] No target URLs (IP:PORT), skipping nuclei scan")
            self.state.set_nuclei_status(target, "skipped_no_targets")
            # Check if we can mark target complete
            self._check_target_completion(target)
            return

        print_header(f"[{target}] Nuclei Scan", char="-", width=50)
        self.state.set_nuclei_status(target, ScanStage.NUCLEI_RUNNING.value)

        directory = target_state.directory
        urls_file = f"{directory}/target_urls.txt"
        nuclei_dir = f"{directory}/nuclei"
        Path(nuclei_dir).mkdir(parents=True, exist_ok=True)

        # Use IP:PORT combinations for more targeted nuclei scanning
        from config import NUCLEI_SCAN_URLS_TEMPLATE

        cmd = format_command(
            NUCLEI_SCAN_URLS_TEMPLATE,
            urls_file=urls_file,
            markdown_dir=nuclei_dir,
            json_file=f"{nuclei_dir}/output.json",
        )

        timeout = self.config.nuclei_timeout * 60
        ret, timed_out = await run_command(cmd, timeout=timeout, output_prefix=target)

        if ret != 0:
            error_msg = "timed out" if timed_out else f"exit code {ret}"
            print(f"[{target}] Nuclei scan had issues: {error_msg}")
            self.state.set_nuclei_status(target, ScanStage.NUCLEI_FAILED.value)
        else:
            print(f"[{target}] Nuclei scan complete")
            self.state.set_nuclei_status(target, ScanStage.NUCLEI_COMPLETE.value)

        # Check if target is now fully complete
        self._check_target_completion(target)

    def _check_target_completion(self, target: str):
        """Check if target is fully complete and mark it if so"""
        target_state = self.state.get_target_state(target)
        if not target_state:
            return

        # If service scan is complete and nuclei is now done, mark complete
        if target_state.stage == ScanStage.SERVICE_SCAN_COMPLETE.value:
            nuclei_status = target_state.nuclei_status
            if nuclei_status in [
                ScanStage.NUCLEI_COMPLETE.value,
                ScanStage.NUCLEI_FAILED.value,
                "skipped_no_hosts",
                "skipped_no_targets",
            ]:
                self.state.update_stage(target, ScanStage.COMPLETE)
                print(f"[{target}] All scans complete")


class ScanOrchestrator:
    """Orchestrates the scanning process with queues and workers"""

    def __init__(self, config: ScanConfig, state: ScanState):
        self.config = config
        self.state = state

        # Create queues
        self.nmap_queue = asyncio.Queue()
        self.nuclei_queue = asyncio.Queue()

        # Create workers
        self.nmap_workers = [
            NmapWorker(i, config, state) for i in range(config.max_nmap_workers)
        ]
        self.nuclei_workers = [
            NucleiWorker(i, config, state) for i in range(config.max_nuclei_workers)
        ]

    async def start(self):
        """Start all workers and the orchestration loop"""
        print(f"Starting {len(self.nmap_workers)} nmap workers")
        print(f"Starting {len(self.nuclei_workers)} nuclei workers")

        # Start all workers
        worker_tasks = []
        for worker in self.nmap_workers:
            worker_tasks.append(asyncio.create_task(worker.run(self.nmap_queue)))
        for worker in self.nuclei_workers:
            worker_tasks.append(asyncio.create_task(worker.run(self.nuclei_queue)))

        # Start the orchestration loop
        orchestration_task = asyncio.create_task(self._orchestrate())

        # Wait for orchestration to complete
        await orchestration_task

        # Stop all workers
        for worker in self.nmap_workers + self.nuclei_workers:
            worker.active = False

        # Wait for all workers to finish
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        print("All workers stopped")

    async def _orchestrate(self):
        """Main orchestration loop - feeds queues based on state"""
        print("Orchestration loop started")

        while True:
            # Check if all targets are complete or failed
            incomplete = self.state.get_incomplete_targets()
            if not incomplete:
                print("All targets processed")
                break

            # Feed nmap queue with pending host discovery tasks
            pending_host_discovery = self.state.get_targets_ready_for_stage(
                ScanStage.HOST_DISCOVERY
            )
            for target in pending_host_discovery:
                await self.nmap_queue.put({"target": target, "stage": "host_discovery"})
                self.state.mark_queued(target)

            # Feed nmap queue with port discovery tasks
            ready_for_port_discovery = self.state.get_targets_ready_for_stage(
                ScanStage.PORT_DISCOVERY
            )
            for target in ready_for_port_discovery:
                await self.nmap_queue.put({"target": target, "stage": "port_discovery"})
                self.state.mark_queued(target)

            # Feed nmap queue with service scan tasks
            ready_for_service_scan = self.state.get_targets_ready_for_stage(
                ScanStage.SERVICE_SCAN
            )
            for target in ready_for_service_scan:
                await self.nmap_queue.put({"target": target, "stage": "service_scan"})
                self.state.mark_queued(target)

            # Feed nuclei queue (can run as soon as host discovery is complete)
            ready_for_nuclei = self.state.get_targets_ready_for_stage(
                ScanStage.NUCLEI_SCAN
            )
            for target in ready_for_nuclei:
                await self.nuclei_queue.put({"target": target})
                self.state.mark_queued(target)
                # Mark as queued, NOT complete - nuclei will update status when done
                self.state.set_nuclei_status(target, ScanStage.NUCLEI_QUEUED.value)

            # Wait a bit before checking again
            await asyncio.sleep(2)

        print("Orchestration loop finished")

    def get_progress(self) -> dict:
        """Get current progress statistics"""
        return self.state.get_statistics()
