#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import json
import logging
import os
import re
import shutil
import signal
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

import docker

from config.testing_config import TestingConfig
from helper.commands import AGWCTL, DPCTL

logger = logging.getLogger(__name__)


class TimeoutError(Exception):
    """Raised when a command times out"""
    pass


@contextmanager
def timeout_handler(seconds):
    """Context manager for command timeout"""
    def timeout_signal_handler(signum, frame):
        raise TimeoutError(f"Command timed out after {seconds} seconds")
    
    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, timeout_signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


class CommandExecutor:
    """Execute commands in AGW and SIM Docker containers"""
    
    def __init__(self, config: TestingConfig):
        self.config = config
        self._docker_client = None
        self._agw_container = None
        self._sim_container = None
        self._sim_containers = None
    
    @property
    def docker_client(self):
        """Lazy initialization of Docker client"""
        if self._docker_client is None:
            self._docker_client = docker.from_env()
        return self._docker_client
    
    def _get_agw_container(self):
        """Get AGW container object"""
        if self._agw_container is None:
            try:
                self._agw_container = self.docker_client.containers.get(self.config.agw_container_name)
            except docker.errors.NotFound:
                raise RuntimeError(f"AGW container '{self.config.agw_container_name}' not found. Run 'make launch-containers' first.")
        return self._agw_container
    
    def _get_sim_container(self):
        """Get SIM container object (naples-{version})"""
        if self._sim_container is None:
            sim_containers = self._get_sim_containers()
            if not sim_containers:
                raise RuntimeError("No SIM container found. Run 'make launch-containers' first.")
            self._sim_container = sim_containers[0]
            logger.info(f"Detected SIM container: {self._sim_container.name}")
        return self._sim_container

    def _get_sim_containers(self):
        """Get all SIM containers sorted by name."""
        if self._sim_containers is None:
            containers = self.docker_client.containers.list()
            sim_containers = sorted(
                [c for c in containers if c.name.startswith("naples-")],
                key=lambda c: c.name,
            )
            if not sim_containers:
                raise RuntimeError("No SIM container found. Run 'make launch-containers' first.")
            self._sim_containers = sim_containers
            logger.info("Detected SIM containers: %s", [c.name for c in sim_containers])
        return self._sim_containers
    
    def get_sim_container_name(self) -> str:
        """Get the SIM container name (naples-{version})"""
        sim_container = self._get_sim_container()
        return sim_container.name

    def get_sim_container_names(self) -> list[str]:
        """Get all SIM container names (naples-*)."""
        return [c.name for c in self._get_sim_containers()]

    def get_two_sim_container_names(self) -> tuple[str, str]:
        """Return exactly two SIM container names sorted by name."""
        sim_names = self.get_sim_container_names()
        if len(sim_names) < 2:
            raise RuntimeError(
                f"Expected at least 2 SIM containers, found {len(sim_names)}: {sim_names}"
            )
        return sim_names[0], sim_names[1]

    def get_sim_host_uplink_ports(self, sim_container_name: str) -> tuple[str, str]:
        """Get host uplink interface names for a SIM container."""
        match = re.search(r"-(\d+)$", sim_container_name)
        if not match:
            raise RuntimeError(
                f"Cannot derive SIM index from container name '{sim_container_name}'"
            )

        sim_index = match.group(1)
        port0 = f"sim{sim_index}-eth1-1"
        port1 = f"sim{sim_index}-eth1-2"

        if not os.path.exists(f"/sys/class/net/{port0}"):
            raise RuntimeError(f"Host interface not found: {port0}")
        if not os.path.exists(f"/sys/class/net/{port1}"):
            raise RuntimeError(f"Host interface not found: {port1}")

        return port0, port1

    def _get_sim_container_by_name(self, sim_container_name: Optional[str] = None):
        """Get SIM container by name, or default SIM when name is not provided."""
        if sim_container_name is None:
            return self._get_sim_container()

        for container in self._get_sim_containers():
            if container.name == sim_container_name:
                return container

        available = ", ".join(self.get_sim_container_names())
        raise RuntimeError(
            f"SIM container '{sim_container_name}' not found. "
            f"Available SIM containers: {available}"
        )
    
    def _exec_in_container(self, container, command: str, timeout: Optional[int] = None) -> str:
        """Execute a command in a Docker container
        
        Args:
            container: Docker container object
            command: Command to execute
            timeout: Timeout in seconds (default: uses config.timeout)
        
        Returns:
            Command output as string
        """
        if timeout is None:
            timeout = self.config.timeout
        
        logger.info(f"Executing in {container.name}: {command} (timeout: {timeout}s)")
        
        try:
            with timeout_handler(timeout):
                exec_result = container.exec_run(
                    command, 
                    tty=True, 
                    stdin=True,
                    demux=False
                )
                output = exec_result.output.decode("utf-8")
                
                if exec_result.exit_code != 0:
                    logger.error(f"Command failed with exit code {exec_result.exit_code}")
                    logger.error(f"Output: {output}")
                    raise RuntimeError(f"Command failed: {output}")
                
                logger.info(f"Command output:\n{output}")
                return output.strip()
        except TimeoutError as e:
            logger.error(f"Command timed out: {e}")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise
    
    def _get_sim_data_dir(self) -> Path:
        sim_container = self._get_sim_container()
        container_name = sim_container.name
        
        pwd = Path(__file__).parent.parent.absolute()
        
        sim_data_dir = pwd / "dsc" / container_name / "data"
        
        if not sim_data_dir.exists():
            raise FileNotFoundError(
                f"SIM data directory not found: {sim_data_dir}. "
                f"Ensure SIM container is running with proper volume mounts."
            )
        
        return sim_data_dir
    
    def _copy_file_to_container(self, local_path: str, remote_path: str):
        source_path = Path(local_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {local_path}")
        
        dest_path = Path(remote_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        shutil.copy(source_path, dest_path)
        logger.info(f"Copied file: {local_path} -> {dest_path}")
    
    def _copy_file_to_sim_container(self, local_path: str, filename: str):
        source_path = Path(local_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {local_path}")
        
        sim_data_dir = self._get_sim_data_dir()
        
        dest_path = sim_data_dir / filename
        
        shutil.copy(source_path, dest_path)
        logger.info(f"Copied file to SIM: {local_path} -> {dest_path} (visible at /data/{filename} in container)")
    
    # AGW Commands
    
    def agw_health(self) -> str:
        """Check AGW health"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HEALTH.value}"
        )
    
    def agw_show_status(self) -> str:
        """Show AGW status"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_STATUS.value}"
        )
    
    def agw_add_policy(self, policy_file_path: str) -> str:
        """Add a policy via agwctl"""
        container = self._get_agw_container()
        
        # Copy policy file to /tmp (mounted volume)
        self._copy_file_to_container(
            policy_file_path,
            self.config.policy_remote_path
        )
        
        # Execute add policy command
        cmd = f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_ADD.value.format(self.config.policy_remote_path)}"
        return self._exec_in_container(container, cmd)
    
    def agw_show_policies(self) -> str:
        """Show all policies"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_SHOW.value}"
        )
    
    def agw_show_policies_json(self) -> dict:
        """Show all policies in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.POLICIES_SHOW.value}"
        )
        return json.loads(output)
    
    def agw_show_policy_by_filter(self, filter_str: str) -> str:
        """Show policies filtered by ResourceID"""
        container = self._get_agw_container()
        cmd = f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_SHOW_FILTER.value.format(filter_str)}"
        return self._exec_in_container(container, cmd)
    
    def agw_remove_policy(self, policy_file_path: str) -> str:
        """Remove a policy via agwctl"""
        container = self._get_agw_container()
        
        # Copy policy file to /tmp (mounted volume)
        self._copy_file_to_container(
            policy_file_path,
            self.config.policy_remote_path
        )
        
        # Execute remove policy command
        cmd = f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_REMOVE.value.format(self.config.policy_remote_path)}"
        return self._exec_in_container(container, cmd)
    
    def agw_clear_policies(self) -> str:
        """Clear all policies via agwctl"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_CLEAR.value}"
        )
    
    def agw_show_dpu(self) -> str:
        """Show DPU status"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_DPU.value}"
        )
    
    
    def get_container_logs(self, container_name: str, tail_lines: int = 50) -> str:
        """Get logs from a Docker container"""
        try:
            container = self.docker_client.containers.get(container_name)
            logs = container.logs(tail=tail_lines).decode('utf-8')
            return logs
        except docker.errors.NotFound:
            raise RuntimeError(f"Container '{container_name}' not found")
    
    # SIM Commands (dpctl)
    
    def sim_show_policies(self, sim_container_name: Optional[str] = None) -> str:
        """Show policies in SIM container using dpctl
        
        Note: In CI environments, dpctl commands can be slow to respond.
        Using extended timeout to handle this.
        """
        container = self._get_sim_container_by_name(sim_container_name)
        # Use longer timeout for dpctl commands in CI
        extended_timeout = self.config.timeout * 3  # 90s default
        logger.info(
            "Querying SIM policies for %s with extended timeout: %ss",
            container.name,
            extended_timeout,
        )
        return self._exec_in_container(
            container,
            DPCTL.POLICIES_SHOW.value,
            timeout=extended_timeout
        )
    
    def sim_show_policies_json(
        self, sim_container_name: Optional[str] = None
    ) -> dict:
        """Show policies in SIM container and parse JSON"""
        output = self.sim_show_policies(sim_container_name=sim_container_name)
        return json.loads(output)

    def sim_show_policies_all(self) -> dict[str, str]:
        """Show policies in all SIM containers using dpctl.

        Returns:
            Map of container name to dpctl JSON output.
        """
        outputs = {}
        for container in self._get_sim_containers():
            outputs[container.name] = self.sim_show_policies(
                sim_container_name=container.name
            )
        return outputs
    
    def sim_clear_policies(self, sim_container_name: Optional[str] = None) -> str:
        """Clear all policies in SIM container using dpctl"""
        container = self._get_sim_container_by_name(sim_container_name)
        return self._exec_in_container(
            container,
            DPCTL.POLICY_CLEAR.value
        )

    def sim_clear_policies_all(self) -> dict[str, str]:
        """Clear all policies in every SIM container using dpctl.

        Returns:
            Map of container name to clear command output.
        """
        results = {}
        for container in self._get_sim_containers():
            results[container.name] = self.sim_clear_policies(
                sim_container_name=container.name,
            )
        return results
    
    def sim_clear_flows(self) -> str:
        """Clear flows in SIM container using dpctl
        
        Note: This command can take longer than usual, so we use a longer timeout.
        """
        container = self._get_sim_container()
        # Use longer timeout for flow clearing (can be slow)
        longer_timeout = self.config.timeout * 2
        logger.info(f"Clearing flows with extended timeout: {longer_timeout}s")
        return self._exec_in_container(
            container,
            DPCTL.CLEAR_FLOWS.value,
            timeout=longer_timeout
        )

    def sim_add_vrf(self, vrf_id: int, sim_container_name: Optional[str] = None):
        container = self._get_sim_container_by_name(sim_container_name)
        try:
            return self._exec_in_container(
                container,
                DPCTL.VRF_ADD.value.format(vrf_id)
            )
        except RuntimeError as e:
            if "API_STATUS_ERR" in str(e) or "already" in str(e).lower():
                logger.info(f"VRF {vrf_id} already exists on {container.name}, skipping")
                return f"VRF {vrf_id} already exists"
            raise
