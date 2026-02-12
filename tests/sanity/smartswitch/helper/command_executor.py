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
            containers = self.docker_client.containers.list()
            sim_container = next(
                (c for c in containers if 'naples-' in c.name),
                None
            )
            if not sim_container:
                raise RuntimeError("No SIM container found. Run 'make launch-containers' first.")
            self._sim_container = sim_container
            logger.info(f"Detected SIM container: {sim_container.name}")
        return self._sim_container
    
    def get_sim_container_name(self) -> str:
        """Get the SIM container name (naples-{version})"""
        sim_container = self._get_sim_container()
        return sim_container.name
    
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
    
    def sim_show_policies(self) -> str:
        """Show policies in SIM container using dpctl
        
        Note: In CI environments, dpctl commands can be slow to respond.
        Using extended timeout to handle this.
        """
        container = self._get_sim_container()
        # Use longer timeout for dpctl commands in CI
        extended_timeout = self.config.timeout * 3  # 90s default
        logger.info(f"Querying SIM policies with extended timeout: {extended_timeout}s")
        return self._exec_in_container(
            container,
            DPCTL.POLICIES_SHOW.value,
            timeout=extended_timeout
        )
    
    def sim_show_policies_json(self) -> dict:
        """Show policies in SIM container and parse JSON"""
        output = self.sim_show_policies()
        return json.loads(output)
    
    def sim_clear_policies(self) -> str:
        """Clear all policies in SIM container using dpctl"""
        container = self._get_sim_container()
        return self._exec_in_container(
            container,
            DPCTL.POLICY_CLEAR.value
        )
    
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

    def sim_add_vrf(self, vrf_id: int): 
        container = self._get_sim_container()
        return self._exec_in_container(
            container,
            DPCTL.VRF_ADD.value.format(vrf_id)
        )