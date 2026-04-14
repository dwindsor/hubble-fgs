#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tarfile
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

        container = self._get_agw_container()
        dest_dir = str(Path(remote_path).parent)
        dest_name = Path(remote_path).name

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(str(source_path), arcname=dest_name)
        buf.seek(0)

        container.put_archive(dest_dir, buf)
        logger.info(f"Copied file into container: {local_path} -> {remote_path}")
    
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

    def agw_show_gid(self) -> str:
        """Show AGW GID allocations"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_GID.value}"
        )

    def agw_show_vrf(self) -> str:
        """Show AGW VRF state"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_VRF.value}"
        )

    def agw_show_mbr(self) -> str:
        """Show AGW member state"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_MBR.value}"
        )

    def agw_show_adj(self) -> str:
        """Show AGW adjacency state"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.SHOW_ADJ.value}"
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
        envelope = json.loads(output)
        return envelope.get("data", envelope)
    
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
    
    def agw_metrics_show(self) -> str:
        """Show AGW metrics"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.METRICS_SHOW.value}"
        )
    
    def agw_metrics_show_json(self) -> dict:
        """Show AGW metrics in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.METRICS_SHOW.value}"
        )
        return json.loads(output)
    
    

    # gNMI store commands (text output)

    def agw_gnmi_vrf_show(self) -> str:
        """Show VRF store via gNMI (agwctl vrf show)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VRF_SHOW.value}"
        )

    def agw_gnmi_vlan_show(self) -> str:
        """Show VLAN store via gNMI (agwctl vlan show)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VLAN_SHOW.value}"
        )

    def agw_gnmi_dpu_show(self) -> str:
        """Show DPU store via gNMI (agwctl dpu show)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.DPU_SHOW_GNMI.value}"
        )

    def agw_gnmi_ha_show(self) -> str:
        """Show HA store via gNMI (agwctl ha show)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_SHOW_GNMI.value}"
        )

    def agw_gnmi_device_show(self) -> str:
        """Show device store via gNMI (agwctl device show)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.DEVICE_SHOW.value}"
        )

    def agw_policies_info(self) -> str:
        """Show policies info (agwctl policies info)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.POLICIES_INFO.value}"
        )

    # gNMI store commands (JSON output)

    def agw_gnmi_vrf_show_json(self) -> dict:
        """Show VRF store via gNMI in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VRF_SHOW.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_vlan_show_json(self) -> dict:
        """Show VLAN store via gNMI in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VLAN_SHOW.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_dpu_show_json(self) -> dict:
        """Show DPU store via gNMI in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.DPU_SHOW_GNMI.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_ha_show_json(self) -> dict:
        """Show HA store via gNMI in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.HA_SHOW_GNMI.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_ha_peers_show_json(self) -> dict:
        """Show HA peers detail via gNMI in JSON format (agwctl ha peers show)"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.HA_PEERS_GNMI.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_device_show_json(self) -> dict:
        """Show device store via gNMI in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.DEVICE_SHOW.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_policies_info_json(self) -> dict:
        """Show policies info in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.POLICIES_INFO.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    # VRF/VLAN subcommands

    def agw_gnmi_vrf_list(self) -> str:
        """List VRF names (agwctl vrf list)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VRF_LIST.value}"
        )

    def agw_gnmi_vrf_list_json(self) -> dict:
        """List VRF names in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VRF_LIST.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_vrf_info(self, name: str) -> str:
        """Show VRF info for a specific VRF (agwctl vrf info --name <name>)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VRF_INFO.value.format(name)}"
        )

    def agw_gnmi_vrf_info_json(self, name: str) -> dict:
        """Show VRF info for a specific VRF in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VRF_INFO.value.format(name)}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_vrf_gids(self) -> str:
        """Show VRF GID allocations (agwctl vrf gids)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VRF_GIDS.value}"
        )

    def agw_gnmi_vrf_gids_json(self) -> dict:
        """Show VRF GID allocations in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VRF_GIDS.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_vlan_list(self) -> str:
        """List VLAN names (agwctl vlan list)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VLAN_LIST.value}"
        )

    def agw_gnmi_vlan_list_json(self) -> dict:
        """List VLAN names in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VLAN_LIST.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_gnmi_vlan_info(self, name: str) -> str:
        """Show VLAN info for a specific VLAN (agwctl vlan info --name <name>)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.VLAN_INFO.value.format(name)}"
        )

    def agw_gnmi_vlan_info_json(self, name: str) -> dict:
        """Show VLAN info for a specific VLAN in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.VLAN_INFO.value.format(name)}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    # Mock gNMI commands

    def agw_mock_gnmi_show(self) -> str:
        """Dump all mock gNMI path/value pairs (text)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.MOCK_GNMI_SHOW.value}"
        )

    def agw_mock_gnmi_show_json(self) -> dict:
        """Dump all mock gNMI path/value pairs (JSON)"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.MOCK_GNMI_SHOW.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_mock_gnmi_get(self, path: str) -> str:
        """Get the value stored at a specific mock gNMI path"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.MOCK_GNMI_GET.value.format(path)}"
        )

    def agw_mock_gnmi_get_json(self, path: str) -> dict:
        """Get the value stored at a specific mock gNMI path (JSON)"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.MOCK_GNMI_GET.value.format(path)}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_mock_gnmi_set(self, path: str, value: str) -> str:
        """Set a value at a mock gNMI path and trigger notifications"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.MOCK_GNMI_SET.value.format(path, value)}"
        )

    def agw_mock_gnmi_set_file(self, local_path: str) -> str:
        """Bulk-load mock gNMI values from a nested JSON tree file.

        Copies the local file into the container and runs
        ``agwctl mock gnmi set --file <remote_path>``.
        """
        remote_path = "/tmp/mock_gnmi_seed.json"
        self._copy_file_to_container(local_path, remote_path)
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.MOCK_GNMI_SET_FILE.value.format(remote_path)}"
        )

    def agw_mock_gnmi_delete(self, path: str) -> str:
        """Delete a path from the mock gNMI handler and trigger notifications"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.MOCK_GNMI_DELETE.value.format(path)}"
        )

    def agw_mock_gnmi_log(self, n: int = 0, path: str = None, prefix: str = None, operation: str = None) -> str:
        """Read the mock gNMI transaction log with optional filters.

        Args:
            n: Show only the last N entries (0 = all).
            path: Filter by exact path match.
            prefix: Filter by path prefix match.
            operation: Filter by operation (get, set, delete, set_notify, etc.).
        """
        container = self._get_agw_container()
        cmd_parts = [TestingConfig.AGWCTL_PATH, AGWCTL.MOCK_GNMI_LOG.value]
        if n:
            cmd_parts.append(f"-n {n}")
        if path:
            cmd_parts.append(f"--path {path}")
        if prefix:
            cmd_parts.append(f"--prefix {prefix}")
        if operation:
            cmd_parts.append(f"--operation {operation}")
        return self._exec_in_container(container, " ".join(cmd_parts))

    def agw_mock_gnmi_log_json(self, n: int = 0, path: str = None, prefix: str = None, operation: str = None) -> list:
        """Read the mock gNMI transaction log as parsed JSON list."""
        container = self._get_agw_container()
        cmd_parts = [TestingConfig.AGWCTL_PATH, "--json", AGWCTL.MOCK_GNMI_LOG.value]
        if n:
            cmd_parts.append(f"-n {n}")
        if path:
            cmd_parts.append(f"--path {path}")
        if prefix:
            cmd_parts.append(f"--prefix {prefix}")
        if operation:
            cmd_parts.append(f"--operation {operation}")
        output = self._exec_in_container(container, " ".join(cmd_parts))
        envelope = json.loads(output)
        data = envelope.get("data", envelope)
        if isinstance(data, list):
            return data
        return data.get("entries", [])

    def agw_ha_info(self) -> str:
        """Show HA configuration info (agwctl ha info)"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_INFO.value}"
        )

    def agw_ha_info_json(self) -> dict:
        """Show HA configuration info in JSON format"""
        container = self._get_agw_container()
        output = self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} --json {AGWCTL.HA_INFO.value}"
        )
        envelope = json.loads(output)
        return envelope.get("data", envelope)

    def agw_ha_debug_fail(self) -> str:
        """Set the debug_override HA criterion to false, forcing ha-switchover"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_DEBUG_FAIL.value}"
        )

    def agw_ha_debug_ok(self) -> str:
        """Set the debug_override HA criterion to true, restoring normal evaluation"""
        container = self._get_agw_container()
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_DEBUG_OK.value}"
        )

    def agw_ha_debug_peer_fail(self, peer: str, membership: bool = False, adjacency: bool = False) -> str:
        """Inject a debug failure for a peer's membership or adjacency criteria"""
        container = self._get_agw_container()
        flag = "--membership" if membership else "--adjacency"
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_DEBUG_PEER_FAIL.value} --peer {peer} {flag}"
        )

    def agw_ha_debug_peer_ok(self, peer: str, membership: bool = False, adjacency: bool = False) -> str:
        """Clear a debug failure for a peer's membership or adjacency criteria"""
        container = self._get_agw_container()
        flag = "--membership" if membership else "--adjacency"
        return self._exec_in_container(
            container,
            f"{TestingConfig.AGWCTL_PATH} {AGWCTL.HA_DEBUG_PEER_OK.value} --peer {peer} {flag}"
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
    
    def sim_disable_inter_vrf(self, sim_container_name: Optional[str] = None):
        container = self._get_sim_container_by_name(sim_container_name)
        return self._exec_in_container(
            container,
            DPCTL.DISABLE_INTER_VRF.value
        )

    # Kubectl commands (run on test host, not inside a container)

    KUBECONFIG_PATH = "/tmp/agw-test-kubeconfig"

    def kubectl_apply(self, yaml_content: str) -> str:
        """Apply a YAML manifest to the kind cluster via kubectl."""
        logger.info("Applying YAML via kubectl:\n%s", yaml_content)
        result = subprocess.run(
            ["kubectl", "--kubeconfig", self.KUBECONFIG_PATH, "apply", "-f", "-"],
            input=yaml_content,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.error("kubectl apply failed: %s", result.stderr)
            raise RuntimeError(f"kubectl apply failed: {result.stderr}")
        logger.info("kubectl apply output: %s", result.stdout.strip())
        return result.stdout.strip()

    def kubectl_delete(self, yaml_content: str) -> str:
        """Delete a K8s resource described by YAML from the kind cluster."""
        logger.info("Deleting resource via kubectl")
        result = subprocess.run(
            ["kubectl", "--kubeconfig", self.KUBECONFIG_PATH, "delete", "-f", "-", "--ignore-not-found"],
            input=yaml_content,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("kubectl delete failed: %s", result.stderr)
        else:
            logger.info("kubectl delete output: %s", result.stdout.strip())
        return result.stdout.strip()
