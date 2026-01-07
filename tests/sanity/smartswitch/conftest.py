#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import os
import pytest
import logging
from typing import List

from scapy.sendrecv import AsyncSniffer

from config.testing_config import TestingConfig
from helper.command_executor import CommandExecutor
from helper.packet_utils import create_sniffers

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def config() -> TestingConfig:
    return TestingConfig()


@pytest.fixture(scope="session")
def cmd(config) -> CommandExecutor:
    executor = CommandExecutor(config)
    
    try:
        result = executor.agw_health()
        logger.info(f"AGW container '{config.agw_container_name}' is healthy")
        
        sim_name = executor.get_sim_container_name()
        logger.info(f"SIM container '{sim_name}' detected")
    except Exception as e:
        logger.error(f"Failed to connect to containers: {e}")
        pytest.exit("Cannot connect to Docker containers. Run 'make launch-containers' first.")
    
    return executor


@pytest.fixture(scope="function", autouse=True)
def clean_policies_and_flows(cmd):
    """Automatic cleanup fixture - runs before every test.
    
    Clears policies from AGW and SIM containers before each test to ensure
    a clean state. Flow clearing is skipped as it can hang in CI environments.
    """
    logger.info("Cleaning up policies and flows before test")
    
    try:
        cmd.agw_clear_policies()
        logger.info("✅ AGW policies cleared")
    except Exception as e:
        logger.warning(f"Failed to clear AGW policies: {e}")
    
    try:
        cmd.sim_clear_policies()
        logger.info("✅ SIM policies cleared")
    except Exception as e:
        logger.warning(f"Failed to clear SIM policies: {e}")
    
    # Note: dpctl clear flow is intentionally skipped as it can hang in CI
    logger.info("⏭️  Skipping SIM flow clearing (dpctl clear flow can hang)")
    
    yield
    
    logger.info("Test completed")


def pytest_addoption(parser):
    parser.addoption(
        "--agw-container",
        action="store",
        default="agw",
        help="AGW Docker container name"
    )


def pytest_configure(config):
    agw_container = config.getoption("--agw-container")
    
    if agw_container:
        os.environ['AGW_CONTAINER'] = agw_container
    
    logger.info(f"Test configuration: agw_container={agw_container}")


# Scapy packet testing fixtures

@pytest.fixture(scope="session")
def ports(config) -> List[str]:
    """Get configured DPU network interface ports.
    
    Configured via DPU_PORT0 and DPU_PORT1 environment variables.
    """
    if not config.has_ports:
        pytest.skip("DPU ports not configured (set DPU_PORT0 and DPU_PORT1)")
    return config.ports


@pytest.fixture(scope="function")
def sniffers(config, ports) -> List[AsyncSniffer]:
    """Create fresh sniffers for each test.
    
    Returns a list of AsyncSniffer instances for the configured ports.
    Sniffers are recreated for each test to ensure clean state.
    """
    return create_sniffers(ports)
