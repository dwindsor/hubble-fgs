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
import time
import signal
import pytest
import logging
from pathlib import Path
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
        executor.agw_health()
        logger.info(f"AGW container '{config.agw_container_name}' is healthy")
    except Exception as e:
        logger.error(f"Failed to connect to AGW container: {e}")
        pytest.exit("Cannot connect to AGW container. Run 'make launch-agw' or 'make launch-containers' first.")

    try:
        sim_name = executor.get_sim_container_name()
        logger.info(f"SIM container '{sim_name}' detected")
    except Exception as e:
        logger.warning(f"SIM container not found (SIM-dependent tests will be skipped): {e}")

    return executor


@pytest.fixture(scope="function", autouse=True)
def clean_policies_and_flows(request, cmd):
    """Automatic cleanup fixture - runs before every test.

    Clears policies from AGW and SIM containers before each test to ensure
    a clean state. Flow clearing is skipped as it can hang in CI environments.
    For AMEX tests, includes a longer wait after clearing to allow the DPU
    to fully process the clear of large policy sets.
    Skipped for HA-marked tests which use separate fixtures.
    """
    if request.node.get_closest_marker("ha"):
        yield
        return

    logger.info("Cleaning up policies and flows before test")
    
    is_amex = request.node.get_closest_marker("amex") is not None

    try:
        cmd.agw_clear_policies()
        logger.info("✅ AGW policies cleared")
    except Exception as e:
        logger.warning(f"Failed to clear AGW policies: {e}")

    try:
        sim_clear_results = cmd.sim_clear_policies_all()
        for sim_name in sim_clear_results:
            logger.info(f"✅ SIM policies cleared: {sim_name}")
    except Exception as e:
        logger.warning(f"Failed to clear SIM policies: {e}")

    # Note: dpctl clear flow is intentionally skipped as it can hang in CI
    logger.info("⏭️  Skipping SIM flow clearing (dpctl clear flow can hang)")
    
    # AMEX policies are large and need extra time for DPU to process the clear
    if is_amex:
        time.sleep(10)
        logger.info("Waited 10s for DPU to process policy clear (amex test)")
    
    yield

    logger.info("Test completed")


def pytest_addoption(parser):
    parser.addoption(
        "--agw-container",
        action="store",
        default="agw",
        help="AGW Docker container name"
    )


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Enforce @pytest.mark.timeout(seconds) via SIGALRM.

    Only effective on Unix (macOS/Linux). Silently ignored on Windows.
    """
    marker = item.get_closest_marker("timeout")
    if marker and hasattr(signal, "SIGALRM"):
        seconds = marker.args[0] if marker.args else 0
        if seconds > 0:
            def _timeout_handler(signum, frame):
                pytest.fail(f"Test timed out after {seconds}s")
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(seconds)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    """Cancel any pending SIGALRM after each test."""
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)


def pytest_configure(config):
    agw_container = config.getoption("--agw-container", default=None)

    # Only override env var if explicitly passed on the command line
    if agw_container and agw_container != "agw":
        os.environ['AGW_CONTAINER'] = agw_container

    effective = os.environ.get('AGW_CONTAINER', 'agw')
    logger.info(f"Test configuration: agw_container={effective}")


@pytest.fixture(scope="session")
def policy_file() -> str:
    """Path to a sample policy file for testing."""
    path = Path(__file__).parent / "testdata" / "policies" / "agw" / "permit_all_simple.yaml"
    if not path.exists():
        pytest.skip(f"Policy test file not found: {path}")
    return str(path)


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
