import os
import pytest
import logging

from config.testing_config import TestingConfig
from helper.command_executor import CommandExecutor

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
