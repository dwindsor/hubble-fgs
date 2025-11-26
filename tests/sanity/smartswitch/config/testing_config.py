import os
from dataclasses import dataclass


@dataclass
class TestingConfig:
    """Configuration for sanity tests with Docker containers"""
    
    # Binary paths inside containers
    AGWCTL_PATH = "/usr/src/app/agwctl"
    
    def __init__(self):
        # Docker container names
        self.agw_container_name = os.getenv("AGW_CONTAINER", "agw")
        # SIM container name is auto-detected (naples-{version})
        
        # Command timeout
        self.timeout = int(os.getenv("TEST_TIMEOUT", "30"))  # seconds
        
        # Paths for policy files (inside containers)
        self.policy_remote_path = "/tmp/test_policy.yaml"
    
    def __repr__(self):
        return (
            f"TestingConfig("
            f"agw_container={self.agw_container_name})"
        )
