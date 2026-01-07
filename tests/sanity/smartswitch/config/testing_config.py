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
from dataclasses import dataclass
from typing import List


@dataclass
class TestingConfig:
    AGWCTL_PATH = "/usr/src/app/agwctl"
    
    def __init__(self):
        self.agw_container_name = os.getenv("AGW_CONTAINER", "agw")
        self.timeout = int(os.getenv("TEST_TIMEOUT", "30"))  # seconds
        
        self.policy_remote_path = "/tmp/test_policy.yaml"
        
        self._port0 = os.getenv("DPU_PORT0", "Eth1-1")
        self._port1 = os.getenv("DPU_PORT1", "Eth1-2")
        
        self.sniff_timeout = float(os.getenv("SNIFF_TIMEOUT", "1"))
    
    @property
    def ports(self) -> List[str]:
        ports = []
        if self._port0:
            ports.append(self._port0)
        if self._port1:
            ports.append(self._port1)
        return ports
    
    @property
    def has_ports(self) -> bool:
        return len(self.ports) > 0
    
    def __repr__(self):
        return (
            f"TestingConfig("
            f"agw_container={self.agw_container_name}, "
            f"ports={self.ports})"
        )
