#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import time
import logging
from pathlib import Path

import pytest

logger = logging.getLogger(__name__)

TESTDATA_DIR = Path(__file__).parent.parent / "testdata" / "gnmi"


@pytest.fixture(scope="session")
def seed_gnmi(cmd):
    """Seed the mock gNMI handler with default test values.

    Loads pre-configured VRFs, VLANs, DPUs, and device metadata into the mock
    handler so tests can reference them without per-test setup. Session-scoped
    so seeding only happens once. A brief sleep after seeding allows gNMI
    notifications to propagate through all domain stores.
    """
    gnmi_file = TESTDATA_DIR / "default_gnmi.json"
    if not gnmi_file.exists():
        logger.warning(f"gNMI seed file not found: {gnmi_file}")
        return
    try:
        output = cmd.agw_mock_gnmi_set_file(str(gnmi_file))
        logger.info(f"Seeded mock gNMI from {gnmi_file}: {output}")
        time.sleep(3)
    except Exception as e:
        logger.warning(f"Failed to seed mock gNMI: {e}")


@pytest.fixture(scope="session", autouse=True)
def skip_nxos_if_unavailable(cmd):
    """Auto-skip all tests in nxos/ when AGW is not in NX-OS mock mode.

    Checks whether show_status returns a 'Phase:' line, which indicates the
    NX-OS manager completed Setup (only happens when the mock is active).
    """
    try:
        output = cmd.agw_show_status()
        if "Phase:" not in output:
            pytest.skip("AGW is not in NX-OS mock mode (no Phase field)")
    except Exception as e:
        pytest.skip(f"AGW show_status failed: {e}")
