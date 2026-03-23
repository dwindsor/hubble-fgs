#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""Shared VRF map builders for integration tests.

These must stay in sync with the AGW_VRF_MAP values in the Makefile.
"""


def build_expected_vrf_map() -> dict:
    """Build the full expected {name: gid} map matching launch-agw AGW_VRF_MAP.

    This must stay in sync with AGW_VRF_MAP in tests/sanity/smartswitch/Makefile.
    """
    expected = {"default": 1, "tims": 2}
    for i in range(1001, 1026):       # epbr-1001 ... epbr-1025
        expected[f"epbr-{i}"] = i
    for i in range(3001, 3076):       # trmvrf-3001 ... trmvrf-3075
        expected[f"trmvrf-{i}"] = i
    return expected


def build_ha_expected_vrf_map() -> dict:
    """Build the {name: gid} map matching launch-ha-agw's smaller VRF map."""
    return {"default": 1, "epbr-1001": 1001, "epbr-1002": 1002, "epbr-1003": 1003}
