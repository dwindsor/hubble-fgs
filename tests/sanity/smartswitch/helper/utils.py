#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import logging
import time
import json
from typing import Callable, List

from scapy.sendrecv import AsyncSniffer

logger = logging.getLogger(__name__)


def retry_on_failure(func: Callable, max_retries: int = 3, delay: float = 1.0):
    """Retry a function on failure with exponential backoff

    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        delay: Initial delay in seconds (will be doubled after each retry)
    """
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                # Exponential backoff: delay * (2 ** attempt)
                backoff_delay = delay * (2**attempt)
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. Retrying in {backoff_delay}s..."
                )
                time.sleep(backoff_delay)
            else:
                logger.error(f"All {max_retries} attempts failed")
                raise


def parse_json_output(output: str) -> dict:
    """Parse JSON output from command"""
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        logger.error(f"Output was: {output}")
        raise


def wait_for_timeout(timeout: int):
    time.sleep(timeout)


def get_last_packet_from_sniffer(sniffers: List[AsyncSniffer], expected: bool = True):
    if not sniffers[-1].results or len(sniffers[-1].results) == 0:
        if not expected:
            logger.info("No packets were sniffed as expected (packet was dropped)")
            return None
        logger.error("No packets were sniffed from sniffer")
        assert False, "Failed: No packets were sniffed from sniffer"

    return sniffers[-1].results[-1]
