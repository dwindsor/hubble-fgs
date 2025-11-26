import logging
import time
from typing import Callable

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
                backoff_delay = delay * (2 ** attempt)
                logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"All {max_retries} attempts failed")
                raise


def parse_json_output(output: str) -> dict:
    """Parse JSON output from command"""
    import json
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        logger.error(f"Output was: {output}")
        raise
