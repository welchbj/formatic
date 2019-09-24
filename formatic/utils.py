"""Random utilities for the formatic project."""

from typing import (
    List)

import random
import re
import string

DICT_TOP_LEVEL_KEYS_RE = re.compile(r"'(?P<name>\w+)':")


def get_random_alnum(
    length: int
) -> str:
    """Get a random alphanumeric string of the specified length.

    Raises:
        ValueError: If a :arg:`length` value less than 1 is specified.

    """
    alnum_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(alnum_chars) for _ in range(length))


def parse_dict_top_level_keys(
    raw_dict_str: str
) -> List[str]:
    """Get the top level keys from a string representation of a dict."""
    return DICT_TOP_LEVEL_KEYS_RE.findall(raw_dict_str)
