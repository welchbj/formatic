"""Random utilities for the formatic project."""

import random
import string


def get_random_alnum(
    length: int
) -> str:
    """Get a random alphanumeric string of the specified length.

    Raises:
        ValueError: If a :arg:`length` value less than 1 is specified.

    """
    alnum_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(alnum_chars) for _ in range(length))
