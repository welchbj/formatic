"""Default values for use in the CLI and library."""

from typing import (
    Set)

DEFAULT_INJECTION_MARKER = '{}'
DEFAULT_INJECTION_RESPONSE_MARKER_LEN = 16

DEFAULT_UNKNOWN_CLASS_NAME: str = '<UNKNOWN CLASS NAME>'
DEFAULT_UNKNOWN_DOC_STRING: str = '<UNKNOWN DOCSTRING>'


DEFAULT_ATTRIBUTE_BLACKLIST: Set[str] = {
    '__weakref__',
}
DEFAULT_BASE_CLASS_BLACKLIST: Set[str] = {
    'object',
}
