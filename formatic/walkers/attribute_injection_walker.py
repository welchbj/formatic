"""Implementation of the AttributeInjectionWalker class."""

import ast

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from ..defaults import (
    DEFAULT_UNKNOWN_ATTRIBUTE_VALUE)


class AttributeInjectionWalker(AbstractInjectionWalker):
    """Injection walker for literal attributes."""

    INJECTION_RE = None
    RESPONSE_RE = r'<attribute .+>'

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()

        self._value: str = DEFAULT_UNKNOWN_ATTRIBUTE_VALUE

    @property
    def value(
        self
    ) -> str:
        """The parsed literal value, if one exists."""
        return self._value

    @property
    def name(
        self
    ) -> str:
        """The name of the attribute."""
        return self._injection_str.split('.')[-1]

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        try:
            self._value = ast.literal_eval(self._raw_result)
            yield self
        except (ValueError, SyntaxError):
            yield FailedInjectionWalker.msg(
                f'Unable to parse raw injection response {self._raw_result} '
                'as Python literal; received from string '
                f'{self._injection_str}')

    def __str__(
        self
    ) -> str:
        return f'Injected attribute with string {self._injection_str}'
