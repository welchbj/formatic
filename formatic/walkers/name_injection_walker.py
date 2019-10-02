"""Implementation of the NameInjectionWalker class."""

import ast

from typing import (
   Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from ..defaults import (
    DEFAULT_UNKNOWN_CLASS_NAME)


class NameInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering ``__name__`` strings."""

    INJECTION_RE = r'.*\[?(__name__|__module__)\]?(!(s|a|r))?$'
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()

        self._value: str = DEFAULT_UNKNOWN_CLASS_NAME
        self._is_default: bool = True

    @property
    def value(
        self
    ) -> str:
        """The name recovered from the __name__ attribute injection."""
        return self._value

    @property
    def is_default(
        self
    ) -> bool:
        """Whether this is the default class name."""
        return self._is_default

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        try:
            value = ast.literal_eval(self._raw_result)
            if not isinstance(value, str):
                raise ValueError()

            self._value = value
            self._is_default = False
        except (ValueError, SyntaxError):
            yield FailedInjectionWalker.msg(
                'Expected string literal for __name__ but got '
                f'{self._raw_result}')

        yield self

    def __str__(
        self
    ) -> str:
        return f'Injected name field with string {self._injection_str}'
