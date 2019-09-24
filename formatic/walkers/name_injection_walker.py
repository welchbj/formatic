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

    INJECTION_RE = r'.*__name__(!(s|a|r))?$'
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()

        self._value: str = DEFAULT_UNKNOWN_CLASS_NAME

    @property
    def value(
        self
    ) -> str:
        """The name recovered from the __name__ attribute injection."""
        return self._value

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        try:
            self._value = ast.literal_eval(self._raw_result)
            if not isinstance(self._value, str):
                raise ValueError()
        except (ValueError, SyntaxError):
            yield FailedInjectionWalker.msg(
                'Expected string literal for __name__ but got '
                f'{self._raw_result}')

        yield self

    def __str__(
        self
    ) -> str:
        return f'Injected name field with string {self._injection_str}'
