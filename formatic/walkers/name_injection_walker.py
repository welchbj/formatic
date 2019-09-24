"""Implementation of the NameInjectionWalker class."""

import ast

from typing import (
   Iterator,
   Optional)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)


class NameInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering ``__name__`` strings."""

    INJECTION_RE = r'.*__name__(!(s|a|r))?$'
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()

        self._value: Optional[str] = None

    @property
    def value(
        self
    ) -> Optional[str]:
        """The name recovered from the __name__ attribute injection."""
        return self._value

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        yield self

        try:
            self._value = ast.literal_eval(self._raw_result)
        except (ValueError, SyntaxError):
            yield FailedInjectionWalker.msg(
                'Expected string literal for __name__ but got '
                f'{self._raw_result}')

    def __str__(
        self
    ) -> str:
        return f'Injected name field with string {self._injection_str}'
