"""Implementation of the DocStringInjectionWalker class."""

import ast

from typing import (
   Iterator,
   Optional)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)


class DocStringInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering ``__doc__`` strings."""

    INJECTION_RE = r'.*__doc__(!(s|a|r))?$'
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
        """The docstring recovered from the __doc__ attribute injection."""
        return self._value

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        yield self

        try:
            self._value = ast.literal_eval(self._raw_result)
        except (ValueError, SyntaxError):
            yield FailedInjectionWalker.msg(
                'Expected string literal for __doc__ but got '
                f'{self._raw_result}')

    def __str__(
        self
    ) -> str:
        return f'Injected docstring with string {self._injection_str}'
