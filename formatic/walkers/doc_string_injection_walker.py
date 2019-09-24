"""Implementation of the DocStringInjectionWalker class."""

import ast

from typing import (
   Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from ..defaults import (
    DEFAULT_UNKNOWN_DOC_STRING)


class DocStringInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering ``__doc__`` strings."""

    INJECTION_RE = r'.*__doc__(!(s|a|r))?$'
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()

        self._value: str = DEFAULT_UNKNOWN_DOC_STRING

    @property
    def value(
        self
    ) -> str:
        """The docstring recovered from the __doc__ attribute injection."""
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
                'Expected string literal for __doc__ but got '
                f'{self._raw_result}')

        yield self

    def __str__(
        self
    ) -> str:
        return f'Injected docstring with string {self._injection_str}'
