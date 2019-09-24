"""Implementation of the FailedInjectionWalker class."""

from __future__ import annotations

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class FailedInjectionWalker(AbstractInjectionWalker):
    """An injection walker for when things don't quite work out."""

    INJECTION_RE = None
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        self._reason: str = 'Injection failed for unknown reason'

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # empty
        return
        yield

    @staticmethod
    def msg(
        text: str
    ) -> FailedInjectionWalker:
        """Get an instance with the specified message."""
        # yes, this is disgusting
        ret = FailedInjectionWalker(None, '', '', '', None)  # type: ignore
        ret._reason = text
        return ret

    @property
    def reason(
        self
    ) -> str:
        """Explanation of why the injection failed."""
        return self._reason

    def __str__(
        self
    ) -> str:
        return self._reason
