"""Implementation of the FailedInjectionWalker class."""

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class FailedInjectionWalker(AbstractInjectionWalker):
    """An injection walker for when things don't quite work out."""

    RE_PATTERN = None

    def __str__(
        self
    ) -> str:
        return f'Failed to inject with string {self._injection_str}'
