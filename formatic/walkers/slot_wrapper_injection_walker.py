"""Implementation of the SlotWrapperInjectionWalker class."""

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class SlotWrapperInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a slot wrapper."""

    INJECTION_RE = None
    RESPONSE_RE = r'<slot wrapper .+>'

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # TODO
        return
        yield

    def __str__(
        self
    ) -> str:
        return f'Injected slot wrapper with string {self._injection_str}'
