"""Implementation of the SlotWrapperInjectionWalker class."""

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class SlotWrapperInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a slot wrapper."""

    RE_PATTERN: str = r'<slot wrapper .+>'

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # TODO
        return
        yield
