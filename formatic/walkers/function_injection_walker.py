"""Implementation of the FunctionInjectionWalker class."""

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class FunctionInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a function.

    This module will attempt to recover the source code for a function, via
    access to the ``__code__`` attribute.

    See:
        https://stackoverflow.com/a/16123158/5094008

    """

    RE_PATTERN: str = r'<function .+ at 0x[0-9a-fA-F]+>'

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # TODO
        return
        yield
