"""Implementation of the ModuleInjectionWalker class."""

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class ModuleInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering module data."""

    INJECTION_RE = None
    RESPONSE_RE = r'<module .+>'

    # TODO
