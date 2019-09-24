"""Implementation of the AttributeInjectionWalker class."""

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class AttributeInjectionWalker(AbstractInjectionWalker):
    """Injection walker for attributes."""

    INJECTION_RE = None
    RESPONSE_RE = r'<attribute .+>'

    # TODO: pull out __class__ in walk(); see if there is anything else we
    #       might want, too

    def __str__(
        self
    ) -> str:
        return f'Injected attribute with string {self._injection_str}'
