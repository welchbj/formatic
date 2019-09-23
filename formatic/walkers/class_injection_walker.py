"""Implementation of ClassInjectionWalker."""

from typing import (
    Iterator,
    TYPE_CHECKING)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from ..harnesses import (
    AbstractInjectionHarness)

if TYPE_CHECKING:
    from ..injection_engine import (
        InjectionEngine)


class ClassInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering class data."""

    RE_PATTERN: str = r'<class .+>'

    # TODO: get bases via __bases__
    # TODO: find functions via __dict__
    # TODO: blacklist of attributes we do not want to follow

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        injection_str: str,
        result_str: str,
        bytecode_version: str,
        engine: 'InjectionEngine'
    ) -> None:
        super().__init__(
            harness, injection_str, result_str, bytecode_version, engine)

        # TODO

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        init_func_injection = f'{self._injection_str}.__init__'
        result = self._harness.send_injection(init_func_injection)
        if result is None:
            return

        yield self

        # TODO: is follow_branch the way to go here?
        #       we should know what kind of fields we are expecting to see
        #       in a class

        next_walker = self.follow_branch(init_func_injection, result)
        if next_walker is None:
            return

        yield from next_walker.walk()

    def __str__(
        self
    ) -> str:
        return f'Injected class with string {self._injection_str}'
