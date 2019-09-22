"""Implementation of ClassInjectionWalker."""

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)


class ClassInjectionWalker(AbstractInjectionWalker):

    RE_PATTERN: str = r'<class .+>'

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
