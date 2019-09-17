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
        init_func_injection: str = f'{self._injection_str}.__init__'
        result = self._harness.send_injection(init_func_injection)
        if result is None:
            return

        yield self

        next_walker = self.follow_branch(init_func_injection, result)
        if next_walker is None:
            return

        yield from next_walker.walk()
