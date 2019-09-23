"""Implementation of the InjectionEngine class."""

from typing import (
    List,
    Iterator,
    Optional)

from .harnesses import (
    AbstractInjectionHarness)
from .walkers import (
    AbstractInjectionWalker)


class InjectionEngine:
    """Enumerate a vulnerable service via format() injections."""

    def __init__(
        self,
        harness: AbstractInjectionHarness
    ) -> None:
        self._harness = harness

        self._visited_module_names: List[str] = []
        self._visited_class_names: List[str] = []

        # TODO: create some state for tracking visited items

    def run(
        self,
        injectable_index: int,
        bytecode_version: str
    ) -> Iterator[AbstractInjectionWalker]:
        """Yield results from sending injections via :data:`harness`.

        Note that the state of the called instance is mutating throughout the
        runtime of this function.

        """
        format_str = f'{injectable_index}.__class__'

        response: Optional[str] = self._harness.send_injection(format_str)
        if not response:
            raise ValueError(
                'Unable to trigger initial injection at index '
                f'{injectable_index}')

        walker_cls = AbstractInjectionWalker.matching_subclass(response)
        if walker_cls is None:
            raise ValueError(
                f'Unable to parse injection response: {response}')

        walker = walker_cls(
            self._harness, format_str, response, bytecode_version, self)

        for walk_result in walker.walk():
            # TODO: gracefully handle errors raised during walking
            # TODO: record the result somehow
            yield walk_result

    @property
    def harness(
        self
    ) -> AbstractInjectionHarness:
        """The harness used to send payloads to the vulnerable service."""
        return self._harness

    # TODO: should below properties be sets?
    @property
    def visited_module_names(
        self
    ) -> List[str]:
        """A list of the names of visited modules."""
        return self._visited_module_names

    @property
    def visited_class_names(
        self
    ) -> List[str]:
        """A list of the names of visited classes."""
        return self._visited_class_names

    def __str__(
        self
    ) -> str:
        return 'TODO'

    def __repr__(
        self
    ) -> str:
        return f'<{self.__class__.__qualname__}>'
