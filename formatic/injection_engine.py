"""Implementation of the InjectionEngine class."""

from typing import (
    Iterator,
    Optional,
    Sequence,
    Set)

from .defaults import (
    DEFAULT_ATTRIBUTE_BLACKLIST,
    DEFAULT_CLASS_BLACKLIST)
from .harnesses import (
    AbstractInjectionHarness)
from .walkers import (
    AbstractInjectionWalker)


class InjectionEngine:
    """Enumerate a vulnerable service via format() injections."""

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        attribute_blacklist: Sequence[str] = DEFAULT_ATTRIBUTE_BLACKLIST,
        class_blacklist: Sequence[str] = DEFAULT_CLASS_BLACKLIST
    ) -> None:
        self._harness = harness
        self._attribute_blacklist = set(attribute_blacklist)
        self._class_blacklist = set(class_blacklist)

        # TODO: other blacklists (modules, etc.)

        # TODO: if we are going with modules and classes, we should probably
        #       just do everything
        self._visited_module_names: Set[str] = set()
        # TODO: should we record the below, or is it something that we should
        #       recursively pull from modules?
        self._visited_class_names: Set[str] = set()

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

        walker_cls = AbstractInjectionWalker.matching_subclass(
            format_str, response)
        if walker_cls is None:
            raise ValueError(
                f'Unable to parse injection response: {response}')

        walker = walker_cls(
            self._harness, format_str, response, bytecode_version, self)

        for walk_result in walker.walk():
            # TODO: record results
            yield walk_result

    @property
    def harness(
        self
    ) -> AbstractInjectionHarness:
        """The harness used to send payloads to the vulnerable service."""
        return self._harness

    @property
    def attribute_blacklist(
        self
    ) -> Set[str]:
        """Attribute names that will not be followed."""
        return self._attribute_blacklist

    @property
    def class_blacklist(
        self
    ) -> Set[str]:
        """Base class names that will not be followed."""
        return self._class_blacklist

    @property
    def visited_module_names(
        self
    ) -> Set[str]:
        """A list of the names of visited modules."""
        return self._visited_module_names

    @property
    def visited_class_names(
        self
    ) -> Set[str]:
        """A list of the names of visited classes."""
        return self._visited_class_names

    def __str__(
        self
    ) -> str:
        # TODO
        return 'TODO'

    def __repr__(
        self
    ) -> str:
        return f'<{self.__class__.__qualname__}>'
