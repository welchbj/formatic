"""Implementation of the AbstractInjectionWalker class."""

from __future__ import annotations

import re

from abc import (
    ABC,
    abstractmethod)
from typing import (
    Iterator,
    Optional,
    TYPE_CHECKING)

from ..harnesses import (
    AbstractInjectionHarness)

if TYPE_CHECKING:
    from ..injection_engine import (
        InjectionEngine)


class AbstractInjectionWalker(ABC):
    """Recursive classes to walk all injection branches of a target.

    TODO

    """

    RE_PATTERN = NotImplemented

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        injection_str: str,
        result_str: str,
        bytecode_version: str,
        engine: 'InjectionEngine'
    ) -> None:
        self._harness = harness
        self._injection_str = injection_str
        self._raw_result = result_str
        self._bytecode_version = bytecode_version
        self._engine = engine

    def __init_subclass__(
        cls,
        **kwargs
    ) -> None:
        super().__init_subclass__(**kwargs)

        if cls.RE_PATTERN is NotImplemented:
            raise TypeError(
                'Descendants of AbstractInjectionResult must define the class '
                'property RE_PATTERN')

    @abstractmethod
    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Yield all subsequent injections from the current instance.

        Args:
            visited_injections: A sequence of injection strings that have
                already been sent to the client; this is needed in order to
                prevent cycles in the graph of injections

        Returns:
            An iterator of other :class:`AbstractInjectionResult` instances.

        """

    @staticmethod
    def instance_from_raw_result(
        harness: AbstractInjectionHarness,
        injection_str: str,
        result_str: str,
        bytecode_version: str,
        engine: InjectionEngine
    ) -> Optional[AbstractInjectionWalker]:
        """Get an instance of an injection result from a response type."""
        for cls in AbstractInjectionWalker.__subclasses__():
            if cls.RE_PATTERN and re.search(cls.RE_PATTERN, result_str):
                return cls(harness,
                           injection_str,
                           result_str,
                           bytecode_version,
                           engine)

        return None

    def follow_branch(
        self,
        injection_str: str,
        result_str: str
    ) -> Optional[AbstractInjectionWalker]:
        """Create a walker instance from the specified format str branch."""
        try:
            return self.__class__.instance_from_raw_result(
                self._harness,
                injection_str,
                result_str,
                self._bytecode_version,
                self._engine)
        except TypeError:
            return None

    @property
    def harness(
        self
    ) -> AbstractInjectionHarness:
        """The harness to use for sending new injections."""
        return self._harness

    @property
    def injection_str(
        self
    ) -> str:
        """The format string sent to the target."""
        return self._injection_str

    @property
    def raw_result(
        self
    ) -> Optional[str]:
        """The raw injection result returned by the target."""
        return self._raw_result

    @property
    def bytecode_version(
        self
    ) -> str:
        """The Python bytecode version to use for function decompilation."""
        return self._bytecode_version
