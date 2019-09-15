"""Implementation of the InjectionResult class."""

from __future__ import annotations

import ast
import re

from abc import (
    ABC,
    abstractmethod)
from typing import (
    Any,
    Iterator,
    Optional)


class AbstractInjectionResult(ABC):
    """The result of sending an injection format() string to a target.

    TODO

    """

    def __init__(
        self,
        injection_str: str,
        result_str: str
    ) -> None:
        self._injection_str = injection_str
        self._raw_result = result_str

        try:
            self._literal_result = ast.literal_eval(result_str)
        except SyntaxError:
            self._literal_result = None

    @abstractmethod
    def walk(
        self
    ) -> Iterator[AbstractInjectionResult]:
        """Yield all subsequent injections from the current instance.

        Args:
            visited_injections: A sequence of injection strings that have
                already been sent to the client; this is needed in order to
                prevent cycles in the graph of injections

        Returns:
            An iterator of other :class:`AbstractInjectionResult` instances.

        """

    @staticmethod
    @abstractmethod
    def get_re_pattern(
    ) -> str:
        """Get an RE pattern for matching an injection result class."""

    @staticmethod
    def instance_from_raw_result(
        injection_str: str,
        result_str: str
    ) -> Optional[AbstractInjectionResult]:
        """Get an instance of an injection result from a response type."""
        for cls in AbstractInjectionResult.__subclasses__():
            if re.match(cls.get_re_pattern(), result_str):
                return cls(injection_str, result_str)

        return None

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
    def literal_result(
        self
    ) -> Optional[Any]:
        """The parsed literal version of the :data:`raw_result` attribute."""
        return self._literal_result
