"""Implementation of the InjectionResult class."""

import ast

from typing import (
    Any,
    Optional)


class InjectionResult:
    """The result of sending an injection format() string to a target."""

    def __init__(
        self,
        payload: str,
        raw_result: str
    ) -> None:
        self._payload = payload
        self._raw_result = raw_result
        try:
            self._result = ast.literal_eval(raw_result)
        except SyntaxError:
            self._result = None

    @property
    def payload(
        self
    ) -> str:
        """The payload sent to generate the stored result."""
        return self._payload

    @property
    def raw_result(
        self
    ) -> str:
        """The raw result returned from the vulnerable service."""
        return self._raw_result

    @property
    def result(
        self
    ) -> Optional[Any]:
        """The parsed version of :data:`raw_result`."""
        return self._result
