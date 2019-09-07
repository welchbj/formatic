"""Implementation of the InjectionWalker class."""

from typing import (
    Iterator)

from .harnesses import (
    AbstractInjectionHarness)
from .injection_result import (
    InjectionResult)
from .utils import (
    get_random_alnum)


DEFAULT_RESPONSE_MARKER_LEN = 16


class InjectionWalker:
    """Walk the vulnerable service via format() injections."""

    def __init__(
        self,
        harness: AbstractInjectionHarness
    ) -> None:
        self._harness = harness
        self._response_marker = get_random_alnum(DEFAULT_RESPONSE_MARKER_LEN)

    def walk(
        self
    ) -> Iterator[InjectionResult]:
        """Yield results from sending injections via :data:`harness`.

        Note that the state of the called instance is mutating throughout the
        runtime of this function.

        """
        # TODO: fuzz to get to a starting point
        # TODO: actually walk the target service

        payload = self._mark_payload('{0.__class__}')
        raw_response = self._harness.send_injection(payload)

        yield InjectionResult(payload, raw_response)

    @property
    def harness(
        self
    ) -> AbstractInjectionHarness:
        """The harness used to send payloads to the vulnerable service."""
        return self._harness

    @property
    def response_marker(
        self
    ) -> str:
        """The random string used to mark a start and end of a response."""
        return self._response_marker

    def _mark_payload(
        self,
        payload: str
    ) -> str:
        """Surround a payload with :data:`response_markers`s."""
        return f'{self._response_marker}{payload}{self._response_marker}'
