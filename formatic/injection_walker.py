"""Implementation of the InjectionWalker class."""

from typing import (
    Optional,
    Iterator)

from .defaults import (
    DEFAULT_INJECTION_RESPONSE_MARKER_LEN)
from .harnesses import (
    AbstractInjectionHarness)
from .injection_result import (
    InjectionResult)
from .utils import (
    get_random_alnum)


class InjectionWalker:
    """Walk the vulnerable service via format() injections."""

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        response_marker: Optional[str] = None,
        rand_response_marker_len: int = DEFAULT_INJECTION_RESPONSE_MARKER_LEN
    ) -> None:
        self._harness = harness

        if response_marker is not None:
            self._response_marker = response_marker
        elif rand_response_marker_len < 1:
            raise ValueError(
                'rand_response_marker_len must be positive integer;'
                f'{rand_response_marker_len} is not acceptable')
        else:
            self._response_marker = get_random_alnum(rand_response_marker_len)

    def walk(
        self
    ) -> Iterator[InjectionResult]:
        """Yield results from sending injections via :data:`harness`.

        Note that the state of the called instance is mutating throughout the
        runtime of this function.

        """
        # TODO: fuzz to get to a starting point
        # TODO: actually walk the target service

        # TODO: what information are we trying to extract from the target?
        #       - A complete understanding of objects in memory; i.e.,
        #         extracting all of their __dict__ members
        #       - All source code that is reachable / reversible
        #       - Highlight any anomalous __getitem__ / __getattr__ /
        #         __getattribute__ methods?

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
