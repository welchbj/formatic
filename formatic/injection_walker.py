"""Implementation of the InjectionWalker class."""

import re

from typing import (
    Optional,
    Iterator)

from .defaults import (
    DEFAULT_INJECTION_RESPONSE_MARKER_LEN)
from .harnesses import (
    AbstractInjectionHarness)
from .results import (
    AbstractInjectionResult)
from .utils import (
    get_random_alnum)


class InjectionWalker:
    """Enumerate a vulnerable service via format() injections."""

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

        self._response_re = re.compile(
            f'{self._response_marker}'
            '(?P<injection_response>.*)'
            f'{self._response_marker}', re.DOTALL)

    def walk(
        self,
        injectable_index: int
    ) -> Iterator[AbstractInjectionResult]:
        """Yield results from sending injections via :data:`harness`.

        Note that the state of the called instance is mutating throughout the
        runtime of this function.

        """
        # yes, the below line is itself technically injectable
        format_str = '{' + str(injectable_index) + '.__class__}'
        payload = self._mark_payload(format_str)

        raw_app_response = self._harness.send_injection(payload)
        raw_payload_response = self._parse_response(raw_app_response)

        if not raw_payload_response:
            raise ValueError(
                'Unable to trigger initial injection at index '
                f'{injectable_index}')

        result = AbstractInjectionResult.instance_from_raw_result(
            format_str, raw_payload_response)
        if result is None:
            raise ValueError(
                f'Unable to parse injection response: {raw_payload_response}')

        print(result)
        # TODO: iterate over result's walk()

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

    def _parse_response(
        self,
        raw_app_response: str
    ) -> Optional[str]:
        """Parse the actual injection response from a raw response.

        Args:
            raw_app_response: The raw textual response returned by the
                vulnerable application

        """
        result = self._response_re.match(raw_app_response)
        if not result:
            return None

        injection_response: str = result.group('injection_response')
        if not injection_response:
            return None

        return injection_response

    def __str__(
        self
    ) -> str:
        return 'TODO'

    def __repr__(
        self
    ) -> str:
        return f'<{self.__class__.__qualname__}>'
