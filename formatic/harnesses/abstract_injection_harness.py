"""Implementation of the AbstractInjectionHarness class."""

import re

from abc import (
    ABC,
    abstractmethod)
from typing import (
    Optional)

from ..defaults import (
    DEFAULT_INJECTION_MARKER,
    DEFAULT_INJECTION_RESPONSE_MARKER_LEN)
from ..utils import (
    get_random_alnum)


class AbstractInjectionHarness(ABC):
    """Abstract harness for configuring injection-delivery methods."""

    def __init__(
        self,
        injection_marker: Optional[str] = None,
        response_marker: Optional[str] = None,
        rand_response_marker_len: int = DEFAULT_INJECTION_RESPONSE_MARKER_LEN
    ) -> None:
        super().__init__()

        if injection_marker is None:
            self._injection_marker = DEFAULT_INJECTION_MARKER
        else:
            self._injection_marker = injection_marker

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

    @abstractmethod
    def send_injection(
        self,
        payload: str
    ) -> Optional[str]:
        """The method used to send injections to a vulnerable service.

        Implementations of this method are encourage to wrap the specified
        payload in a random marker that makes it easier to extract the raw
        result from the text.

        As an example, see :class:`SubprocessInjectionHarness`.

        Args:
            payload: The format string body (without curly braces) to be sent
                to the vulnerable service.

        Returns:
            The extracted format string response, if present. Otherwise, None.

        """

    @property
    def injection_marker(
        self
    ) -> str:
        """Marker for substitutiing payloads in injections."""
        return self._injection_marker

    @property
    def response_marker(
        self
    ) -> str:
        """The marker of where to subsitute the generated format() payloads."""
        return self._response_marker

    def _mark_payload(
        self,
        payload: str
    ) -> str:
        """Surround a payload with :data:`response_markers`s."""
        return f'{self._response_marker}{{{payload}}}{self._response_marker}'

    def _parse_response(
        self,
        raw_app_response: str
    ) -> Optional[str]:
        """Parse the actual injection response from a raw response.

        Args:
            raw_app_response: The raw textual response returned by the
                vulnerable application

        """
        result = self._response_re.search(raw_app_response)
        if not result:
            return None

        injection_response: str = result.group('injection_response')
        if not injection_response:
            return None

        return injection_response
