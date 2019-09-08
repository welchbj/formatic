"""Implementation of the SubprocessInjectionHarness class."""

from subprocess import (
    PIPE,
    run)
from typing import (
    List)

from .abstract_injection_harness import (
    AbstractInjectionHarness)
from ..defaults import (
    DEFAULT_INJECTION_MARKER)


class SubprocessInjectionHarness(AbstractInjectionHarness):
    """A harness for injecting format() strings into a local subprocess."""

    def __init__(
        self,
        args: List[str],
        injection_marker: str = DEFAULT_INJECTION_MARKER
    ) -> None:
        super().__init__(injection_marker)
        self._args = args

    def build_args(
        self,
        payload: str
    ) -> List[str]:
        """Build subproc args, with the :data:`injection_marker` populated.

        Raises:
            ValueError: If the number of occurences of

        """
        built_args = []
        found_marker = False

        for arg in self.args:
            new_arg = arg
            arg_has_marker = self._injection_marker in arg

            if found_marker and arg_has_marker:
                raise ValueError(
                    'Multiple instances of injection marker '
                    f'{self._injection_marker} found in specified arguments')
            elif arg_has_marker:
                new_arg = arg.replace(self._injection_marker, payload, 1)
                found_marker = True

            if self._injection_marker in new_arg:
                raise ValueError(
                    'Multiple instances of injection marker '
                    f'{self._injection_marker} found in argument {arg}')

            built_args.append(new_arg)

        if not found_marker:
            raise ValueError(
                f'No instances of injection marker {self._injection_marker} '
                'found in arguments')

        return built_args

    def send_injection(
        self,
        payload: str
    ) -> str:
        args = self.build_args(payload)
        proc = run(args, stdout=PIPE, stderr=PIPE)
        result = proc.stdout.decode('utf-8')
        return result

    @property
    def args(
        self
    ) -> List[str]:
        """The arguments used for generating the vulnerable subprocess."""
        return self._args
