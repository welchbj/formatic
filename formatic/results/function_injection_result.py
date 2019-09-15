"""Implementation of the FunctionInjectionResult class."""

from typing import (
    Iterator)

from .abstract_injection_result import (
    AbstractInjectionResult)


class FunctionInjectionResult(AbstractInjectionResult):

    def walk(
        self
    ) -> Iterator[AbstractInjectionResult]:
        # TODO
        return
        yield

    @staticmethod
    def get_re_pattern(
    ) -> str:
        return '<function .+ at 0x[0-9a-fA-f]+>'
