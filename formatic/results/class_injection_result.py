"""Implementation of ClassInjectionResult."""

from typing import (
    Iterator)

from .abstract_injection_result import (
    AbstractInjectionResult)


class ClassInjectionResult(AbstractInjectionResult):

    def walk(
        self
    ) -> Iterator[AbstractInjectionResult]:
        # TODO
        return
        yield

    @staticmethod
    def get_re_pattern(
    ) -> str:
        return '<class .+>'
