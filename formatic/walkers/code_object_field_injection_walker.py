"""Implementation of the CodeObjectFieldInjectionWalker class."""

from typing import (
    Any,
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from ..harnesses import (
    AbstractInjectionHarness)


class CodeObjectFieldInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a field of a code object."""

    RE_PATTERN: str = r'____THIS_DOES_NOT_MATTER____'

    def __init__(
        self,
        harness: AbstractInjectionHarness,
        injection_str: str,
        result_str: str,
        bytecode_version: str,
        value: Any
    ) -> None:
        super().__init__(harness, injection_str, result_str, bytecode_version)

        self._value = value

    @property
    def value(
        self
    ) -> Any:
        """The value extracted from the field injection."""
        return self._value

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # there is nothing further to walk
        return
        yield

    def __str__(
        self
    ) -> str:
        return f'Injected code object field with string {self._injection_str}'
