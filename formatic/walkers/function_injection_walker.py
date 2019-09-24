"""Implementation of the FunctionInjectionWalker class."""

from inspect import (
    signature as inspect_signature)
from types import (
    CodeType,
    FunctionType)

from typing import (
    Iterator,
    Optional)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .code_object_injection_walker import (
    CodeObjectInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)


class FunctionInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a function.

    This module will attempt to recover the source code from a function, via
    access to its ``__code__`` attribute.

    """

    # TODO: how are decorators handled?

    INJECTION_RE = None
    RESPONSE_RE = r'<function .+ at 0x[0-9a-fA-F]+>'

    def __extra_init__(
        self
    ) -> None:
        self._code_walker: Optional[CodeObjectInjectionWalker] = None
        self._signature: Optional[str] = None

    @property
    def code_walker(
        self
    ) -> Optional[CodeObjectInjectionWalker]:
        """The code object that this walker recovered from the target.

        This attribute will only be populated after a call to :func:`walk`. If
        the call to ``walk()`` cannot recover the object, then this attribute
        will remain as ``None``.

        """
        return self._code_walker

    @property
    def src_code(
        self
    ) -> Optional[str]:
        """The source code that this walker recovered from the target."""
        return self._src_code

    @property
    def signature(
        self
    ) -> Optional[str]:
        """The decompiled function's signature, if one was retrieved."""
        return self._signature

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        code_obj_injection = f'{self._injection_str}.__code__'
        raw_result = self._harness.send_injection(code_obj_injection)
        if raw_result is None:
            yield FailedInjectionWalker.msg(
                'Unable to recover injection response from string '
                f'{raw_result}')
            return

        walker = self.next_walker(code_obj_injection, raw_result)
        if walker is None:
            yield FailedInjectionWalker.msg(
                'No matching walker found for injection response '
                f'{raw_result}')
            return
        elif not isinstance(walker, CodeObjectInjectionWalker):
            yield FailedInjectionWalker.msg(
                f'Got {type(walker)} when injecting function __code__ '
                'attribute; something is terribly wrong...')
            return

        for sub_walker in walker.walk():
            yield sub_walker

        if walker.code_obj is None or walker.src_code is None:
            yield FailedInjectionWalker.msg(
                'Unable to successfully recover code object from string '
                f'{walker.injection_str}')
            return

        src_lines = ([] if walker.src_code is None else
                     walker.src_code.splitlines())
        indented_src_lines = [f'   {line}' for line in src_lines]
        # TODO: need to get __doc__
        # TODO: need to get __name__
        self._signature = self.__class__.code_obj_to_signature(
            walker.code_obj)
        self._src_code = f'def {self._signature}:\n'
        self._src_code += '\n'.join(indented_src_lines)

        yield self

    @staticmethod
    def code_obj_to_signature(
        code_obj: CodeType
    ) -> str:
        """Get a function signature from a code object.

        See:
            https://stackoverflow.com/a/56761306/5094008

        """
        func = FunctionType(code_obj, {})
        arg_sequence = inspect_signature(func)
        return f'{code_obj.co_name}{arg_sequence}'

    def __str__(
        self
    ) -> str:
        return f'Injected function object with string {self._injection_str}'
