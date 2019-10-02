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
from .doc_string_injection_walker import (
    DocStringInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from .name_injection_walker import (
    NameInjectionWalker)


class FunctionInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a function.

    This module will attempt to recover the source code from a function, via
    access to its ``__code__`` attribute.

    """

    INJECTION_RE = None
    RESPONSE_RE = r'<function .+ at 0x[0-9a-fA-F]+>'

    def __extra_init__(
        self
    ) -> None:
        self._code_walker: Optional[CodeObjectInjectionWalker] = None
        self._name_walker: NameInjectionWalker = \
            self.empty_instance(NameInjectionWalker)
        self._docstring_walker: DocStringInjectionWalker = \
            self.empty_instance(DocStringInjectionWalker)
        self._src_code: Optional[str] = None
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
    def name_walker(
        self
    ) -> NameInjectionWalker:
        """Walker used to recover this function's __name__."""
        return self._name_walker

    @property
    def docstring_walker(
        self
    ) -> DocStringInjectionWalker:
        """Walker used to recover this function's __doc__ string."""
        return self._docstring_walker

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
        yield from self._walk_name()
        if not self._name_walker.is_default:
            if self._name_walker.value in self._engine.function_blacklist:
                return

            self._engine.function_blacklist.add(self._name_walker.value)

        yield from self._walk_docstring()

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
        self._signature = self.__class__.code_obj_to_signature(
            walker.code_obj)
        self._src_code = f'{self._signature}\n'
        if self._docstring_walker.value:
            self._src_code += f'    """{self._docstring_walker.value}"""\n'
        self._src_code += '\n'.join(indented_src_lines)

        yield self

    def _walk_name(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover the function's __name__ attribute."""
        name_injection = f'{self._injection_str}.__qualname__!r'
        result = self._harness.send_injection(name_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to read __name__ of function via injection '
                f'{name_injection}')
            return

        walker = self.next_walker(name_injection, result)
        if not isinstance(walker, NameInjectionWalker):
            yield FailedInjectionWalker.msg(
                f'Expected a name walker when sending {name_injection} '
                f'but got {walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()
        self._name_walker = walker

    def _walk_docstring(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover the function's __doc__ attribute."""
        doc_string_injection = f'{self._injection_str}.__doc__!r'
        result = self._harness.send_injection(doc_string_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to read __doc__ of function via injection '
                f'{doc_string_injection}')
            return

        walker = self.next_walker(doc_string_injection, result)
        if not isinstance(walker, DocStringInjectionWalker):
            yield FailedInjectionWalker.msg(
                f'Expected a doc walker when sending {doc_string_injection} '
                f'but got {walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()
        self._docstring_walker = walker

    @staticmethod
    def code_obj_to_signature(
        code_obj: CodeType
    ) -> str:
        """Get a function signature from a code object.

        See:
            https://stackoverflow.com/a/56761306/5094008

        """
        try:
            func = FunctionType(code_obj, {})
            arg_sequence = inspect_signature(func)
            return f'def {code_obj.co_name}{arg_sequence}:'
        except TypeError:
            # build our own signature
            return f"""\
# exact argument names could not be reversed for below signature
def {code_obj.co_name}(*args, **kwargs):"""

    def __str__(
        self
    ) -> str:
        return f'Injected function object with string {self._injection_str}'
