"""Implementation of the CodeObjectInjectionWalker class."""

import ast
import re

from io import (
    StringIO)
from types import (
    CodeType)
from uncompyle6.main import (
    decompile)
from xdis.magics import (
    py_str2float)

from typing import (
    Iterator,
    Optional)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .code_object_field_injection_walker import (
    CodeObjectFieldInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)


class CodeObjectInjectionWalker(AbstractInjectionWalker):
    """Injection walker for a code object.

    This walker will extract the following attributes from an injectable
    ``__code__`` attribute:

        * co_argcount - number of positional args, including those with
            default values
        * co_code - raw bytecode
        * co_cellvars - local variables referenced by nested functions
        * co_consts - literals used in bytecode
        * co_filename - filename from which the code was compiled
        * co_firstlineno - first line number of the function's source code
        * co_flags - integer with flags to be processed by the interpreter
        * co_lnotab - str that maps bytecode offsets to source code line
            numbers
        * co_freevars - tuple of names of free variables
        * co_kwonlyargcount - number of keyword-only args, not including
            **kwargs
        * co_name - function name
        * co_names - tuple of names used within the bytecode
        * co_nlocals - number of local variables used by the function
        * co_stacksize - vm stack space needed
        * co_varnames - tuple of names of arguments and local variables

    These attributes are then passed to the ``uncompyle6`` byte-code
    decompilation engine, producing the reconstructed source code of the
    injected code object.

    See:
        https://stackoverflow.com/a/16123158/5094008

    """

    INJECTION_RE = None
    RESPONSE_RE = r'<code object .+ at 0x[0-9a-fA-F]+, file .+, line .+>'

    def __extra_init__(
        self
    ) -> None:
        return super().__extra_init__()

        self._src_code: Optional[str] = None
        self._code_obj: Optional[CodeType] = None

    @property
    def src_code(
        self
    ) -> Optional[str]:
        """The source code of the code's body (if recovered)."""
        return self._src_code

    @property
    def code_obj(
        self
    ) -> Optional[CodeType]:
        """The underlying code object (if recovered)."""
        return self._code_obj

    # TODO: we need to refactor usages of this into FailedInjectionWalker
    def assert_populated(
        self
    ) -> None:
        """Assert that all optional fields of this instance are not None.

        Raises:
            ValueError: If any optional fields on this instance are None.

        """
        if self._code_obj is None or self._src_code is None:
            raise ValueError(f'Incomplete {self.__class__.__qualname__}')

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # TODO: we are not current yielding self from within the code field
        #       walk() impl; let's look into refactoring that

        try:
            co_argcount_inj_walker = self._read_co_argcount()
            yield co_argcount_inj_walker

            co_kwonlyargcount_inj_walker = self._read_co_kwonlyargcount()
            yield co_kwonlyargcount_inj_walker

            co_nlocals_inj_walker = self._read_co_nlocals()
            yield co_nlocals_inj_walker

            co_stacksize_inj_walker = self._read_co_stacksize()
            yield co_stacksize_inj_walker

            co_flags_inj_walker = self._read_co_flags()
            yield co_flags_inj_walker

            co_code_inj_walker = self._read_co_code()
            yield co_code_inj_walker

            co_consts_inj_walker: AbstractInjectionWalker
            for walker in self._read_co_consts():
                yield walker
                co_consts_inj_walker = walker
            if not isinstance(co_consts_inj_walker,
                              CodeObjectFieldInjectionWalker):
                yield FailedInjectionWalker.msg(
                    f'Received unexpected type {type(co_consts_inj_walker)} '
                    'when expecting a field injection walker')
                return

            co_names_inj_walker = self._read_co_names()
            yield co_names_inj_walker

            co_varnames_inj_walker = self._read_co_varnames()
            yield co_varnames_inj_walker

            co_filename_inj_walker = self._read_co_filename()
            yield co_filename_inj_walker

            co_name_inj_walker = self._read_co_name()
            yield co_name_inj_walker

            co_firstlineno_inj_walker = self._read_co_firstlineno()
            yield co_firstlineno_inj_walker

            co_lnotab_inj_walker = self._read_co_lnotab()
            yield co_lnotab_inj_walker

            co_freevars_inj_walker = self._read_co_freevars()
            yield co_freevars_inj_walker

            co_cellvars_inj_walker = self._read_co_cellvars()
            yield co_cellvars_inj_walker
        except ValueError as e:
            yield FailedInjectionWalker.msg(str(e))

        self._code_obj = CodeType(
            co_argcount_inj_walker.value,
            co_kwonlyargcount_inj_walker.value,
            co_nlocals_inj_walker.value,
            co_stacksize_inj_walker.value,
            co_flags_inj_walker.value,
            co_code_inj_walker.value,
            co_consts_inj_walker.value,
            co_names_inj_walker.value,
            co_varnames_inj_walker.value,
            co_filename_inj_walker.value,
            co_name_inj_walker.value,
            co_firstlineno_inj_walker.value,
            co_lnotab_inj_walker.value,
            co_freevars_inj_walker.value,
            co_cellvars_inj_walker.value)

        bytecode_version_float = py_str2float(self._bytecode_version)
        with StringIO() as f:
            decompile(bytecode_version_float, self._code_obj, out=f)
            raw_decompiled_src_body = f.getvalue()

        decompiled_src_body = raw_decompiled_src_body.replace(
            '\n\n\n', '\n\n')
        lines = [
            line for line in decompiled_src_body.splitlines()
            if not line.lstrip().startswith('# ')]
        self._src_code = '\n'.join(lines)

        yield self

    def _read_code_field(
        self,
        field_name: str,
    ) -> CodeObjectFieldInjectionWalker:
        """Read a field from a ``__code__`` object.

        Raises:
            ValueError: If a raw result is not retrieved from the injection.

        """
        injection_str = f'{self._injection_str}.{field_name}!r'
        raw_result = self._harness.send_injection(injection_str)
        if raw_result is None:
            raise ValueError(
                f'Unable to retrieve {field_name} field from code object '
                f'injection with string {injection_str}')

        parsed_result = ast.literal_eval(raw_result)
        return CodeObjectFieldInjectionWalker(
            self._harness,
            injection_str.rstrip('!r'),
            raw_result,
            self._bytecode_version,
            self._engine,
            parsed_result)

    def _read_co_argcount(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_argcount')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_argcount; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_code(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_code')
        if not isinstance(result.value, bytes):
            raise ValueError(
                'Expected bytes when reading co_code; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_cellvars(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_cellvars')
        if (not isinstance(result.value, tuple) or
                not all(isinstance(elt, str) for elt in result.value)):
            raise ValueError(
                'Expected tuple of strings when reading co_cellvars; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_consts(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        parsed_elts = []
        i = 0
        while True:
            elt_injection = f'{self._injection_str}.co_consts[{i}]!r'
            raw_elt = self._harness.send_injection(elt_injection)
            if raw_elt is None:
                break

            try:
                value = ast.literal_eval(raw_elt)
                yield CodeObjectFieldInjectionWalker(
                    self._harness,
                    elt_injection.rstrip('!r'),
                    raw_elt,
                    self._bytecode_version,
                    self._engine,
                    value)

                parsed_elts.append(value)

                i += 1
                continue
            except Exception:
                pass

            m = re.match(self.__class__.RESPONSE_RE, raw_elt)
            if m:
                injection_str = elt_injection[:-2]
                code_obj_walker = CodeObjectInjectionWalker(
                    self._harness,
                    injection_str,
                    raw_elt,
                    self._bytecode_version,
                    self._engine)
                yield code_obj_walker
                for sub_walker in code_obj_walker.walk():
                    pass

                code_obj_walker.assert_populated()
                parsed_elts.append(code_obj_walker.code_obj)

                i += 1
                continue

            raise ValueError(f'Unable to parse co_const {raw_elt}')

        if not parsed_elts:
            raise ValueError(
                'Got an empty tuple for co_consts; this should never happen!')

        yield CodeObjectFieldInjectionWalker(
            self._harness,
            f'{self._injection_str}.co_consts',
            'placeholder',
            self._bytecode_version,
            self._engine,
            tuple(parsed_elts))

    def _read_co_filename(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_filename')
        if not isinstance(result.value, str):
            raise ValueError(
                'Expected str when reading co_filename; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_firstlineno(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_firstlineno')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_firstlineno; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_flags(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_flags')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_flags; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_lnotab(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_lnotab')
        if not isinstance(result.value, bytes):
            raise ValueError(
                'Expected bytes when reading co_lnotab; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_freevars(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_freevars')
        if (not isinstance(result.value, tuple) or
                not all(isinstance(elt, str) for elt in result.value)):
            raise ValueError(
                'Expected tuple of strings when reading co_freevars; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_kwonlyargcount(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_kwonlyargcount')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_kwonlyargcount; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_name(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_name')
        if not isinstance(result.value, str):
            raise ValueError(
                'Expected str when reading co_name; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_names(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_names')
        if (not isinstance(result.value, tuple) or
                not all(isinstance(elt, str) for elt in result.value)):
            raise ValueError(
                'Expected tuple of strings when reading co_names; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_nlocals(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_nlocals')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_nlocals; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_stacksize(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_stacksize')
        if not isinstance(result.value, int):
            raise ValueError(
                'Expected int when reading co_stacksize; got '
                f'{type(result.value)} instead')

        return result

    def _read_co_varnames(
        self
    ) -> CodeObjectFieldInjectionWalker:
        result = self._read_code_field('co_varnames')
        if (not isinstance(result.value, tuple) or
                not all(isinstance(elt, str) for elt in result.value)):
            raise ValueError(
                'Expected tuple of strings when reading co_varnames; got '
                f'{type(result.value)} instead')

        return result

    def __str__(
        self
    ) -> str:
        return f'Injected code object with string {self._injection_str}'
