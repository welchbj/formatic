"""Implementation of the ModuleInjectionWalker class."""

import re

from typing import (
    Iterator)

from .abstract_injection_walker import (
    AbstractInjectionWalker)
from .failed_injection_walker import (
    FailedInjectionWalker)
from ..utils import (
    parse_dict_top_level_keys)

MODULE_RE = r'<module .+>'


class ModuleInjectionWalker(AbstractInjectionWalker):
    """An injection walker for recovering module data."""

    INJECTION_RE = None
    RESPONSE_RE = None

    # TODO: handle imports of other modules

    def __extra_init__(
        self
    ) -> None:
        # TODO
        pass

    def walk(
        self
    ) -> Iterator[AbstractInjectionWalker]:
        # TODO: where should we be collecting the module's data/functions/etc.?
        # TODO: find name first, determine if it is in the blacklist

        top_level_dict_keys = parse_dict_top_level_keys(self._raw_result)
        if not top_level_dict_keys:
            yield FailedInjectionWalker.msg(
                'Unable to parse dictionary keys from response '
                f'{self._raw_response} from injection {self._injection_str}')
            return

        for key in top_level_dict_keys:
            key_injection_str = f'{self._injection_str}[{key}]!r'
            result = self._harness.send_injection(key_injection_str)
            if result is None:
                yield FailedInjectionWalker.msg(
                    'Unable to recover response from injection string '
                    f'{key_injection_str}')
                continue

            next_walker = self.next_walker(key_injection_str, result)
            if next_walker is not None:
                yield from next_walker.walk()
            elif not re.search(MODULE_RE, result):
                yield FailedInjectionWalker.msg(
                    'Unable to find injection walker to handle response '
                    f'{result}')
            else:
                mod_dict_injection_str = (
                    f'{key_injection_str.rstrip("!r")}.__dict__')
                result = self._harness.send_injection(
                    mod_dict_injection_str)
                if result is None:
                    yield FailedInjectionWalker.msg(
                        'Unable to recover expected module __dict__ via '
                        f'injection string {mod_dict_injection_str}')
                print(f'TESTESTEST: {mod_dict_injection_str}')
                yield from ModuleInjectionWalker(
                    self._harness,
                    mod_dict_injection_str,
                    result,
                    self._bytecode_version,
                    self._engine).walk()
