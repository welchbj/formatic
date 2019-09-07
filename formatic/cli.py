"""Command-line interface for formatic."""

import sys

from argparse import (
    ArgumentParser,
    Namespace,
    RawTextHelpFormatter)
from functools import (
    partial)
from typing import (
    NoReturn)

from .harnesses import (
    SubprocessInjectionHarness)
from .injection_result import (
    InjectionResult)
from .injection_walker import (
    InjectionWalker)
from .version import (
    __version__)


DEFAULT_INJECTION_MARKER = '{}'

print_info = partial(print, '[*] ', sep='')
print_err = partial(print, '[!] ', sep='', file=sys.stderr)


class CustomArgumentParser(ArgumentParser):
    """ArgumentParser with custom error-handling functionality."""

    def error(
        self,
        message: str
    ) -> NoReturn:
        print_err('Error when argument-parsing - ', message)
        sys.exit(1)


def get_parsed_args(
) -> Namespace:
    """Get the parsed command-line arguments."""
    parser = CustomArgumentParser(
        prog='formatic',
        usage='formatic [OPTIONS] COMMAND',
        description=(r"""
            ___                                     _    _
          .' ..]                                   / |_ (_)
         _| |_   .--.   _ .--.  _ .--..--.   ,--. `| |-'__   .---.
        '-| |-'/ .'`\ \[ `/'`\][ `.-. .-. | `'_\ : | | [  | / /'`\]
          | |  | \__. | | |     | | | | | | // | |,| |, | | | \__.
         [___]  '.__.' [___]   [___||__||__]\'-;__/\__/[___]'.___.'

             automatic traversal of Python format() injections
"""),
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help='print verbose information')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    parser.add_argument(
        '-i', '--injection-marker',
        action='store',
        default=DEFAULT_INJECTION_MARKER,
        help='the symbol specified in the COMMAND argument, which will be\n'
             'where generated injection strings will be subsituted;\n'
             'defaults to ' + DEFAULT_INJECTION_MARKER)

    parser.add_argument(
        'command',
        nargs='+',
        metavar='COMMAND',
        help='the arguments of the command to run for injecting format\n'
             'strings into the vulnerable program; this will be run many\n'
             'times in order to fully enumerate the service')

    return parser.parse_args()


def main(
) -> int:
    try:
        opts = get_parsed_args()

        harness = SubprocessInjectionHarness(
            opts.injection_marker,
            opts.command)
        injection_walker = InjectionWalker(harness)

        print_info('Beginning enumeration of remote service...')

        result: InjectionResult
        for result in injection_walker.walk():
            if opts.verbose:
                print_info('Payload ', result.payload, ' resulted in below '
                           'response:')
                print(result.raw_result)

        print_info('Completed execution')
    except ValueError as e:
        print_err(e)
        return 1
    except Exception as e:
        print_err('Unknown exception occured; re-raising it!', file=sys.stderr)
        raise e

    return 0
