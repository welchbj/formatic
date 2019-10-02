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

from colorama import (
    Fore,
    init as colorama_init,
    Style)
from pygments import (
    highlight)
from pygments.formatters import (
    TerminalFormatter)
from pygments.lexers import (
    Python3Lexer)
from xdis.magics import (
    python_versions as supported_bytecode_versions)

from .defaults import (
    DEFAULT_INJECTION_MARKER,
    DEFAULT_INJECTION_RESPONSE_MARKER_LEN)
from .harnesses import (
    SubprocessInjectionHarness)
from .injection_engine import (
    InjectionEngine)
from .version import (
    __version__)
from .walkers import (
    ClassInjectionWalker,
    FailedInjectionWalker,
    FunctionInjectionWalker)


print_info = partial(print, Fore.CYAN + '[*] ' + Style.RESET_ALL, sep='')
print_warn = partial(print, Fore.YELLOW + '[#] ' + Style.RESET_ALL, sep='')
print_err = partial(print, Fore.RED + '[!] ' + Style.RESET_ALL, sep='',
                    file=sys.stderr)


def print_py_src(
    code: str
) -> None:
    """Print highlighted Python 3 source code to the terminal."""
    print(highlight(code, Python3Lexer(), TerminalFormatter()))


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
        '-v', '--verbosity',
        action='count',
        default=0,
        help='print verbose information (-vv prints more detail than -v)')

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
        '-d', '--injection-index',
        action='store',
        type=int,
        default=0,
        help='the index that is injectable in the targeted format string;\n'
             'if omitted, the index will be fuzzed')

    parser.add_argument(
        '-m', '--response-marker',
        action='store',
        required=False,
        help='if specified, this will be used in place of a random string\n'
             'to surround payloads sent to the target in order to ease\n'
             'parsing of injection responses; you would only need to specify\n'
             'this argument if your targeted application has very\n'
             'restrictive input filters')

    parser.add_argument(
        '-l', '--random-response-marker-length',
        action='store',
        default=DEFAULT_INJECTION_RESPONSE_MARKER_LEN,
        help='the length of the randomly-generated alphanumeric string that\n'
             'will be used to extract results from injected payload responses')

    parser.add_argument(
        '-b', '--bytecode_version',
        action='store',
        default='3.7',
        choices=sorted(supported_bytecode_versions),
        help='the Python bytecode version to use for function decompilation')

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
        colorama_init()
        opts = get_parsed_args()

        harness = SubprocessInjectionHarness(
            opts.command,
            injection_marker=opts.injection_marker,
            response_marker=opts.response_marker,
            rand_response_marker_len=opts.random_response_marker_length)
        injection_engine = InjectionEngine(harness)

        print_info('Beginning enumeration of remote service...')

        walker_iter = injection_engine.run(
            opts.injection_index, opts.bytecode_version)
        for walker in walker_iter:
            if opts.verbosity >= 1:
                if isinstance(walker, FailedInjectionWalker):
                    print_warn(walker)
                else:
                    print_info(walker)

            if opts.verbosity >= 2:
                if (isinstance(walker, ClassInjectionWalker) and
                        walker.src_code is not None):
                    print_info('Recovered class source code:')
                    print_py_src(walker.src_code)
                elif (isinstance(walker, FunctionInjectionWalker) and
                        walker.src_code is not None):
                    print_info('Recovered function source code:')
                    print_py_src(walker.src_code)

        print_info('Completed execution; see below for data dump')
        print(injection_engine)
    except ValueError as e:
        print_err(e)
        return 1
    except Exception as e:
        print_err('Unknown exception occured; re-raising it!', file=sys.stderr)
        raise e

    return 0
