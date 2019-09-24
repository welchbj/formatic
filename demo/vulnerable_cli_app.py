"""A simple command-line application vulnerable to format() injection."""

import base64
import sys

from argparse import (
    ArgumentParser)

MODULE_LEVEL_SECRET = b'TUVWXYZ'


def module_level_func(x, y, z):
    print(MODULE_LEVEL_SECRET)
    sys.exit(1)


class SomeClass:
    """SomeClass docstring...

    on

    multiple

    lines

    """
    pass


class Dummy(SomeClass):
    """Some documentation for the Dummy class."""
    CLASS_ATTR = 0xdeadbeef

    def __init__(self):
        x = 100
        self.y = x // 100
        self.z = '1234'

        s = SomeClass()

        def f(x, y):
            return 1 + 1

        f(s, 1)

    def test(a: str, b: int, c) -> str:
        d = a + str(b)
        b64 = base64.b64encode(d)
        c = reversed(b64)
        return str(c)


class SecretClass:
    def __init__(self):
        self.key = 'a-secret-key'

    def get_key(self):
        print('here is the key:')
        print(self.key)


def get_parsed_args():
    parser = ArgumentParser(
        prog='vulnerable_app.py',
        usage='vulnerable_app.py --inject INJECTION',
        description='an application vulnerable to format() string injection')

    parser.add_argument(
        '--inject',
        action='store',
        required=True,
        help='the string to pass as an injection')

    return parser.parse_args()


def main():
    opts = get_parsed_args()
    dummy = Dummy()
    print(opts.inject.format(dummy))


if __name__ == '__main__':
    sys.exit(main())
