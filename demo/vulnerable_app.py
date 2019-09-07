"""A simple command-line application vulnerable to format() injection."""

import sys

from argparse import (
    ArgumentParser)


class Dummy:
    def __init__(self):
        pass


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
