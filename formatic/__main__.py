"""Main entry-point for the command-line formatic program."""

import sys

from .cli import (
    main as cli_main)


def main():
    """The function pointed to in setup.py's console_scripts."""
    sys.exit(cli_main())


if __name__ == '__main__':
    main()
