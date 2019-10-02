"""Default values for use in the CLI and library."""

from typing import (
    Set)

DEFAULT_INJECTION_MARKER = '@@'
DEFAULT_INJECTION_RESPONSE_MARKER_LEN = 16

DEFAULT_UNKNOWN_CLASS_NAME: str = '<UNKNOWN CLASS NAME>'
DEFAULT_UNKNOWN_DOC_STRING: str = '<UNKNOWN DOCSTRING>'
DEFAULT_UNKNOWN_ATTRIBUTE_VALUE: str = '<UNKNOWN ATTRIBUTE VALUE>'


DEFAULT_ATTRIBUTE_BLACKLIST: Set[str] = {
    '__weakref__',
}
DEFAULT_CLASS_BLACKLIST: Set[str] = {
    'object',
}
DEFAULT_MODULE_BLACKLIST: Set[str] = {
    '__future__',
    '_dummy_thread',
    '_thread',
    'abc',
    'aifc',
    'argparse',
    'array',
    'ast',
    'asynchat',
    'asyncio',
    'asyncore',
    'atexit',
    'audioop',
    'base64',
    'bdb',
    'binascii',
    'binhex',
    'bisect',
    'builtins',
    'bz2',
    'calendar',
    'cgi',
    'cgitb',
    'chunk',
    'cmath',
    'cmd',
    'code',
    'codecs',
    'codeop',
    'collections',
    'colorsys',
    'compileall',
    'configparser',
    'contextlib',
    'contextvars',
    'copy',
    'copyreg',
    'cProfile',
    'crypt',
    'csv',
    'ctypes',
    'curses',
    'curses.textpad',
    'dataclasses',
    'datetime',
    'dbm',
    'dbm.dumb',
    'dbm.gnu',
    'dbm.ndbm',
    'decimal',
    'difflib',
    'dis',
    'distutils',
    'doctest',
    'dummy_threading',
    'email',
    'encodings.idna',
    'encodings.mbcs',
    'encodings.utf_8_sig',
    'ensurepip',
    'enum',
    'errno',
    'faulthandler',
    'fcntl',
    'filecmp',
    'fileinput',
    'fnmatch',
    'formatter',
    'fractions',
    'ftplib',
    'functools',
    'gc',
    'getopt',
    'getpass',
    'gettext',
    'glob',
    'grp',
    'gzip',
    'hashlib',
    'heapq',
    'hmac',
    'html',
    'http',
    'imaplib',
    'imghdr',
    'imp',
    'importlib',
    'importlib.abc',
    'importlib.machinery',
    'importlib.resources',
    'importlib.util',
    'inspect',
    'io',
    'ipaddress',
    'itertools',
    'json',
    'json.tool',
    'keyword',
    'lib2to3',
    'linecache',
    'locale',
    'logging',
    'lzma',
    'macpath',
    'mailbox',
    'mailcap',
    'marshal',
    'math',
    'mimetypes',
    'mmap',
    'modulefinder',
    'msilib',
    'msvcrt',
    'multiprocessing',
    'multiprocessing.connection',
    'multiprocessing.dummy',
    'multiprocessing.managers',
    'multiprocessing.pool',
    'multiprocessing.sharedctypes',
    'netrc',
    'nis',
    'nntplib',
    'numbers',
    'operator',
    'optparse',
    'os',
    'ossaudiodev',
    'parser',
    'pathlib',
    'pdb',
    'pickle',
    'pickletools',
    'pipes',
    'pkgutil',
    'platform',
    'plistlib',
    'poplib',
    'posix',
    'pprint',
    'profile',
    'pstats',
    'pty',
    'pwd',
    'py_compile',
    'pyclbr',
    'pydoc',
    'queue',
    'quopri',
    'random',
    're',
    'readline',
    'reprlib',
    'resource',
    'rlcompleter',
    'runpy',
    'sched',
    'secrets',
    'select',
    'selectors',
    'shelve',
    'shlex',
    'shutil',
    'signal',
    'site',
    'smtpd',
    'smtplib',
    'sndhdr',
    'socket',
    'socketserver',
    'spwd',
    'sqlite3',
    'ssl',
    'stat',
    'statistics',
    'string',
    'stringprep',
    'struct',
    'subprocess',
    'sunau',
    'symbol',
    'symtable',
    'sys',
    'sysconfig',
    'syslog',
    'tabnanny',
    'tarfile',
    'telnetlib',
    'tempfile',
    'termios',
    'test',
    'test.support',
    'test.support.script_helper',
    'textwrap',
    'threading',
    'time',
    'timeit',
    'tkinter',
    'token',
    'tokenize',
    'trace',
    'traceback',
    'tracemalloc',
    'tty',
    'turtle',
    'turtledemo',
    'types',
    'typing',
    'unicodedata',
    'unittest',
    'urllib',
    'uu',
    'uuid',
    'venv',
    'warnings',
    'wave',
    'weakref',
    'webbrowser',
    'winreg',
    'winsound',
    'wsgiref',
    'wsgiref.handlers',
    'wsgiref.headers',
    'wsgiref.simple_server',
    'wsgiref.util',
    'wsgiref.validate',
    'xdrlib',
    'xml',
    'xml.parsers.expat',
    'xml.parsers.expat.errors',
    'xml.parsers.expat.model',
    'zipapp',
    'zipfile',
    'zipimport',
    'zlib',
}
