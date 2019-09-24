<p align="center">
  <img width="345" height="80" src="static/logo.png" alt="formatic">
</p>

---

## Synopsis

`formatic` is a Python tool and library for automated traversal of Python [`format()` string](https://docs.python.org/3/library/string.html#string-formatting) injections, leaking system information of a vulnerable service.

## Installation

To install via pip:
```bash
pip install formatic
```

To install the latest version from source:
```bash
git clone https://github.com/welchbj/formatic
cd formatic
python setup.py
```

To install a development copy of the environment:
```bash
git clone https://github.com/welchbj/formatic
cd formatic
pip install -r dev-requirements.txt
```

## Usage

`formatic` is usable against Python programs that are vulnerable to `format()` string injections. A targeted application must also return the result of the format string injection to the user, so that `formatic` can process it.

`formatic` comes with a builtin harness for injecting into any program that can be called from the command-line. All you have to do is specify the command as you would invoke it from the terminal, marking the injectable field with the `{}` marker.

This repository contains a couple of applications that are vulnerable to `format()` string injections. To inject into a vulnerable local command-line program, try:
```bash
formatic -vv -- python demo/vulnerable_cli_app.py --inject {}
```

To inject into a vulnerable local web server, first run the server with:
```bash
python demo/vulnerable_web_app.py 8888
```

And then run `formatic` against it:
```bash
formatic -vv -- curl -g http://localhost:8888/inject/{}
```

## License

`formatic` is intended for educational purposes and events such as CTFs only and should never be run on machines and/or networks without explicit prior consent. This code is released under the [MIT license](https://opensource.org/licenses/MIT).

## Development

The following linting should be performed on any committed code:
```bash
# pep8 compliance
flake8 .

# type checking
mypy .
```

When it's time to cut a release:
```bash
# clean any old dist builds
rm -r dist/

# build source and wheel distributions
python setup.py bdist_wheel sdist

# run post-build checks
twine check dist/*

# upload to PyPI
twine upload dist/*
```

## References

The following resources were a great help in getting this project up and running:

* [James Bennett - A Bit about Bytes: Understanding Python Bytecode - PyCon 2018](https://www.youtube.com/watch?v=cSSpnq362Bk)
* [Stack Overflow - How to create a code object in Python](https://stackoverflow.com/questions/16064409/how-to-create-a-code-object-in-python)
