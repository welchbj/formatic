"""A simple Flask web application vulnerable to format() injection."""

import sys

from flask import (
    Flask,
    request)


app = Flask(__name__)


@app.route('/')
def index():
    return 'Thanks for reqesting the index!'


@app.route('/inject/<page>')
def injection(page):
    return (
        'You requested the page ' + str(request.path) + ' from the '
        '{0} web app'
    ).format(app)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Expected one argument: the port number')

    port = int(sys.argv[1])
    app.run(port=port)
