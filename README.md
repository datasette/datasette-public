# datasette-public

[![PyPI](https://img.shields.io/pypi/v/datasette-public.svg)](https://pypi.org/project/datasette-public/)
[![Changelog](https://img.shields.io/github/v/release/simonw/datasette-public?include_prereleases&label=changelog)](https://github.com/simonw/datasette-public/releases)
[![Tests](https://github.com/simonw/datasette-public/workflows/Test/badge.svg)](https://github.com/simonw/datasette-public/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-public/blob/main/LICENSE)

Make specific Datasette tables visible to the public

## Installation

Install this plugin in the same environment as Datasette.
```bash
datasette install datasette-public
```
## Usage

This plugin can only be used with Datasette 1.0a+ and requires Datasette to be run with a persistent internal database:

```bash
datasette --internal internal.db data.db
```

A UI allows users with the `datasette-public` permission to toggle both tables and databases between public and private.

TODO: Make this true: Installing this plugin also causes `allow-sql` permission checks to fall back to checking if the user has access to the entire database. This is to avoid users with access to a single public table being able to access data from other tables using the `?_where=` query string parameter.

## Development

To set up this plugin locally, first checkout the code. Then create a new virtual environment:
```bash
cd datasette-public
python -m venv venv
source venv/bin/activate
```
Now install the dependencies and test dependencies:
```bash
pip install -e '.[test]'
```
To run the tests:
```bash
pytest
```
