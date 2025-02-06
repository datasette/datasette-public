# datasette-public

[![PyPI](https://img.shields.io/pypi/v/datasette-public.svg)](https://pypi.org/project/datasette-public/)
[![Changelog](https://img.shields.io/github/v/release/datasette/datasette-public?include_prereleases&label=changelog)](https://github.com/datasette/datasette-public/releases)
[![Tests](https://github.com/datasette/datasette-public/workflows/Test/badge.svg)](https://github.com/datasette/datasette-public/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/datasette/datasette-public/blob/main/LICENSE)

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
To grant `datasette-public` permission to the root user run the following:

```bash
datasette --internal internal.db data.db --root -s permissions.datasette-public.id root
```

New database and table action menu items allow users with the `datasette-public` permission to toggle both tables and databases between public and private.

For databases, users can also select if the ability to execute arbitrary SQL should be exposed to the public.

If a table is public but the database is private, users will not we able to use the `?_where=` parameter on that table.

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
