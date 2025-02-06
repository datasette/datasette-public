from setuptools import setup
import os

VERSION = "0.2.3"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="datasette-public",
    description="Make specific Datasette tables visible to the public",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/datasette/datasette-public",
    project_urls={
        "Issues": "https://github.com/datasette/datasette-public/issues",
        "CI": "https://github.com/datasette/datasette-public/actions",
        "Changelog": "https://github.com/datasette/datasette-public/releases",
    },
    license="Apache License, Version 2.0",
    classifiers=[
        "Framework :: Datasette",
        "License :: OSI Approved :: Apache Software License",
    ],
    version=VERSION,
    packages=["datasette_public"],
    entry_points={"datasette": ["public = datasette_public"]},
    install_requires=["datasette>=1.0a1"],
    extras_require={"test": ["pytest", "pytest-asyncio"]},
    package_data={"datasette_public": ["templates/*"]},
    python_requires=">=3.7",
)
