"""tarsniff: check an npm package for malware before installing it (local, offline model)."""


def main() -> None:
    import sys

    from .cli import main as _main

    sys.exit(_main())
