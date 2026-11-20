"""Allow ``python -m maldoctrace ...`` as an alias for the ``maldoctrace`` command."""

import sys

from . import run


def main() -> int:
    return run(sys.argv[1:]).returncode


if __name__ == "__main__":
    sys.exit(main())
