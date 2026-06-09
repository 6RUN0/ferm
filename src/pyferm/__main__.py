"""Enable ``python -m pyferm`` by delegating to the CLI entry point."""

import sys

from pyferm.cli import main

if __name__ == "__main__":
    sys.exit(main())
