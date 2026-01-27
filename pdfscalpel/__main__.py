"""Entry point for python -m pdfautopsy"""

import sys
from pdfscalpel.cli.main import cli

if __name__ == '__main__':
    sys.exit(cli())
