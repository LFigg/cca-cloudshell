#!/usr/bin/env python3
"""Cost report generator — thin CLI wrapper for lib.reports.cost."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.reports.cost import main

if __name__ == '__main__':
    main()
