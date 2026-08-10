#!/usr/bin/env python3
"""Protection report generator — thin CLI wrapper for lib.reports.protection."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.reports.protection import main

if __name__ == '__main__':
    main()
