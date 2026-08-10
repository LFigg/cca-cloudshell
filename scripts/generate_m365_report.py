#!/usr/bin/env python3
"""M365 report generator — thin CLI wrapper for lib.reports.m365."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.reports.m365 import main

if __name__ == '__main__':
    main()
