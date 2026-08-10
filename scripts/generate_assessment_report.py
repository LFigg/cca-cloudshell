#!/usr/bin/env python3
"""Assessment report generator — thin CLI wrapper for lib.reports.assessment."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib.reports.assessment import main

if __name__ == '__main__':
    main()
