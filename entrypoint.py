#!/usr/bin/env python3
"""
ThirdGen Security Scanner Entrypoint
Wrapper script for Docker container
"""

import sys
sys.path.insert(0, '/app')

from audit.run_audit import main

if __name__ == "__main__":
    main()
