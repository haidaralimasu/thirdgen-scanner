#!/usr/bin/env python3
"""
Local runner for ThirdGen Security Scanner
Usage: python run_local.py [path/to/solidity/project]
"""

import os
import sys

# Add audit module to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Change to target directory if provided
if len(sys.argv) > 1:
    target_dir = sys.argv[1]
    if os.path.isdir(target_dir):
        os.chdir(target_dir)
        print(f"Scanning: {target_dir}")
    else:
        print(f"Error: {target_dir} is not a directory")
        sys.exit(1)

from audit.run_audit import main

if __name__ == "__main__":
    # Remove the target dir from argv so argparse doesn't see it
    if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
        sys.argv.pop(1)
    main()
