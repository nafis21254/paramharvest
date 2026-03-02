#!/usr/bin/env python3
"""
ParamHarvest - mitmproxy Entry Point

This script is loaded by mitmproxy/mitmdump as an addon.

Usage:
    mitmdump -s paramharvest.py
    mitmdump -s "paramharvest.py --domain target.com"
    mitmdump -s "paramharvest.py --domain target.com --reflection"
"""

import argparse
import os
import sys
from pathlib import Path

# Add src directory to path for imports
script_dir = Path(__file__).parent.absolute()
src_dir = script_dir / "src"
sys.path.insert(0, str(src_dir))

from param_harvester import ParamHarvester


def parse_addon_args():
    """Parse arguments passed to the addon script."""
    parser = argparse.ArgumentParser(add_help=False)
    
    parser.add_argument(
        "-d", "--domain",
        type=str,
        default=None,
        help="Filter by domain"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output directory"
    )
    
    parser.add_argument(
        "-r", "--reflection",
        action="store_true",
        default=False,
        help="Enable reflection checking"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Quiet mode"
    )
    
    # Parse known args only (mitmproxy may pass additional args)
    args, _ = parser.parse_known_args()
    return args


def setup_output_dir(base_path: str = None) -> str:
    """Setup and return output directory path."""
    if base_path:
        output_dir = Path(base_path)
    else:
        output_dir = script_dir / "logs"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    return str(output_dir.absolute())


# Parse arguments
args = parse_addon_args()

# Setup output directory
output_dir = setup_output_dir(args.output)

# Create the addon instance
harvester = ParamHarvester(
    domain_filter=args.domain,
    output_dir=output_dir,
    check_reflection=args.reflection,
    verbose=not args.quiet
)

# Register with mitmproxy
addons = [harvester]
