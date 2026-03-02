#!/usr/bin/env python3
"""
ParamHarvest CLI - Command Line Interface
Provides argument parsing and mitmproxy integration.

Usage:
    paramharvest --domain example.com --output ./logs
    paramharvest --reflection --verbose
"""

import argparse
import os
import sys
from pathlib import Path

from colorama import Fore, Style, init

init(autoreset=True)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="paramharvest",
        description=(
            "ParamHarvest - Automated Parameter Discovery & Logging Engine\n"
            "A mitmproxy addon for extracting, deduplicating, and categorizing "
            "HTTP parameters for security testing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage - capture all parameters
  mitmdump -s paramharvest.py

  # Filter specific domain
  mitmdump -s "paramharvest.py --domain api.target.com"

  # Enable reflection checking
  mitmdump -s "paramharvest.py --reflection --domain target.com"

  # Custom output directory
  mitmdump -s "paramharvest.py --output /path/to/logs"

  # Quiet mode (no live output)
  mitmdump -s "paramharvest.py --quiet"

Security Disclaimer:
  This tool is intended for authorized security testing only.
  Always obtain proper authorization before testing any systems.
"""
    )
    
    parser.add_argument(
        "-d", "--domain",
        type=str,
        default=None,
        help="Filter parameters by domain (e.g., 'api.target.com')"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./logs",
        help="Output directory for logs (default: ./logs)"
    )
    
    parser.add_argument(
        "-r", "--reflection",
        action="store_true",
        default=False,
        help="Enable live reflection checking (potential XSS/SSTI detection)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Quiet mode - suppress live parameter output"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Proxy port (default: 8080, passed to mitmproxy)"
    )
    
    return parser.parse_args()


def ensure_output_dir(path: str) -> str:
    """Ensure output directory exists."""
    output_path = Path(path)
    output_path.mkdir(parents=True, exist_ok=True)
    return str(output_path.absolute())


def print_startup_info(args):
    """Print startup configuration info."""
    print(f"\n{Fore.GREEN}[*] ParamHarvest Configuration:{Style.RESET_ALL}")
    print(f"    Domain Filter: {args.domain or 'All domains'}")
    print(f"    Output Dir: {args.output}")
    print(f"    Reflection Check: {args.reflection}")
    print(f"    Verbose: {not args.quiet}")
    print(f"    Proxy Port: {args.port}")
    print()


def main():
    """Main entry point for CLI."""
    args = parse_args()
    
    # Ensure output directory exists
    output_dir = ensure_output_dir(args.output)
    
    # Print config
    print_startup_info(args)
    
    # Import and configure harvester
    from param_harvester import ParamHarvester
    
    harvester = ParamHarvester(
        domain_filter=args.domain,
        output_dir=output_dir,
        check_reflection=args.reflection,
        verbose=not args.quiet
    )
    
    return harvester


# This is used when running as a mitmproxy addon
def configure_addon():
    """Configure addon for mitmproxy script mode."""
    import sys
    
    # Parse args from sys.argv (mitmproxy passes script args)
    args = parse_args()
    
    # Ensure output directory
    output_dir = ensure_output_dir(args.output)
    
    # Create and return harvester
    from param_harvester import ParamHarvester
    
    return ParamHarvester(
        domain_filter=args.domain,
        output_dir=output_dir,
        check_reflection=args.reflection,
        verbose=not args.quiet
    )


if __name__ == "__main__":
    main()
