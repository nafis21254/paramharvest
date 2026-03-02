#!/usr/bin/env python3
"""
ParamHarvest - Core Interception Engine
A mitmproxy addon for automated parameter discovery and logging.

Author: Security Research Team
License: MIT
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse
from collections import defaultdict

from mitmproxy import http, ctx
from colorama import Fore, Style, init

# Initialize colorama for cross-platform terminal colors
init(autoreset=True)


class RiskTagger:
    """Automated parameter risk classification based on naming patterns."""
    
    RISK_PATTERNS = {
        "IDOR": {
            "patterns": [
                r"^(id|user_?id|account_?id|profile_?id|uuid|uid|pid|oid)$",
                r"^(customer|member|employee|admin|owner)_?id$",
                r"^(record|item|order|invoice|ticket)_?id$",
            ],
            "color": Fore.RED,
            "severity": "HIGH"
        },
        "LFI/RFI": {
            "patterns": [
                r"^(file|path|dir|directory|folder|filename|filepath)$",
                r"^(url|uri|redirect|return_?url|next|goto|dest|destination)$",
                r"^(include|require|load|read|fetch|import|template|view)$",
                r"^(doc|document|page|module|action|handler)$",
            ],
            "color": Fore.MAGENTA,
            "severity": "HIGH"
        },
        "CMD_INJECTION": {
            "patterns": [
                r"^(cmd|command|exec|execute|run|shell|system|proc|process)$",
                r"^(query|search|filter|sort|order_?by|group_?by)$",
                r"^(ping|host|ip|dns|nslookup|dig|traceroute)$",
            ],
            "color": Fore.YELLOW,
            "severity": "CRITICAL"
        },
        "SQLI": {
            "patterns": [
                r"^(select|where|table|column|db|database|schema)$",
                r"^(limit|offset|sort|order|group|having)$",
            ],
            "color": Fore.CYAN,
            "severity": "HIGH"
        },
        "XSS": {
            "patterns": [
                r"^(q|query|search|keyword|term|text|message|comment|content)$",
                r"^(name|title|description|label|caption|alt)$",
                r"^(callback|jsonp|cb|handler|function)$",
            ],
            "color": Fore.GREEN,
            "severity": "MEDIUM"
        },
        "AUTH": {
            "patterns": [
                r"^(token|api_?key|auth|session|jwt|bearer|credential)$",
                r"^(password|passwd|pwd|secret|private)$",
                r"^(username|user|login|email|account)$",
            ],
            "color": Fore.BLUE,
            "severity": "INFO"
        }
    }
    
    def __init__(self):
        # Pre-compile all regex patterns for performance
        self.compiled_patterns = {}
        for risk_type, config in self.RISK_PATTERNS.items():
            self.compiled_patterns[risk_type] = [
                re.compile(p, re.IGNORECASE) for p in config["patterns"]
            ]
    
    def classify(self, param_name: str) -> list[dict]:
        """Classify a parameter and return all matching risk tags."""
        tags = []
        param_lower = param_name.lower()
        
        for risk_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.match(param_lower):
                    config = self.RISK_PATTERNS[risk_type]
                    tags.append({
                        "type": risk_type,
                        "severity": config["severity"],
                        "color": config["color"]
                    })
                    break  # One match per risk type is enough
        
        return tags


class ParamHarvester:
    """
    Main mitmproxy addon for parameter harvesting.
    
    Features:
    - Multi-source extraction (GET, POST, JSON)
    - Smart deduplication via hashing
    - Contextual risk tagging
    - Live reflection detection
    - Structured output for fuzzing tools
    """
    
    def __init__(
        self,
        domain_filter: Optional[str] = None,
        output_dir: str = "./logs",
        check_reflection: bool = False,
        verbose: bool = True
    ):
        self.domain_filter = domain_filter
        self.output_dir = output_dir
        self.check_reflection = check_reflection
        self.verbose = verbose
        
        # Deduplication storage
        self.seen_hashes: set[str] = set()
        self.parameters: list[dict] = []
        self.unique_keys: set[str] = set()
        
        # Statistics
        self.stats = defaultdict(int)
        
        # Risk tagger
        self.tagger = RiskTagger()
        
        # Output files
        self.json_file = f"{output_dir}/raw_params.json"
        self.txt_file = f"{output_dir}/fuzz_list.txt"
        
        self._print_banner()
    
    def _print_banner(self):
        """Display startup banner."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗{Fore.CYAN}                 ║
║  {Fore.WHITE}██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║{Fore.CYAN}                 ║
║  {Fore.WHITE}██████╔╝███████║██████╔╝███████║██╔████╔██║{Fore.CYAN}                 ║
║  {Fore.WHITE}██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║{Fore.CYAN}                 ║
║  {Fore.WHITE}██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║{Fore.CYAN}                 ║
║  {Fore.WHITE}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{Fore.CYAN}                 ║
║  {Fore.YELLOW}H A R V E S T{Fore.CYAN}  - Parameter Discovery Engine              ║
╠══════════════════════════════════════════════════════════════╣
║  {Fore.GREEN}[+]{Fore.WHITE} Domain Filter: {Fore.YELLOW}{self.domain_filter or 'ALL'}{Fore.CYAN}
║  {Fore.GREEN}[+]{Fore.WHITE} Output Dir: {Fore.YELLOW}{self.output_dir}{Fore.CYAN}
║  {Fore.GREEN}[+]{Fore.WHITE} Reflection Check: {Fore.YELLOW}{self.check_reflection}{Fore.CYAN}
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def _generate_hash(self, method: str, path: str, param_key: str) -> str:
        """Generate unique hash for deduplication."""
        unique_str = f"{method}|{path}|{param_key}"
        return hashlib.md5(unique_str.encode()).hexdigest()
    
    def _should_process(self, flow: http.HTTPFlow) -> bool:
        """Check if request should be processed based on domain filter."""
        if not self.domain_filter:
            return True
        
        host = flow.request.host
        return self.domain_filter.lower() in host.lower()
    
    def _extract_json_params(
        self, 
        data: Any, 
        prefix: str = "",
        params: Optional[list] = None
    ) -> list[tuple[str, Any]]:
        """Recursively extract parameters from nested JSON."""
        if params is None:
            params = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._extract_json_params(value, full_key, params)
                else:
                    params.append((full_key, value))
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                full_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    self._extract_json_params(item, full_key, params)
                else:
                    params.append((full_key, item))
        
        return params
    
    def _check_reflection(
        self, 
        param_value: str, 
        response_body: str
    ) -> bool:
        """Check if parameter value is reflected in response (potential XSS/SSTI)."""
        if not param_value or not response_body:
            return False
        
        # Skip very short or common values
        if len(str(param_value)) < 4:
            return False
        
        return str(param_value) in response_body
    
    def _log_parameter(
        self,
        method: str,
        url: str,
        path: str,
        param_key: str,
        param_value: Any,
        source: str,
        reflected: bool = False
    ):
        """Log a unique parameter with deduplication."""
        # Generate dedup hash
        param_hash = self._generate_hash(method, path, param_key)
        
        if param_hash in self.seen_hashes:
            self.stats["duplicates"] += 1
            return
        
        self.seen_hashes.add(param_hash)
        
        # Classify risk
        risk_tags = self.tagger.classify(param_key)
        
        # Build parameter record
        param_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "url": url,
            "path": path,
            "key": param_key,
            "value": str(param_value)[:500],  # Truncate long values
            "source": source,
            "hash": param_hash,
            "risk_tags": [t["type"] for t in risk_tags],
            "reflected": reflected
        }
        
        self.parameters.append(param_record)
        
        # Extract base key for fuzz list (remove array indices and nested paths)
        base_key = param_key.split("[")[0].split(".")[-1]
        self.unique_keys.add(base_key)
        
        # Update stats
        self.stats["total"] += 1
        self.stats[source] += 1
        
        # Print if verbose
        if self.verbose:
            self._print_param(param_record, risk_tags, reflected)
    
    def _print_param(
        self, 
        record: dict, 
        risk_tags: list[dict], 
        reflected: bool
    ):
        """Pretty print discovered parameter."""
        # Risk tag display
        tag_str = ""
        if risk_tags:
            tags = [f"{t['color']}[{t['type']}]{Style.RESET_ALL}" for t in risk_tags]
            tag_str = " ".join(tags)
        
        # Reflection indicator
        reflect_str = f" {Fore.RED}⚡REFLECTED{Style.RESET_ALL}" if reflected else ""
        
        # Method color
        method_colors = {
            "GET": Fore.GREEN,
            "POST": Fore.YELLOW,
            "PUT": Fore.BLUE,
            "DELETE": Fore.RED,
            "PATCH": Fore.MAGENTA
        }
        method_color = method_colors.get(record["method"], Fore.WHITE)
        
        print(
            f"{Fore.CYAN}[{record['timestamp'][11:19]}]{Style.RESET_ALL} "
            f"{method_color}{record['method']}{Style.RESET_ALL} "
            f"{Fore.WHITE}{record['path'][:50]}{Style.RESET_ALL} "
            f"| {Fore.YELLOW}{record['source']}{Style.RESET_ALL} "
            f"| {Fore.GREEN}{record['key']}{Style.RESET_ALL}"
            f"={Fore.CYAN}{record['value'][:30]}{Style.RESET_ALL} "
            f"{tag_str}{reflect_str}"
        )
    
    def request(self, flow: http.HTTPFlow):
        """Process incoming request - extract parameters."""
        if not self._should_process(flow):
            return
        
        request = flow.request
        method = request.method
        url = request.pretty_url
        parsed = urlparse(url)
        path = parsed.path
        
        # 1. Extract URL Query Parameters (GET)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for key, values in query_params.items():
                for value in values:
                    self._log_parameter(
                        method, url, path, key, value, "QUERY"
                    )
        
        # 2. Extract Form Data (POST)
        content_type = request.headers.get("content-type", "")
        
        if "application/x-www-form-urlencoded" in content_type:
            try:
                form_data = parse_qs(
                    request.get_text(), 
                    keep_blank_values=True
                )
                for key, values in form_data.items():
                    for value in values:
                        self._log_parameter(
                            method, url, path, key, value, "FORM"
                        )
            except Exception as e:
                ctx.log.warn(f"Failed to parse form data: {e}")
        
        # 3. Extract JSON Body Parameters
        elif "application/json" in content_type:
            try:
                json_data = request.json()
                json_params = self._extract_json_params(json_data)
                for key, value in json_params:
                    self._log_parameter(
                        method, url, path, key, value, "JSON"
                    )
            except Exception as e:
                ctx.log.warn(f"Failed to parse JSON: {e}")
        
        # 4. Extract multipart form data
        elif "multipart/form-data" in content_type:
            try:
                multipart = request.multipart_form
                if multipart:
                    for key, value in multipart.items():
                        if isinstance(value, bytes):
                            value = "<binary_data>"
                        self._log_parameter(
                            method, url, path, key, value, "MULTIPART"
                        )
            except Exception as e:
                ctx.log.warn(f"Failed to parse multipart: {e}")
    
    def response(self, flow: http.HTTPFlow):
        """Process response - check for parameter reflection."""
        if not self.check_reflection:
            return
        
        if not self._should_process(flow):
            return
        
        try:
            response_text = flow.response.get_text()
            if not response_text:
                return
            
            # Check recent parameters for reflection
            for param in self.parameters[-50:]:  # Check last 50 params
                if param.get("reflected"):
                    continue
                
                if self._check_reflection(param["value"], response_text):
                    param["reflected"] = True
                    self.stats["reflected"] += 1
                    
                    if self.verbose:
                        print(
                            f"{Fore.RED}[!] REFLECTION DETECTED: "
                            f"{param['key']}={param['value'][:30]}... "
                            f"in {flow.request.pretty_url[:50]}{Style.RESET_ALL}"
                        )
        
        except Exception as e:
            ctx.log.warn(f"Reflection check failed: {e}")
    
    def done(self):
        """Called when mitmproxy shuts down - save all data."""
        self._save_output()
        self._print_summary()
    
    def _save_output(self):
        """Save collected parameters to files."""
        # Save structured JSON
        output_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "domain_filter": self.domain_filter,
                "total_unique_params": len(self.parameters),
                "total_unique_keys": len(self.unique_keys),
                "statistics": dict(self.stats)
            },
            "parameters": self.parameters
        }
        
        with open(self.json_file, "w") as f:
            json.dump(output_data, f, indent=2)
        
        # Save fuzz wordlist
        with open(self.txt_file, "w") as f:
            for key in sorted(self.unique_keys):
                f.write(f"{key}\n")
        
        print(f"\n{Fore.GREEN}[+] Output saved:{Style.RESET_ALL}")
        print(f"    JSON: {self.json_file}")
        print(f"    Wordlist: {self.txt_file}")
    
    def _print_summary(self):
        """Print session summary statistics."""
        summary = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}SESSION SUMMARY{Fore.CYAN}                                             ║
╠══════════════════════════════════════════════════════════════╣
║  {Fore.GREEN}Total Unique Parameters:{Fore.WHITE} {self.stats['total']:<10}{Fore.CYAN}                       ║
║  {Fore.GREEN}Unique Parameter Keys:{Fore.WHITE}   {len(self.unique_keys):<10}{Fore.CYAN}                       ║
║  {Fore.GREEN}Duplicates Skipped:{Fore.WHITE}      {self.stats['duplicates']:<10}{Fore.CYAN}                       ║
╠══════════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}By Source:{Fore.CYAN}                                                  ║
║    QUERY:     {self.stats['QUERY']:<10}                                     ║
║    FORM:      {self.stats['FORM']:<10}                                     ║
║    JSON:      {self.stats['JSON']:<10}                                     ║
║    MULTIPART: {self.stats['MULTIPART']:<10}                                     ║
╠══════════════════════════════════════════════════════════════╣
║  {Fore.RED}Reflected Parameters:{Fore.WHITE} {self.stats['reflected']:<10}{Fore.CYAN}                        ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(summary)


# Global addon instance (set by CLI)
addons = []
