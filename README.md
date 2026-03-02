# ParamHarvest 🎯

**Automated Parameter Discovery & Logging Engine**

A powerful mitmproxy-based interception tool designed for security researchers, penetration testers, and bug bounty hunters. ParamHarvest automatically captures, deduplicates, and categorizes every unique HTTP parameter encountered during a browsing session.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)

---

## 🚀 Features

- **Multi-Source Extraction**: Captures parameters from URL query strings (GET), form data (POST), JSON bodies (nested), and multipart uploads
- **Smart Deduplication**: Hash-based deduplication ensures each unique parameter is logged only once, even if encountered thousands of times
- **Risk Classification**: Automatically tags parameters based on potential vulnerability categories:
  - 🔴 **IDOR**: `id`, `user_id`, `account`, `uuid`
  - 🟣 **LFI/RFI**: `file`, `path`, `url`, `redirect`
  - 🟡 **Command Injection**: `cmd`, `exec`, `query`
  - 🔵 **SQLi**: `select`, `where`, `order_by`
  - 🟢 **XSS**: `q`, `search`, `callback`
- **Live Reflection Detection**: Optional real-time checking for parameter reflection in responses (potential XSS/SSTI)
- **Dual Output Formats**:
  - `raw_params.json`: Structured data for integration with other tools
  - `fuzz_list.txt`: Clean wordlist ready for ffuf, Burp Intruder, or custom fuzzing

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Certificate Setup](#-certificate-setup)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Integration](#-integration-with-fuzzing-tools)
- [Daemon Mode](#-daemon-mode)
- [Configuration](#-configuration)
- [Security Disclaimer](#-security-disclaimer)
- [License](#-license)

---

## ⚡ Quick Start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/paramharvest.git
cd paramharvest
pip install -r requirements.txt

# 2. Install certificates (required for HTTPS)
./scripts/install_cert.sh --all

# 3. Start harvesting
mitmdump -s paramharvest.py

# 4. Configure browser proxy to 127.0.0.1:8080 and browse!

# 5. Stop with Ctrl+C - outputs saved to ./logs/
```

---

## 📦 Installation

### Prerequisites

- Python 3.9+
- pip package manager
- A modern browser (Chrome, Firefox, Brave, Edge)

### Step-by-Step Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/paramharvest.git
cd paramharvest

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
mitmdump --version
```

---

## 🔐 Certificate Setup

ParamHarvest needs to intercept HTTPS traffic, which requires installing a trusted CA certificate.

### Automated Installation

```bash
# Full setup (generate + install + instructions)
./scripts/install_cert.sh --all

# Or step by step:
./scripts/install_cert.sh --generate   # Generate certificates
./scripts/install_cert.sh --system     # Install to system trust store
./scripts/install_cert.sh --browser    # Show browser instructions
./scripts/install_cert.sh --proxy      # Show proxy config instructions
```

### Manual Browser Installation

1. Start ParamHarvest: `mitmdump -s paramharvest.py`
2. Configure browser proxy to `127.0.0.1:8080`
3. Visit: **http://mitm.it**
4. Download and install the certificate for your platform
5. Restart browser

### Certificate Locations

| OS | System Trust Store Location |
|----|----------------------------|
| Ubuntu/Debian | `/usr/local/share/ca-certificates/` |
| RHEL/CentOS | `/etc/pki/ca-trust/source/anchors/` |
| Arch Linux | `/etc/ca-certificates/trust-source/anchors/` |
| macOS | System Keychain (via `security` command) |
| Windows | Certificate Manager (`certmgr.msc`) |

---

## 🎮 Usage

### Basic Usage

```bash
# Capture all parameters from all domains
mitmdump -s paramharvest.py

# Filter specific target domain
mitmdump -s "paramharvest.py --domain api.target.com"

# Enable reflection detection (finds potential XSS/SSTI)
mitmdump -s "paramharvest.py --domain target.com --reflection"

# Custom output directory
mitmdump -s "paramharvest.py --output /path/to/output"

# Quiet mode (no live output)
mitmdump -s "paramharvest.py --quiet"

# Custom proxy port
mitmdump --listen-port 9090 -s paramharvest.py
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--domain` | `-d` | Filter parameters by domain (substring match) |
| `--output` | `-o` | Output directory for logs (default: `./logs`) |
| `--reflection` | `-r` | Enable live reflection checking |
| `--quiet` | `-q` | Suppress live parameter output |

### Browser Proxy Configuration

#### Option 1: Proxy SwitchyOmega Extension (Recommended)

1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif) for Chrome/Brave/Edge
2. Create new profile named "ParamHarvest"
3. Set Protocol: `HTTP`, Server: `127.0.0.1`, Port: `8080`
4. Save and activate when testing

#### Option 2: System-Wide Proxy

```bash
# Linux/macOS (temporary)
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Windows (PowerShell)
$env:http_proxy = "http://127.0.0.1:8080"
$env:https_proxy = "http://127.0.0.1:8080"
```

---

## 📊 Output Formats

### raw_params.json

Structured JSON with full context for each parameter:

```json
{
  "metadata": {
    "generated_at": "2024-01-15T10:30:00.000000",
    "domain_filter": "api.target.com",
    "total_unique_params": 156,
    "total_unique_keys": 47,
    "statistics": {
      "total": 156,
      "duplicates": 1842,
      "QUERY": 89,
      "FORM": 34,
      "JSON": 33,
      "reflected": 3
    }
  },
  "parameters": [
    {
      "timestamp": "2024-01-15T10:25:33.123456",
      "method": "GET",
      "url": "https://api.target.com/users?id=123",
      "path": "/users",
      "key": "id",
      "value": "123",
      "source": "QUERY",
      "hash": "a1b2c3d4e5f6...",
      "risk_tags": ["IDOR"],
      "reflected": false
    }
  ]
}
```

### fuzz_list.txt

Clean wordlist ready for fuzzing tools:

```
id
user_id
account
email
search
page
limit
sort
callback
redirect_url
file
path
...
```

---

## 🔗 Integration with Fuzzing Tools

### ffuf

```bash
# Parameter discovery with ffuf
ffuf -w logs/fuzz_list.txt -u "https://target.com/api?FUZZ=test" -mc 200,301,302

# Combined with values
ffuf -w logs/fuzz_list.txt:PARAM -w values.txt:VAL \
     -u "https://target.com/api?PARAM=VAL" -mc all -fc 404
```

### Burp Suite

1. Open Burp Suite → Intruder
2. Load `logs/fuzz_list.txt` as payload list
3. Use for parameter bruteforcing or fuzzing

### sqlmap

```bash
# Extract parameters for specific endpoint from JSON
cat logs/raw_params.json | jq -r '.parameters[] | select(.path=="/login") | .key' > login_params.txt

# Use with sqlmap
sqlmap -u "https://target.com/login" --data="username=test&password=test" \
       --risk=3 --level=5
```

### Arjun

```bash
# Use discovered parameters as custom wordlist
arjun -u https://target.com/api -w logs/fuzz_list.txt
```

### Custom Python Script

```python
import json

with open('logs/raw_params.json') as f:
    data = json.load(f)

# Find all IDOR-tagged parameters
idor_params = [
    p for p in data['parameters'] 
    if 'IDOR' in p['risk_tags']
]

for p in idor_params:
    print(f"[IDOR] {p['method']} {p['path']} - {p['key']}={p['value']}")
```

---

## 🔄 Daemon Mode

Run ParamHarvest as a background service:

```bash
# Start daemon
./scripts/run_daemon.sh start

# Check status
./scripts/run_daemon.sh status

# View live logs
./scripts/run_daemon.sh logs

# Stop daemon
./scripts/run_daemon.sh stop

# Restart
./scripts/run_daemon.sh restart
```

### Environment Variables

```bash
# Configure via environment variables
export PARAMHARVEST_PORT=9090
export PARAMHARVEST_DOMAIN=target.com
export PARAMHARVEST_OUTPUT=/var/log/paramharvest
export PARAMHARVEST_REFLECTION=true

./scripts/run_daemon.sh start
```

### Systemd Service (Linux)

Create `/etc/systemd/system/paramharvest.service`:

```ini
[Unit]
Description=ParamHarvest Parameter Discovery Engine
After=network.target

[Service]
Type=simple
User=security
WorkingDirectory=/opt/paramharvest
ExecStart=/usr/bin/mitmdump --listen-port 8080 -s /opt/paramharvest/paramharvest.py --set quiet=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable paramharvest
sudo systemctl start paramharvest
```

---

## ⚙️ Configuration

### Risk Pattern Customization

Edit `src/param_harvester.py` to add custom risk patterns:

```python
RISK_PATTERNS = {
    "CUSTOM_RISK": {
        "patterns": [
            r"^(my_custom_param|another_param)$",
        ],
        "color": Fore.WHITE,
        "severity": "MEDIUM"
    },
    # ... existing patterns
}
```

### Filtering Specific Content Types

The tool automatically handles:
- `application/x-www-form-urlencoded` (form data)
- `application/json` (JSON bodies)
- `multipart/form-data` (file uploads)

---

## 🛡️ Security Disclaimer

> ⚠️ **IMPORTANT: This tool is intended for authorized security testing only.**

- **Always obtain explicit written permission** before testing any systems you don't own
- **Bug bounty programs**: Ensure the target is in scope before testing
- **Legal compliance**: Unauthorized access to computer systems is illegal in most jurisdictions
- **Responsible disclosure**: Report any vulnerabilities found through proper channels
- **Data handling**: Captured parameters may contain sensitive information - handle with care

**The authors are not responsible for any misuse of this tool.**

---

## 📁 Project Structure

```
paramharvest/
├── paramharvest.py          # Main mitmproxy entry point
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── .gitignore              # Git ignore rules
├── src/
│   ├── param_harvester.py  # Core interception logic
│   └── cli.py              # Command line interface
├── scripts/
│   ├── install_cert.sh     # Certificate installation
│   └── run_daemon.sh       # Daemon management
├── logs/                   # Output directory (gitignored)
│   ├── raw_params.json     # Structured output
│   └── fuzz_list.txt       # Wordlist output
└── certs/                  # Generated certificates (gitignored)
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [mitmproxy](https://mitmproxy.org/) - The powerful interactive HTTPS proxy
- [colorama](https://github.com/tartley/colorama) - Cross-platform colored terminal text
- The bug bounty community for inspiration and feedback

---

**Happy Hunting! 🎯**
