#!/usr/bin/env bash
#
# ParamHarvest - Certificate Installation Script
# Generates and installs mitmproxy CA certificate for HTTPS interception
#
# Usage: ./install_cert.sh [--system|--browser|--all]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs"
MITMPROXY_CERT_DIR="${HOME}/.mitmproxy"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ParamHarvest - Certificate Installer                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "debian"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/arch-release ]; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Generate mitmproxy certificates
generate_certificates() {
    print_status "Generating mitmproxy certificates..."
    
    # Create cert directory
    mkdir -p "${CERT_DIR}"
    
    # Check if mitmproxy certs already exist
    if [ -f "${MITMPROXY_CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
        print_status "Mitmproxy certificates already exist"
        cp "${MITMPROXY_CERT_DIR}/mitmproxy-ca-cert.pem" "${CERT_DIR}/"
        cp "${MITMPROXY_CERT_DIR}/mitmproxy-ca-cert.cer" "${CERT_DIR}/" 2>/dev/null || true
    else
        print_status "Running mitmproxy once to generate certificates..."
        # Run mitmproxy briefly to generate certs
        timeout 2 mitmdump --quiet || true
        
        if [ -f "${MITMPROXY_CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
            cp "${MITMPROXY_CERT_DIR}/mitmproxy-ca-cert.pem" "${CERT_DIR}/"
            print_status "Certificates generated successfully"
        else
            print_error "Failed to generate certificates"
            exit 1
        fi
    fi
    
    # Create .cer version for Windows/macOS
    if [ -f "${CERT_DIR}/mitmproxy-ca-cert.pem" ]; then
        cp "${CERT_DIR}/mitmproxy-ca-cert.pem" "${CERT_DIR}/mitmproxy-ca-cert.cer"
    fi
    
    print_status "Certificates saved to: ${CERT_DIR}/"
}

# Install certificate on Linux (Debian/Ubuntu)
install_linux_debian() {
    print_status "Installing certificate on Debian/Ubuntu..."
    
    CERT_SOURCE="${CERT_DIR}/mitmproxy-ca-cert.pem"
    CERT_DEST="/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
    
    if [ ! -f "$CERT_SOURCE" ]; then
        print_error "Certificate not found. Run with --generate first."
        exit 1
    fi
    
    sudo cp "$CERT_SOURCE" "$CERT_DEST"
    sudo update-ca-certificates
    
    print_status "Certificate installed to system trust store"
}

# Install certificate on Linux (RedHat/CentOS)
install_linux_redhat() {
    print_status "Installing certificate on RedHat/CentOS..."
    
    CERT_SOURCE="${CERT_DIR}/mitmproxy-ca-cert.pem"
    CERT_DEST="/etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem"
    
    if [ ! -f "$CERT_SOURCE" ]; then
        print_error "Certificate not found. Run with --generate first."
        exit 1
    fi
    
    sudo cp "$CERT_SOURCE" "$CERT_DEST"
    sudo update-ca-trust
    
    print_status "Certificate installed to system trust store"
}

# Install certificate on Linux (Arch)
install_linux_arch() {
    print_status "Installing certificate on Arch Linux..."
    
    CERT_SOURCE="${CERT_DIR}/mitmproxy-ca-cert.pem"
    CERT_DEST="/etc/ca-certificates/trust-source/anchors/mitmproxy-ca-cert.pem"
    
    if [ ! -f "$CERT_SOURCE" ]; then
        print_error "Certificate not found. Run with --generate first."
        exit 1
    fi
    
    sudo cp "$CERT_SOURCE" "$CERT_DEST"
    sudo trust extract-compat
    
    print_status "Certificate installed to system trust store"
}

# Install certificate on macOS
install_macos() {
    print_status "Installing certificate on macOS..."
    
    CERT_SOURCE="${CERT_DIR}/mitmproxy-ca-cert.pem"
    
    if [ ! -f "$CERT_SOURCE" ]; then
        print_error "Certificate not found. Run with --generate first."
        exit 1
    fi
    
    # Add to system keychain and trust
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$CERT_SOURCE"
    
    print_status "Certificate installed to macOS System Keychain"
}

# Print browser installation instructions
print_browser_instructions() {
    CERT_PATH="${CERT_DIR}/mitmproxy-ca-cert.pem"
    
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Browser Certificate Installation Instructions${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}Certificate Location:${NC} ${CERT_PATH}"
    echo ""
    
    echo -e "${YELLOW}Chrome / Brave / Edge:${NC}"
    echo "  1. Navigate to: chrome://settings/certificates"
    echo "  2. Click 'Authorities' tab"
    echo "  3. Click 'Import'"
    echo "  4. Select: ${CERT_PATH}"
    echo "  5. Check 'Trust this certificate for identifying websites'"
    echo "  6. Click OK"
    echo ""
    
    echo -e "${YELLOW}Firefox:${NC}"
    echo "  1. Navigate to: about:preferences#privacy"
    echo "  2. Scroll to 'Certificates' section"
    echo "  3. Click 'View Certificates'"
    echo "  4. Click 'Authorities' tab"
    echo "  5. Click 'Import'"
    echo "  6. Select: ${CERT_PATH}"
    echo "  7. Check 'Trust this CA to identify websites'"
    echo "  8. Click OK"
    echo ""
    
    echo -e "${YELLOW}Alternatively - Quick Method:${NC}"
    echo "  1. Start ParamHarvest: mitmdump -s paramharvest.py"
    echo "  2. Configure browser proxy to 127.0.0.1:8080"
    echo "  3. Visit: http://mitm.it"
    echo "  4. Download and install certificate for your platform"
    echo ""
}

# Print proxy configuration instructions
print_proxy_instructions() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Proxy Configuration Instructions${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${GREEN}Proxy Address:${NC} 127.0.0.1:8080"
    echo ""
    
    echo -e "${YELLOW}Option 1: Browser Extension (Recommended)${NC}"
    echo "  Install 'Proxy SwitchyOmega' extension:"
    echo "    Chrome: https://chrome.google.com/webstore/detail/proxy-switchyomega"
    echo "    Firefox: https://addons.mozilla.org/firefox/addon/switchyomega"
    echo ""
    echo "  Configuration:"
    echo "    1. Click extension icon → Options"
    echo "    2. Create new profile (e.g., 'ParamHarvest')"
    echo "    3. Set Protocol: HTTP"
    echo "    4. Set Server: 127.0.0.1"
    echo "    5. Set Port: 8080"
    echo "    6. Save and activate profile when testing"
    echo ""
    
    echo -e "${YELLOW}Option 2: System Proxy (Linux)${NC}"
    echo "  export http_proxy=http://127.0.0.1:8080"
    echo "  export https_proxy=http://127.0.0.1:8080"
    echo ""
    
    echo -e "${YELLOW}Option 3: System Proxy (macOS)${NC}"
    echo "  System Preferences → Network → Advanced → Proxies"
    echo "  Enable 'Web Proxy (HTTP)' and 'Secure Web Proxy (HTTPS)'"
    echo "  Set both to 127.0.0.1:8080"
    echo ""
    
    echo -e "${YELLOW}Option 4: System Proxy (Windows)${NC}"
    echo "  Settings → Network & Internet → Proxy"
    echo "  Enable 'Use a proxy server'"
    echo "  Address: 127.0.0.1, Port: 8080"
    echo ""
}

# Main
main() {
    print_banner
    
    OS=$(detect_os)
    print_status "Detected OS: ${OS}"
    
    ACTION="${1:---all}"
    
    case "$ACTION" in
        --generate|-g)
            generate_certificates
            ;;
        --system|-s)
            generate_certificates
            case "$OS" in
                debian) install_linux_debian ;;
                redhat) install_linux_redhat ;;
                arch) install_linux_arch ;;
                macos) install_macos ;;
                *)
                    print_warning "System installation not supported for: ${OS}"
                    print_warning "Please install certificate manually"
                    ;;
            esac
            ;;
        --browser|-b)
            generate_certificates
            print_browser_instructions
            ;;
        --proxy|-p)
            print_proxy_instructions
            ;;
        --all|-a)
            generate_certificates
            case "$OS" in
                debian) install_linux_debian ;;
                redhat) install_linux_redhat ;;
                arch) install_linux_arch ;;
                macos) install_macos ;;
                *)
                    print_warning "System installation not supported for: ${OS}"
                    ;;
            esac
            print_browser_instructions
            print_proxy_instructions
            ;;
        --help|-h)
            echo "Usage: $0 [OPTION]"
            echo ""
            echo "Options:"
            echo "  -g, --generate   Generate certificates only"
            echo "  -s, --system     Install to system trust store"
            echo "  -b, --browser    Show browser installation instructions"
            echo "  -p, --proxy      Show proxy configuration instructions"
            echo "  -a, --all        Do everything (default)"
            echo "  -h, --help       Show this help"
            ;;
        *)
            print_error "Unknown option: $ACTION"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
    
    echo ""
    print_status "Done!"
}

main "$@"
