#!/bin/bash
# Install script for Templar dependencies on Linux/macOS
# Run with: bash scripts/install_tools.sh

set -e

echo "========================================"
echo "Templar Tool Installation Script"
echo "========================================"
echo ""

# Check if Node.js is installed
echo "Checking for Node.js..."
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
else
    echo "OK: Node.js found"
    node --version
fi
echo ""

# Install Wappalyzer globally
echo "Installing Wappalyzer..."
if ! npm install -g wappalyzer; then
    echo "ERROR: Failed to install Wappalyzer"
    exit 1
fi
echo "OK: Wappalyzer installed"
echo ""

# Verify Wappalyzer installation
echo "Verifying Wappalyzer..."
if ! command -v wappalyzer &> /dev/null; then
    echo "WARNING: Wappalyzer installed but not found in PATH"
    echo "Try restarting your terminal or checking npm bin directory"
else
    echo "OK: Wappalyzer verified"
    wappalyzer --version
fi
echo ""

# Check for Amass (optional but recommended)
echo "Checking for Amass (subdomain enumeration)..."
if ! command -v amass &> /dev/null; then
    echo "INFO: Amass not found"
    echo "Install with: go install github.com/owasp/amass/v4/cmd/amass@latest"
    echo "Or via package manager (apt, brew, etc.)"
else
    echo "OK: Amass found"
    amass --version
fi
echo ""

# Check for httpx (recommended for probing)
echo "Checking for httpx (HTTP prober)..."
if ! command -v httpx &> /dev/null; then
    echo "INFO: httpx not found"
    echo "Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
else
    echo "OK: httpx found"
    httpx -version
fi
echo ""

# Check for nuclei (recommended for vulnerability scanning)
echo "Checking for nuclei (vulnerability scanner)..."
if ! command -v nuclei &> /dev/null; then
    echo "INFO: nuclei not found"
    echo "Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
else
    echo "OK: nuclei found"
    nuclei -version
fi
echo ""

echo "========================================"
echo "Installation Summary"
echo "========================================"
echo ""
echo "Required tools:"
echo "  - Wappalyzer (fingerprinting): INSTALLED"
echo ""
echo "Optional but recommended:"
echo "  - Amass (subdomain enumeration)"
echo "  - httpx (HTTP probing)"
echo "  - nuclei (vulnerability scanning)"
echo ""
echo "For more info, visit:"
echo "  - Wappalyzer: https://www.wappalyzer.com/"
echo "  - Amass: https://github.com/owasp/amass"
echo "  - httpx: https://github.com/projectdiscovery/httpx"
echo "  - nuclei: https://github.com/projectdiscovery/nuclei"
echo ""
