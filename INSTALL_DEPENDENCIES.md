# Templar Dependencies Installation Guide

## Quick Start

### Windows
```powershell
# Run as Administrator
cd katana
.\scripts\install_tools.bat
```

### Linux / macOS
```bash
cd katana
bash scripts/install_tools.sh
```

## Manual Installation

### Required Tools

#### Wappalyzer (Technology Fingerprinting)
Wappalyzer identifies web technologies, frameworks, and servers.

**Install via npm:**
```bash
npm install -g wappalyzer
```

**Verify:**
```bash
wappalyzer --version
```

### Optional But Recommended Tools

#### Amass (Subdomain Enumeration)
The current test run shows: `exec: "amass": executable file not found in %PATH%`

**Install on Windows (via Chocolatey):**
```bash
choco install amass
```

**Install on Linux/macOS (via Go):**
```bash
go install github.com/owasp/amass/v4/cmd/amass@latest
```

**Verify:**
```bash
amass --version
```

**Alternative:** Download pre-built binaries from https://github.com/owasp/amass/releases

---

#### httpx (HTTP Probing)
Validates which discovered URLs are actually alive and reachable.

**Install via Go:**
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**Verify:**
```bash
httpx -version
```

---

#### nuclei (Vulnerability Scanning)
The current test run shows nuclei timing out after 600s. Installing the latest version may help:

**Install via Go:**
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Verify:**
```bash
nuclei -version
```

**Update templates (recommended):**
```bash
nuclei -update-templates
```

**Note:** nuclei requires downloading vulnerability templates. First run will download ~2GB of data.

---

#### gau (URL Enumeration)
The current test run shows: `tool gau timed out after 60 seconds`

**Install via Go:**
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

**Verify:**
```bash
gau --version
```

---

## Troubleshooting

### "executable file not found in %PATH%"
The tool was installed but not in your system PATH.

**Solution:** 
1. Verify installation location
2. Add the installation directory to your PATH environment variable
3. Restart your terminal/IDE

### npm install -g fails (permission denied)
**Solution for Windows:** Run Command Prompt/PowerShell as Administrator

**Solution for Linux/macOS:** Use `sudo` or configure npm to use a different directory:
```bash
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH
```

### Go tools not found after installation
**Solution:** Ensure `$GOPATH/bin` is in your PATH:
```bash
export PATH=$GOPATH/bin:$PATH
# On Windows: Add C:\Users\<username>\go\bin to PATH
```

---

## Verifying All Tools

Run this to check which tools are available:

**Windows (PowerShell):**
```powershell
$tools = "wappalyzer", "amass", "httpx", "nuclei", "gau"
foreach ($tool in $tools) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        Write-Host "$tool: ✓ installed" -ForegroundColor Green
        & $tool --version 2>$null
    } else {
        Write-Host "$tool: ✗ not found" -ForegroundColor Red
    }
}
```

**Linux/macOS (Bash):**
```bash
for tool in wappalyzer amass httpx nuclei gau; do
    if command -v $tool &> /dev/null; then
        echo "$tool: ✓ installed"
        $tool --version 2>/dev/null || true
    else
        echo "$tool: ✗ not found"
    fi
done
```

---

## Configuration Adjustments Made

### 1. Reduced LLM Tokens (OpenRouter Credits)
**File:** `configs/gruyere_test.yaml`

Changed:
```yaml
max_tokens: 2048  # OLD - caused 402 credit error
max_tokens: 1024  # NEW - fits within available credits
```

This allows the LLM calls to fit within your current OpenRouter balance. Error message was:
```
HTTP 402: This request requires more credits, or fewer max_tokens. 
You requested up to 2048 tokens, but can only afford 1961.
```

### 2. Improved Fingerprinting Error Handling
**File:** `internal/preceptor/cartographer/fingerprint.go`

Enhanced:
- ✓ Validates hosts list before processing
- ✓ Skips hosts with no open ports
- ✓ Gracefully handles missing wappalyzer tool
- ✓ Logs detailed error messages for debugging
- ✓ Shows which targets are being fingerprinted

Previously showed "Discovered 0 TechStack entries" with no explanation.

---

## Next Steps After Installation

1. **Verify all tools are in PATH:**
   ```bash
   wappalyzer --version
   ```

2. **Run the test again:**
   ```powershell
   .\run_templar.ps1 crusade start --config configs/gruyere_test.yaml
   ```

3. **Monitor the output:**
   - Should see more detailed fingerprinting debug output
   - Should see which targets are being scanned
   - Should have better error messages if tools are missing

4. **Check for nuclei template download:**
   - First nuclei run downloads ~2GB of templates
   - This may take several minutes
   - Can be done manually: `nuclei -update-templates`

---

## Environment Variables

Make sure these are set before running crusade:

```bash
# OpenRouter API key (for LLM calls)
$env:OPENROUTER_API_KEY = "sk-or-v1-..."

# HackerOne API key (optional, if enabled in config)
$env:HACKERONE_API_KEY = "your-api-key"

# GitHub token (optional, if enabled in config)
$env:GITHUB_TOKEN = "ghp_..."
```

---

## Additional Resources

- **Wappalyzer Documentation:** https://www.wappalyzer.com/docs
- **Amass Documentation:** https://github.com/owasp/amass/wiki
- **ProjectDiscovery Tools:** https://projectdiscovery.io/
- **Go Installation:** https://golang.org/doc/install
- **Node.js Installation:** https://nodejs.org/
