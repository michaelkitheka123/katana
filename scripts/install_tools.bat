@echo off
REM Install script for Templar dependencies on Windows
REM Run as Administrator from Command Prompt or PowerShell

echo ========================================
echo Templar Tool Installation Script
echo ========================================
echo.

REM Check if Node.js is installed
echo Checking for Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    exit /b 1
) else (
    echo OK: Node.js found
    node --version
)
echo.

REM Install Wappalyzer globally
echo Installing Wappalyzer...
call npm install -g wappalyzer
if %errorlevel% neq 0 (
    echo ERROR: Failed to install Wappalyzer
    exit /b 1
)
echo OK: Wappalyzer installed
echo.

REM Verify Wappalyzer installation
echo Verifying Wappalyzer...
wappalyzer --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Wappalyzer installed but not found in PATH
    echo Try restarting your terminal or adding npm bin directory to PATH
) else (
    echo OK: Wappalyzer verified
    wappalyzer --version
)
echo.

REM Check for Amass (optional but recommended)
echo Checking for Amass (subdomain enumeration)...
amass --version >nul 2>&1
if %errorlevel% neq 0 (
    echo INFO: Amass not found. Installing via Chocolatey (if available)...
    choco install amass -y >nul 2>&1
    if %errorlevel% neq 0 (
        echo INFO: Could not install Amass via Chocolatey
        echo Alternative: Download from https://github.com/owasp/amass/releases
    ) else (
        echo OK: Amass installed via Chocolatey
    )
) else (
    echo OK: Amass found
    amass --version
)
echo.

REM Check for httpx (recommended for probing)
echo Checking for httpx (HTTP prober)...
httpx -version >nul 2>&1
if %errorlevel% neq 0 (
    echo INFO: httpx not found
    echo Install Go from https://golang.org/
    echo Then run: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
) else (
    echo OK: httpx found
    httpx -version
)
echo.

echo ========================================
echo Installation Summary
echo ========================================
echo.
echo Required tools:
echo   - Wappalyzer (fingerprinting): INSTALLED
echo.
echo Optional but recommended:
echo   - Amass (subdomain enumeration)
echo   - httpx (HTTP probing)
echo   - nuclei (vulnerability scanning)
echo.
echo For more info, visit:
echo   - Wappalyzer: https://www.wappalyzer.com/
echo   - Amass: https://github.com/owasp/amass
echo   - httpx: https://github.com/projectdiscovery/httpx
echo   - nuclei: https://github.com/projectdiscovery/nuclei
echo.
