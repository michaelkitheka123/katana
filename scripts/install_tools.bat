@echo off
setlocal

set TOOLS=subfinder nuclei katana naabu httpx dnsx ffuf gau gospider
set TOTAL=9
set DONE=0

echo.
echo =====================================================
echo   TEMPLAR - Installing Security Tools
echo =====================================================
echo.

:: subfinder
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing subfinder...
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
if errorlevel 1 (echo   FAILED: subfinder) else (echo   OK: subfinder)

:: nuclei (clean cache first to fix any corrupted zip)
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing nuclei (cleaning cache first)...
go clean -modcache >nul 2>&1
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
if errorlevel 1 (echo   FAILED: nuclei) else (echo   OK: nuclei)

:: katana
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing katana...
go install github.com/projectdiscovery/katana/cmd/katana@latest
if errorlevel 1 (echo   FAILED: katana) else (echo   OK: katana)

:: naabu
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing naabu...
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
if errorlevel 1 (echo   FAILED: naabu) else (echo   OK: naabu)

:: httpx (PD version)
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing httpx (ProjectDiscovery)...
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
if errorlevel 1 (echo   FAILED: httpx) else (echo   OK: httpx)

:: dnsx
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing dnsx...
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
if errorlevel 1 (echo   FAILED: dnsx) else (echo   OK: dnsx)

:: ffuf
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing ffuf...
go install github.com/ffuf/ffuf/v2@latest
if errorlevel 1 (echo   FAILED: ffuf) else (echo   OK: ffuf)

:: gau
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing gau...
go install github.com/lc/gau/v2/cmd/gau@latest
if errorlevel 1 (echo   FAILED: gau) else (echo   OK: gau)

:: gospider
set /a DONE+=1
set /a PCT=DONE*100/TOTAL
echo [%PCT%%%] (%DONE%/%TOTAL%) Installing gospider...
go install github.com/jaeles-project/gospider@latest
if errorlevel 1 (echo   FAILED: gospider) else (echo   OK: gospider)

echo.
echo =====================================================
echo   Verifying installations...
echo =====================================================
for %%T in (subfinder nuclei katana naabu httpx dnsx ffuf gau gospider) do (
    where %%T >nul 2>&1
    if errorlevel 1 (echo   MISSING : %%T) else (echo   FOUND   : %%T)
)

echo.
echo Done. All tools install to %%GOPATH%%\bin (usually C:\Users\%USERNAME%\go\bin)
echo Make sure that directory is in your PATH.
echo.
pause
