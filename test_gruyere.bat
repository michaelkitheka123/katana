@echo off
echo ========================================
echo  Templar Google Gruyere Sandbox Test
echo ========================================
echo.

echo Building Templar...
go build ./cmd/templar
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b %errorlevel%
)
echo Build successful!
echo.

echo Testing connectivity to Google Gruyere...
curl -I "https://google-gruyere.appspot.com/587129948244799578676866416043766319720/"
echo.

echo Available test configurations:
echo 1. Simple test (no AI, no CVE sources)
echo 2. Full test (with AI and CVE sources)
echo.

set /p choice="Select test (1 or 2): "

if "%choice%"=="1" (
    echo Running simple test...
    .\templar.exe crusade start --config configs\gruyere_simple.yaml
) else if "%choice%"=="2" (
    echo Running full test...
    .\templar.exe crusade start --config configs\gruyere_test.yaml
) else (
    echo Invalid choice. Please run manually:
    echo   .\templar.exe crusade start --config configs\gruyere_simple.yaml
    echo   OR
    echo   .\templar.exe crusade start --config configs\gruyere_test.yaml
)

echo.
echo Test complete. Check reports in:
echo   .\reports\gruyere_simple\  (for simple test)
echo   .\reports\gruyere_test\     (for full test)
pause