@echo off
REM Batch file to run Templar with environment variables loaded from .env
REM Usage: run_templar.bat crusade start --config configs\gruyere_test.yaml

REM Load environment variables from .env file
if exist .env (
    for /f "tokens=1,2 delims==" %%a in (.env) do (
        if not "%%a"=="" if not "%%a:~0,1%"=="#" (
            set "%%a=%%b"
        )
    )
) else (
    echo Warning: .env file not found
)

REM Build Templar if needed
if not exist templar.exe (
    echo Building Templar...
    go build ./cmd/templar
    if errorlevel 1 (
        echo Build failed
        exit /b 1
    )
)

REM Pass all arguments to templar
templar %*