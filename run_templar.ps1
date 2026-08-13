# PowerShell script to run Templar with environment variables loaded from .env
# Usage: .\run_templar.ps1 crusade start --config configs\gruyere_test.yaml

# Load environment variables from .env file
if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $parts = $line.Split("=", 2)
            if ($parts.Length -eq 2) {
                $key = $parts[0].Trim()
                $value = $parts[1].Trim()
                # Set environment variable for current process
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
                Write-Host "Set $key"
            }
        }
    }
} else {
    Write-Host "Warning: .env file not found" -ForegroundColor Yellow
}

# Build Templar if needed
if (-not (Test-Path ".\templar.exe")) {
    Write-Host "Building Templar..." -ForegroundColor Cyan
    go build ./cmd/templar
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed" -ForegroundColor Red
        exit 1
    }
}

# Pass all arguments to templar
.\templar $args