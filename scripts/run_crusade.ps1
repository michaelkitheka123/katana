# run_crusade.ps1 - Launch a Templar campaign and stream output to a markdown log.
# Usage: .\scripts\run_crusade.ps1 [-Config configs/example_crusade.yaml] [-AllowDestructive]
param(
    [string]$Config = "configs/example_crusade.yaml",
    [switch]$AllowDestructive
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$null = chcp 65001

Set-Location (Split-Path $PSScriptRoot)

# Load .env file
$envFile = ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $parts = $line.Split("=", 2)
            if ($parts.Count -eq 2) {
                $k = $parts[0].Trim()
                $v = $parts[1].Trim()
                [System.Environment]::SetEnvironmentVariable($k, $v, "Process")
                Write-Host "  [.env] Loaded: $k"
            }
        }
    }
} else {
    Write-Warning ".env file not found"
}

# Prepare log file
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logDir    = "logs"
$logFile   = "$logDir\crusade_$timestamp.md"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Log($text) {
    Write-Host $text
    Add-Content -Path $logFile -Encoding UTF8 -Value $text
}

Add-Content -Path $logFile -Encoding UTF8 -Value "# Templar Crusade Log"
Add-Content -Path $logFile -Encoding UTF8 -Value ("**Started:** " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Add-Content -Path $logFile -Encoding UTF8 -Value ("**Config:** $Config")
Add-Content -Path $logFile -Encoding UTF8 -Value ""
Add-Content -Path $logFile -Encoding UTF8 -Value '```text'

Write-Host "  Log : $logFile"
Write-Host "  Cfg : $Config"
Write-Host ""

# Build args
$extraArgs = if ($AllowDestructive) { " --allow-destructive" } else { "" }

# Write a wrapper batch file that auto-answers yes and runs templar
$wrapperBat = "$logDir\run_$timestamp.bat"
@"
@echo off
echo yes | .\templar.exe crusade start --config "$Config"$extraArgs
"@ | Out-File -FilePath $wrapperBat -Encoding ASCII

# Start process with stdout redirected, reading line by line
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName               = "cmd.exe"
$psi.Arguments              = "/c `"$wrapperBat`""
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $false

$proc = [System.Diagnostics.Process]::Start($psi)

# Stream stdout in real time, handling \r for in-place updates
$outStream = $proc.StandardOutput
$errStream = $proc.StandardError

# We use [Console]::Write to print characters directly without automatic newlines.
# To avoid file I/O bottlenecks, we buffer characters for the log file and flush on \n.
$logBuffer = [System.Text.StringBuilder]::new()

$buffer = New-Object char[] 1024

# Read all of stdout first (matching original script behavior)
while (-not $outStream.EndOfStream) {
    $readCount = $outStream.Read($buffer, 0, $buffer.Length)
    if ($readCount -gt 0) {
        $text = [string]::new($buffer, 0, $readCount)
        
        # Print to console exactly as-is (preserves \r)
        [Console]::Write($text)
        
        # Append to file
        foreach ($c in $text.ToCharArray()) {
            if ($c -eq [char]13) {
                # Skip writing carriage returns to the log file to avoid messing up the markdown formatting
            } elseif ($c -eq [char]10) {
                $logBuffer.Append($c) | Out-Null
                Add-Content -Path $logFile -Encoding UTF8 -NoNewline -Value $logBuffer.ToString()
                $logBuffer.Clear() | Out-Null
            } else {
                $logBuffer.Append($c) | Out-Null
            }
        }
    }
}

# Then capture any stderr
$errBuffer = [System.Collections.Generic.List[string]]::new()
while (-not $errStream.EndOfStream) {
    $errLine = $errStream.ReadLine()
    if ($errLine) {
        [Console]::WriteLine("[ERR] $errLine")
        $errBuffer.Add("[ERR] $errLine")
    }
}
if ($errBuffer.Count -gt 0) {
    # Write all errors at once to avoid locking issues with rapid Add-Content calls
    $errBuffer | Out-File -FilePath $logFile -Encoding UTF8 -Append
}

# Flush remaining log buffer
if ($logBuffer.Length -gt 0) {
    Add-Content -Path $logFile -Encoding UTF8 -NoNewline -Value $logBuffer.ToString()
    $logBuffer.Clear() | Out-Null
}

$proc.WaitForExit()
$exitCode = $proc.ExitCode

# Clean up wrapper (immediate best-effort)
Remove-Item $wrapperBat -ErrorAction SilentlyContinue

# Also schedule a background job to ensure the wrapper is deleted after 10 minutes (600 seconds)
# This acts as a failsafe in case the script is forcibly terminated before immediate cleanup occurs
Start-Job -ScriptBlock {
    param($batPath)
    Start-Sleep -Seconds 600
    Remove-Item $batPath -ErrorAction SilentlyContinue
} -ArgumentList $wrapperBat | Out-Null

# Close log
Add-Content -Path $logFile -Encoding UTF8 -Value '```'
Add-Content -Path $logFile -Encoding UTF8 -Value ""
Add-Content -Path $logFile -Encoding UTF8 -Value "---"
Add-Content -Path $logFile -Encoding UTF8 -Value "## Summary"
Add-Content -Path $logFile -Encoding UTF8 -Value ("- **Finished:** " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Add-Content -Path $logFile -Encoding UTF8 -Value ("- **Exit Code:** $exitCode")
Add-Content -Path $logFile -Encoding UTF8 -Value ("- **Log:** $logFile")

Write-Host ""
Write-Host "======================================================"
Write-Host "  Crusade finished. Exit code: $exitCode"
Write-Host "  Log: $logFile"
Write-Host "======================================================"
