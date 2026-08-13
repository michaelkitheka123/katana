param (
    [string]$LogDir = "logs",
    [int]$Minutes = 10,
    [switch]$Continuous
)

# Resolve the absolute path to the logs directory relative to this script
$targetPath = Resolve-Path (Join-Path $PSScriptRoot "..\$LogDir") -ErrorAction SilentlyContinue

if (-not $targetPath) {
    Write-Error "Could not find directory: $LogDir"
    exit 1
}

Write-Host "Starting log cleanup in $targetPath (Older than $Minutes minutes)" -ForegroundColor Cyan

do {
    $cutoffTime = (Get-Date).AddMinutes(-$Minutes)
    
    # Find all .md files not modified in the last 10 minutes
    $oldFiles = Get-ChildItem -Path $targetPath -Filter "*.md" -File | Where-Object { $_.LastWriteTime -lt $cutoffTime }
    
    if ($oldFiles.Count -gt 0) {
        foreach ($file in $oldFiles) {
            Write-Host "[-] Deleting: $($file.Name) (Last Touched: $($file.LastWriteTime))" -ForegroundColor Yellow
            Remove-Item -Path $file.FullName -Force
        }
    } else {
        if (-not $Continuous) {
            Write-Host "No files older than $Minutes minutes found." -ForegroundColor DarkGray
        }
    }

    if ($Continuous) {
        Start-Sleep -Seconds 60
    }
} while ($Continuous)

if (-not $Continuous) {
    Write-Host "Cleanup complete." -ForegroundColor Green
}
