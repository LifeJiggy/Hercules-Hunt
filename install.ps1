# Hercules-Hunt Installer for Windows
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [string]$InstallDir = "$env:USERPROFILE\.jiggy"
)

$JiggyRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Banner {
    Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Hercules-Hunt Bug Bounty System     ║" -ForegroundColor Cyan
    Write-Host "║     Version 1.0.0                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Test-Requirement {
    param($Name, $Command)
    $found = Get-Command $Command -ErrorAction SilentlyContinue
    if ($found) { Write-Host "  [PASS] $Name" -ForegroundColor Green; return $true }
    else { Write-Host "  [WARN] $Name not found (optional)" -ForegroundColor Yellow; return $false }
}

function Install-Main {
    Write-Banner

    # Verify requirements
    Write-Host "Checking requirements..." -ForegroundColor Cyan
    Test-Requirement "PowerShell 5.1+" "powershell"
    Test-Requirement "curl.exe" "curl"
    Test-Requirement "Python 3+" "python"
    Test-Requirement "Select-String" "Select-String"

    # Count resources
    $agentCount = (Get-ChildItem "$JiggyRoot\agents\*.md" | Measure-Object).Count
    $ruleCount = (Get-ChildItem "$JiggyRoot\rules\*.md" | Measure-Object).Count
    $toolCount = (Get-ChildItem "$JiggyRoot\tools\*.ps1", "$JiggyRoot\tools\*.py" | Measure-Object).Count

    Write-Host "`nHercules-Hunt Resources:" -ForegroundColor Cyan
    Write-Host "  Agents: $agentCount" -ForegroundColor Green
    Write-Host "  Rules:  $ruleCount" -ForegroundColor Green
    Write-Host "  Tools:  $toolCount" -ForegroundColor Green

    # Dry run
    if ($DryRun) {
        Write-Host "`nDry run complete. Run without -DryRun to install." -ForegroundColor Yellow
        return
    }

    # Install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Copy config files
    $configs = @("Hercules.md", "opencode.json", "plugin.json", "AGENTS.md")
    foreach ($cfg in $configs) {
        Copy-Item "$JiggyRoot\$cfg" "$InstallDir\$cfg" -Force
    }
    Write-Host "  [OK] Configuration files copied" -ForegroundColor Green

    # Copy hooks
    if (Test-Path "$JiggyRoot\hooks") {
        Copy-Item "$JiggyRoot\hooks\*" "$InstallDir\hooks\" -Force -Recurse
    }

    # Create .claude directory
    if (-not (Test-Path "$InstallDir\.claude")) {
        New-Item -ItemType Directory -Path "$InstallDir\.claude" -Force | Out-Null
    }
    Copy-Item "$JiggyRoot\.claude\settings.json" "$InstallDir\.claude\settings.json" -Force

    # Profile setup
    $profileLine = "`n# Hercules-Hunt`n. `"$JiggyRoot\tools\powershell\powershell-lib.ps1`"`n. `"$JiggyRoot\tools\powershell\curl-hunter.ps1`"`n"
    $alreadyAdded = Select-String -Path $PROFILE -Pattern "Hercules-Hunt" -SimpleMatch -Quiet -ErrorAction SilentlyContinue
    if (-not $alreadyAdded) {
        Add-Content -Path $PROFILE -Value $profileLine
        Write-Host "  [OK] Added to PowerShell profile" -ForegroundColor Green
    } else {
        Write-Host "  [OK] Already in PowerShell profile" -ForegroundColor Green
    }

    Write-Host "`nInstallation complete!" -ForegroundColor Cyan
    Write-Host "Start a new PowerShell session and run:" -ForegroundColor Yellow
    Write-Host "  Invoke-ReconPipeline -Domain target.com" -ForegroundColor White
    Write-Host "  Test-Endpoint -Url https://target.com/api/test" -ForegroundColor White
}

function Uninstall-Main {
    Write-Banner
    Write-Host "Removing profile entries..." -ForegroundColor Yellow
    $newContent = Get-Content $PROFILE | Where-Object { $_ -notmatch "Hercules-Hunt" }
    $newContent | Set-Content $PROFILE
    Write-Host "[OK] Removed from profile" -ForegroundColor Green
}

if ($Uninstall) { Uninstall-Main }
else { Install-Main }
