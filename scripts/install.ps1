# Hercules-Hunt Installer for Windows
param(
    [switch]$DryRun,
    [switch]$Uninstall,
    [string]$InstallDir = "$env:USERPROFILE\.jiggy"
)

$JiggyRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Definition)

function Write-Banner {
    Write-Host ""
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|     Hercules-Hunt Bug Bounty System           |" -ForegroundColor Cyan
    Write-Host "|     Version 1.0.0                            |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Requirement {
    param($Name, $Command)
    $found = Get-Command $Command -ErrorAction SilentlyContinue
    if ($found) { Write-Host "  [PASS] $Name" -ForegroundColor Green; return $true }
    else { Write-Host "  [WARN] $Name not found (optional)" -ForegroundColor Yellow; return $false }
}

function Get-FileCount {
    param($Path, [string[]]$Patterns = @("*.*"))
    $fullPath = Join-Path $JiggyRoot $Path
    if (-not (Test-Path $fullPath)) { return 0 }
    $count = 0
    if ($Path -like "mcp*") {
        $count = (Get-ChildItem -LiteralPath $fullPath -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch '__pycache__' } | Measure-Object).Count
    } else {
        foreach ($pat in $Patterns) {
            $count += (Get-ChildItem -LiteralPath $fullPath -Filter $pat -File -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -notmatch '__pycache__' } | Measure-Object).Count
        }
    }
    return $count
}

function Get-ModuleInventory {
    $inventory = @()
    $inventory += [PSCustomObject]@{Name="Agents"; Path="agents"; Count=(Get-FileCount "agents" @("*.md"))}
    $inventory += [PSCustomObject]@{Name="Rules"; Path="rules"; Count=(Get-FileCount "rules" @("*.md"))}
    $inventory += [PSCustomObject]@{Name="Bug Bounty"; Path="bug-bounty"; Count=(Get-FileCount "bug-bounty" @("*.py","*.md","*.json"))}
    $inventory += [PSCustomObject]@{Name="Recon"; Path="recon"; Count=(Get-FileCount "recon" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Security Arsenal"; Path="security-arsenal"; Count=(Get-FileCount "security-arsenal" @("*.md","*.txt","*.json"))}
    $inventory += [PSCustomObject]@{Name="Report Writing"; Path="report-writing"; Count=(Get-FileCount "report-writing" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Triage Validation"; Path="triage-validation"; Count=(Get-FileCount "triage-validation" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Context"; Path="context"; Count=(Get-FileCount "context" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Memory"; Path="memory"; Count=(Get-FileCount "memory" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Storage"; Path="storage"; Count=(Get-FileCount "storage" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Tasks"; Path="tasks"; Count=(Get-FileCount "tasks" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Task Persistence"; Path="task-presistence"; Count=(Get-FileCount "task-presistence" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Utils"; Path="utils"; Count=(Get-FileCount "utils" @("*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Adapters"; Path="adapters"; Count=(Get-FileCount "adapters" @("*.py","*.md","*.json"))}
    $inventory += [PSCustomObject]@{Name="Config"; Path="config"; Count=(Get-FileCount "config" @("*.json","*.py","*.md"))}
    $inventory += [PSCustomObject]@{Name="Hooks"; Path="hooks"; Count=(Get-FileCount "hooks" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="MCP Servers"; Path="mcp"; Count=(Get-FileCount "mcp" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="Tools (Bash)"; Path="tools/bash"; Count=(Get-FileCount "tools/bash" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="Tools (Python)"; Path="tools/python"; Count=(Get-FileCount "tools/python" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="Tools (PowerShell)"; Path="tools/powershell"; Count=(Get-FileCount "tools/powershell" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="Tools (JavaScript)"; Path="tools/javascript"; Count=(Get-FileCount "tools/javascript" @("*.*"))}
    $inventory += [PSCustomObject]@{Name="Doc"; Path="doc"; Count=(Get-FileCount "doc" @("*.md"))}
    $inventory += [PSCustomObject]@{Name="Scripts"; Path="scripts"; Count=(Get-FileCount "scripts" @("*.*"))}
    return $inventory
}

function Show-Inventory {
    param($Inventory)
    $total = ($Inventory | Measure-Object Count -Sum).Sum
    Write-Host "`nHercules-Hunt Module Inventory:" -ForegroundColor Cyan
    Write-Host "  Total modules: $($Inventory.Count)" -ForegroundColor Green
    Write-Host "  Total files:   $total" -ForegroundColor Green
    Write-Host ""
    Write-Host ($("  {0,-25} {1,6}" -f "Module", "Files")) -ForegroundColor Yellow
    Write-Host ($("  " + ("-" * 33))) -ForegroundColor DarkGray
    foreach ($m in ($Inventory | Sort-Object Name)) {
        $color = if ($m.Count -gt 0) { "White" } else { "DarkGray" }
        Write-Host ($("  {0,-25} {1,6}" -f $m.Name, $m.Count)) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host ($("  {0,-25} {1,6}" -f "TOTAL", $total)) -ForegroundColor Cyan
    return $total
}

function Copy-Modules {
    param($InstallDir)
    Write-Host "`nCopying modules to $InstallDir..." -ForegroundColor Cyan
    $copyDirs = @(
        "agents", "rules", "bug-bounty", "recon", "security-arsenal",
        "report-writing", "triage-validation", "context", "memory",
        "storage", "tasks", "task-presistence", "utils", "adapters",
        "config", "hooks", "mcp", "doc", "scripts",
        "tools/bash", "tools/python", "tools/powershell",
        "tools/javascript", "tools/markdown"
    )
    foreach ($dir in $copyDirs) {
        $src = Join-Path $JiggyRoot $dir
        if (Test-Path $src) {
            $dst = Join-Path $InstallDir $dir
            Copy-Item -LiteralPath $src -Destination $dst -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    # Copy root configs
    $configs = @("Hercules.md", "opencode.json", "plugin.json", "AGENTS.md", "opencode.jsonc", "requirements.txt")
    foreach ($cfg in $configs) {
        $src = Join-Path $JiggyRoot $cfg
        if (Test-Path $src) {
            Copy-Item -LiteralPath $src (Join-Path $InstallDir $cfg) -Force
        }
    }
    # Copy .claude settings
    if (-not (Test-Path "$InstallDir\.claude")) {
        New-Item -ItemType Directory -Path "$InstallDir\.claude" -Force | Out-Null
    }
    $claudeSettings = Join-Path $JiggyRoot ".claude\settings.json"
    if (Test-Path $claudeSettings) {
        Copy-Item -LiteralPath $claudeSettings "$InstallDir\.claude\settings.json" -Force
    }
    Write-Host "  [OK] All modules installed to $InstallDir" -ForegroundColor Green
}

function Install-Adapter {
    Write-Host "`nDeploying to 18 agentic CLI targets..." -ForegroundColor Cyan
    $adapterPy = Join-Path $JiggyRoot "scripts\jiggy-adapter.py"
    if (Test-Path $adapterPy) {
        if ($DryRun) {
            & python $adapterPy --target all --dry-run
        } else {
            & python $adapterPy --target all --apply
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Deployed to all 18 CLI targets" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] Adapter install had errors (check output above)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [WARN] jiggy-adapter.py not found at $adapterPy" -ForegroundColor Yellow
    }
}

function Install-Dependencies {
    Write-Host "`nInstalling dependencies..." -ForegroundColor Cyan

    # Python deps
    $reqFile = Join-Path $JiggyRoot "requirements.txt"
    if (Test-Path $reqFile) {
        if (-not $DryRun) {
            & python -m pip install -r $reqFile --quiet 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Python dependencies installed" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] pip install had issues" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [DRY-RUN] pip install -r requirements.txt" -ForegroundColor Yellow
        }
    }

    # Node deps
    $pkgFile = Join-Path $JiggyRoot "tools\javascript\package.json"
    if (Test-Path $pkgFile) {
        $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
        if ($npmCmd) {
            if (-not $DryRun) {
                Push-Location (Join-Path $JiggyRoot "tools\javascript")
                & npm install --silent 2>$null
                Pop-Location
                Write-Host "  [OK] Node.js dependencies installed" -ForegroundColor Green
            } else {
                Write-Host "  [DRY-RUN] npm install" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [WARN] npm not found, skipping Node deps" -ForegroundColor Yellow
        }
    }

    # MCP Python deps
    $mcpServers = Get-ChildItem (Join-Path $JiggyRoot "mcp") -Directory -ErrorAction SilentlyContinue
    foreach ($srv in $mcpServers) {
        $req = Join-Path $srv.FullName "requirements.txt"
        if (Test-Path $req) {
            if (-not $DryRun) {
                & python -m pip install -r $req --quiet 2>$null
            } else {
                Write-Host "  [DRY-RUN] pip install -r mcp\$($srv.Name)\requirements.txt" -ForegroundColor Yellow
            }
        }
    }
}

function Install-Profile {
    Write-Host "`nConfiguring PowerShell profile..." -ForegroundColor Cyan
    $jiggyEntry = Join-Path $InstallDir "tools\powershell\jiggy.ps1"
    $profileLine = "`n# Hercules-Hunt Bug Bounty Toolkit`n. `"$jiggyEntry`""
    $alreadyAdded = $false
    if (Test-Path $PROFILE) {
        $alreadyAdded = Select-String -Path $PROFILE -Pattern "Hercules-Hunt Bug Bounty Toolkit" -SimpleMatch -Quiet -ErrorAction SilentlyContinue
    }
    if (-not $alreadyAdded) {
        if (-not $DryRun) {
            Add-Content -Path $PROFILE -Value $profileLine
            Write-Host "  [OK] Added jiggy.ps1 to PowerShell profile ($PROFILE)" -ForegroundColor Green
        } else {
            Write-Host "  [DRY-RUN] Add jiggy.ps1 to $PROFILE" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [OK] PowerShell profile already configured" -ForegroundColor Green
    }
}

function Install-Main {
    Write-Banner
    Write-Host "Checking requirements..." -ForegroundColor Cyan
    Test-Requirement "PowerShell 5.1+" "powershell"
    Test-Requirement "curl.exe" "curl"
    Test-Requirement "Python 3+" "python"
    Test-Requirement "Select-String" "Select-String"

    # Show inventory
    $inventory = Get-ModuleInventory
    $total = Show-Inventory $inventory

    if ($DryRun) {
        Write-Host "`nDry run only. Use without -DryRun to install." -ForegroundColor Yellow
    }

    # Step 1: Copy modules
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Copy-Modules $InstallDir

    # Step 2: Profile setup
    Install-Profile

    # Step 3: Dependencies
    Install-Dependencies

    # Step 4: Deploy to all 18 agentic CLIs via adapter
    Install-Adapter

    Write-Host "`nInstallation complete!" -ForegroundColor Cyan
    Write-Host "  Modules:   $($inventory.Count) modules, $total files" -ForegroundColor Green
    Write-Host "  Location:  $InstallDir" -ForegroundColor White
    Write-Host "  CLI tools: 18 agentic CLI targets configured" -ForegroundColor Green
    Write-Host ""
    Write-Host "Start a new PowerShell session or run:" -ForegroundColor Yellow
    Write-Host "  . `"$InstallDir\tools\powershell\jiggy.ps1`"" -ForegroundColor White
    Write-Host "  Invoke-ReconPipeline -Domain target.com" -ForegroundColor White
}

function Uninstall-Main {
    Write-Banner
    Write-Host "Removing profile entries..." -ForegroundColor Yellow
    $newContent = Get-Content $PROFILE | Where-Object { $_ -notmatch "Hercules-Hunt" }
    $newContent | Set-Content $PROFILE
    Write-Host "[OK] Removed from profile" -ForegroundColor Green
    Write-Host "To remove all files, delete: $InstallDir" -ForegroundColor Yellow
}

if ($Uninstall) { Uninstall-Main }
else { Install-Main }
