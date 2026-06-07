#!/usr/bin/env pwsh
# Jiggy-2026 CLI — Bug Bounty Tool Launcher
# Usage: .\jiggy.ps1 <command> [options]

param(
    [string]$Command = "",
    [string]$Target = "",
    [string]$Url = "",
    [string]$File = "",
    [string]$Method = "GET",
    [string]$Wordlist = "",
    [int]$Start = 1,
    [int]$End = 100,
    [switch]$List,
    [switch]$Help
)

$JiggyRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition | Split-Path -Parent

function Show-Help {
    Write-Host @"
Jiggy-2026 Bug Bounty CLI
Usage: .\jiggy.ps1 <command> [options]

Commands:
  recon    <domain>     Run full recon pipeline
  curl     <url>        Test endpoint with curl toolkit
  fuzz     <url>        Run full fuzzing pipeline
  idor     <url> -s N -e N  Enumerate IDOR range
  cors     <url>        Test CORS misconfiguration
  ssrf     <url>        Test SSRF-prone parameters
  method   <url>        Test HTTP method bypass
  js       <file>       Analyze downloaded JS bundle
  scan     <file>       Scan file for secrets/endpoints
  tools                  List available tools
  list                   List all available commands and agents
  help                   Show this help

Examples:
  .\jiggy.ps1 recon target.com
  .\jiggy.ps1 curl https://api.target.com/endpoint
  .\jiggy.ps1 idor https://api.target.com/users/{id} -s 1 -e 100
"@
}

function Invoke-Recon {
    param($Domain)
    . "$JiggyRoot\tools\powershell\recon-toolkit.ps1"
    Invoke-ReconPipeline -Domain $Domain -Verbose
}

function Invoke-Curl {
    param($Url)
    . "$JiggyRoot\tools\powershell\curl-hunter.ps1"
    Test-Endpoint -Url $Url -Method $Method
}

function Invoke-Fuzz {
    param($Url)
    . "$JiggyRoot\tools\powershell\fuzzer-toolkit.ps1"
    Invoke-FullFuzzPipeline -Url $Url
}

function Invoke-Idor {
    param($Url, $Start, $End)
    . "$JiggyRoot\tools\powershell\curl-hunter.ps1"
    Test-IdorRange -BaseUrl $Url -Start $Start -End $End
}

function Invoke-CorsTest {
    param($Url)
    . "$JiggyRoot\tools\powershell\curl-hunter.ps1"
    Test-Cors -Url $Url
}

function Invoke-SsrfTest {
    param($Url)
    . "$JiggyRoot\tools\powershell\fuzzer-toolkit.ps1"
    Invoke-SsrfProbe -Url $Url
}

function Invoke-MethodTest {
    param($Url)
    . "$JiggyRoot\tools\powershell\curl-hunter.ps1"
    Test-MethodBypass -Url $Url
}

function Invoke-JsAnalyze {
    param($File)
    . "$JiggyRoot\tools\powershell\js-analyzer.ps1"
    Invoke-FullJsScan -BundlePath $File
}

function Invoke-SecretScan {
    param($File)
    python "$JiggyRoot\tools\python\python-hunter.py" scan --file "$File"
}

function Show-Tools {
    Write-Host "`nJiggy-2026 Tools:" -ForegroundColor Cyan
    Get-ChildItem "$JiggyRoot\tools\*.ps1", "$JiggyRoot\tools\*.py" | ForEach-Object {
        $name = $_.BaseName
        $type = if ($_.Extension -eq '.py') { 'Python' } else { 'PowerShell' }
        $lines = (Get-Content $_.FullName | Measure-Object -Line).Lines
        Write-Host "  $name.$($_.Extension)  ($type, $lines lines)" -ForegroundColor Green
    }
    Write-Host ""
}

if ($Help -or ($Command -eq "help")) { Show-Help; exit }
if ($List -or ($Command -eq "list")) { Show-Tools; exit }
if ($Command -eq "tools") { Show-Tools; exit }

switch ($Command.ToLower()) {
    "recon"  { Invoke-Recon  $Target }
    "curl"   { Invoke-Curl   $Url }
    "fuzz"   { Invoke-Fuzz   $Url }
    "idor"   { Invoke-Idor   $Url $Start $End }
    "cors"   { Invoke-CorsTest $Url }
    "ssrf"   { Invoke-SsrfTest $Url }
    "method" { Invoke-MethodTest $Url }
    "js"     { Invoke-JsAnalyze $File }
    "scan"   { Invoke-SecretScan $File }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Show-Help
    }
}
