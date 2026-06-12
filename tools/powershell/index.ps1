<#
.SYNOPSIS
    Hercules-Hunt PowerShell Tool Index Loader

.DESCRIPTION
    Centralized module loader for all 17 PowerShell hunting tools.
    Dot-source this file to import one, several, or all tool scripts.

    Version: 3.0.0

.EXAMPLE
    . .\index.ps1
    Get-ToolList

.EXAMPLE
    . .\index.ps1
    Import-HerculesTool -Name "extract-apis"

.EXAMPLE
    . .\index.ps1
    Import-HerculesAll

.NOTES
    File Name  : index.ps1
    Author     : Hercules-Hunt Team
    Version    : 3.0.0
#>

#Requires -Version 5.1

$script:HerculesVersion = "3.0.0"
$script:HerculesDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$script:HerculesToolIndex = @{
    "extract-apis"          = @{File="extract-apis.ps1";          Description="API endpoint discovery - extracts REST/GraphQL endpoints from responses and JS"}
    "extract-js"            = @{File="extract-js.ps1";            Description="JS extraction and secret scanning - finds hardcoded keys, tokens, internal paths"}
    "deep-hunt"             = @{File="deep-hunt.ps1";             Description="Multi-pass systematic hunting - runs layered probes for deep coverage"}
    "fast-hunt"             = @{File="fast-hunt.ps1";             Description="Quick surface-level probes - rapid checks for low-hanging vulnerabilities"}
    "https-probing"         = @{File="https-probing.ps1";         Description="TLS/certificate/header analysis - inspects security headers, cert chains, ciphers"}
    "extract-parameters"    = @{File="extract-parameters.ps1";    Description="Parameter extraction - collects query, body, and header parameters"}
    "extract-functionalities" = @{File="extract-functionalities.ps1"; Description="User function extraction - maps application features and workflows"}
    "endpoint-fuzzer"       = @{File="endpoint-fuzzer.ps1";       Description="Path/method/extension fuzzing - discovers hidden endpoints and verbs"}
    "auth-tester"           = @{File="auth-tester.ps1";           Description="Auth bypass testing - probes auth flows, JWT, session, role enforcement"}
    "report-builder"        = @{File="report-builder.ps1";        Description="CVSS 3.1 report generation - builds structured findings with severity scoring"}
    "curl-hunter"           = @{File="curl-hunter.ps1";           Description="Curl-based hunting - raw HTTP probe toolkit for lightweight testing"}
    "evidence-toolkit"      = @{File="evidence-toolkit.ps1";      Description="Evidence collection - captures PoC screenshots, HAR files, request logs"}
    "fuzzer-toolkit"        = @{File="fuzzer-toolkit.ps1";        Description="Advanced fuzzing engine - wordlist-based fuzzing with custom payloads"}
    "js-analyzer"           = @{File="js-analyzer.ps1";           Description="JavaScript analysis - extracts endpoints, secrets, and logic from JS bundles"}
    "recon-toolkit"         = @{File="recon-toolkit.ps1";         Description="Reconnaissance - subdomain enum, DNS resolution, port scanning"}
    "jiggy"                 = @{File="jiggy.ps1";                 Description="Main dispatcher - orchestrates multi-tool hunting workflows"}
    "powershell-lib"        = @{File="powershell-lib.ps1";        Description="Shared library - utility functions, logging, colors, helpers"}
}

<#
.SYNOPSIS
    Lists all available Hercules-Hunt PowerShell tools with descriptions.

.DESCRIPTION
    Displays a formatted table of all registered tool names, their filenames,
    and descriptions.

.EXAMPLE
    Get-ToolList

.OUTPUTS
    [PSCustomObject[]] Array of tool info objects if assigned, or formatted table to console.
#>
function Get-ToolList {
    [CmdletBinding()]
    param()

    $maxNameLen = ($script:HerculesToolIndex.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    if ($maxNameLen -lt 4) { $maxNameLen = 4 }

    $header = "  $("Name".PadRight($maxNameLen))  File                          Description"
    $sep    = "  $("-" * $maxNameLen)  ----                          -----------"

    Write-Output ""
    Write-Output "Hercules-Hunt PowerShell Tools v$script:HerculesVersion"
    Write-Output ""
    Write-Output $header
    Write-Output $sep

    $results = foreach ($name in ($script:HerculesToolIndex.Keys | Sort-Object)) {
        $info = $script:HerculesToolIndex[$name]
        [PSCustomObject]@{
            Name        = $name
            File        = $info.File
            Description = $info.Description
        }
    }

    $results | Format-Table -Property Name, File, Description -AutoSize -Wrap
    Write-Output ""

    return $results
}

<#
.SYNOPSIS
    Imports a specific Hercules-Hunt tool by name.

.DESCRIPTION
    Dot-sources the specified tool script file. Validates that the tool name
    exists in the registry and that the corresponding file is present on disk.

.PARAMETER Name
    The short name of the tool to import (e.g. "extract-apis", "deep-hunt").

.PARAMETER PassThru
    If specified, returns the tool metadata hashtable after a successful import.

.EXAMPLE
    Import-HerculesTool -Name "extract-apis"

.EXAMPLE
    Import-HerculesTool -Name "recon-toolkit" -PassThru

.OUTPUTS
    [Hashtable] Tool metadata when -PassThru is specified.
#>
function Import-HerculesTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [switch]$PassThru
    )

    if (-not $script:HerculesToolIndex.ContainsKey($Name)) {
        Write-Error "[!] Unknown tool: '$Name'. Use Get-ToolList to see available tools." -ErrorAction Stop
        return
    }

    $info = $script:HerculesToolIndex[$Name]
    $toolPath = Join-Path -Path $script:HerculesDir -ChildPath $info.File

    if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
        $msg = "[!] Tool file not found: $toolPath"
        Write-Error $msg -ErrorAction Stop
        return
    }

    try {
        . $toolPath
        Write-Host "[+] Loaded: $Name ($($info.File))" -ForegroundColor Green
        if ($PassThru) {
            return $info
        }
    }
    catch {
        Write-Error "[!] Failed to load '$Name': $_" -ErrorAction Stop
    }
}

<#
.SYNOPSIS
    Imports all Hercules-Hunt PowerShell tools.

.DESCRIPTION
    Iterates through the full tool index and dot-sources every registered
    script. Reports success and failure counts on completion.

.PARAMETER PassThru
    If specified, returns a hashtable of results with per-tool status.

.EXAMPLE
    Import-HerculesAll

.EXAMPLE
    Import-HerculesAll -PassThru

.OUTPUTS
    [Hashtable] Results summary when -PassThru is specified.
#>
function Import-HerculesAll {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$PassThru
    )

    $results = @{}
    $loaded  = 0
    $failed  = 0

    foreach ($name in ($script:HerculesToolIndex.Keys | Sort-Object)) {
        $info = $script:HerculesToolIndex[$name]
        $toolPath = Join-Path -Path $script:HerculesDir -ChildPath $info.File

        if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
            Write-Warning "[!] Missing: $toolPath"
            $results[$name] = @{Status="FAILED"; Reason="File not found"}
            $failed++
            continue
        }

        try {
            . $toolPath
            $results[$name] = @{Status="LOADED"; File=$info.File}
            $loaded++
        }
        catch {
            Write-Warning "[!] Failed to load '$name': $_"
            $results[$name] = @{Status="FAILED"; Reason=$_.Exception.Message}
            $failed++
        }
    }

    Write-Host "[+] Loaded $loaded tools successfully." -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Warning "[!] $failed tools failed to load."
    }

    if ($PassThru) {
        return @{
            Version = $script:HerculesVersion
            Total   = $script:HerculesToolIndex.Count
            Loaded  = $loaded
            Failed  = $failed
            Results = $results
        }
    }
}

Write-Host "[+] Hercules-Hunt PowerShell Tool Index v$script:HerculesVersion loaded." -ForegroundColor Cyan
Write-Host "[+] Use Get-ToolList to list tools, Import-HerculesTool to load a specific tool, or Import-HerculesAll to load all." -ForegroundColor Cyan
