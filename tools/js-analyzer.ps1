<#
.SYNOPSIS
    JavaScript Bundle Analysis Toolkit for Bug Bounty Hunting on Windows.

.DESCRIPTION
    A comprehensive PowerShell toolkit for analyzing JavaScript bundles during
    bug bounty recon and web application security assessments. Features include
    bundle downloading, beautification, API endpoint extraction, secret scanning,
    configuration leak detection, source map analysis, bundle diffing, and
    structured reporting.

    Designed for Windows environments using native PowerShell and common tools.

.NOTES
    Author  : Bug Bounty Toolkit
    Version : 1.0.0
    Requires: PowerShell 5.1+, curl.exe, node.js (optional for beautify)

.LINK
    https://opencode.ai

.EXAMPLE
    .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.bundle.js"
    Download and scan a bundle with default options.

.EXAMPLE
    .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.bundle.js" -FullScan -ReportPath ".\report.md"
    Full scan with markdown report output.

.EXAMPLE
    .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.bundle.js" -Beautify -CacheDir ".\js_cache"
    Download a bundle, beautify it, and cache locally.

.EXAMPLE
    .\js-analyzer.ps1 -CompareOld "old.js" -CompareNew "new.js"
    Diff two bundle versions to find new endpoints and changed behavior.
#>

param(
    [Parameter(ParameterSetName = 'Scan', Position = 0)]
    [string]$BundleUrl,

    [Parameter(ParameterSetName = 'Scan', Position = 1)]
    [string]$BundlePath,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Beautify,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$ApiEndpoints,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Secrets,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$FeatureFlags,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$InternalRoutes,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$ConfigLeaks,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$HardcodedCreds,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$SourceMap,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$FullScan,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$CacheDir = "$env:USERPROFILE\.js-analyzer-cache",

    [Parameter(ParameterSetName = 'Scan')]
    [string]$ReportPath,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Passthru,

    [Parameter(ParameterSetName = 'Compare')]
    [string]$CompareOld,

    [Parameter(ParameterSetName = 'Compare')]
    [string]$CompareNew,

    [Parameter(ParameterSetName = 'Compare')]
    [string]$CompareName = "bundle",

    [Parameter(ParameterSetName = 'Compare')]
    [switch]$CompareReport,
    
    [Parameter()]
    [switch]$SkipCache
)

#region ScriptInfo
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       JS Bundle Analysis Toolkit v1.0.0              ║" -ForegroundColor Cyan
Write-Host "║       Bug Bounty Reconnaissance Utility              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
#endregion

#region HelperFunctions

function Test-CommandExists {
    param([string]$CommandName)
    $result = Get-Command $CommandName -ErrorAction SilentlyContinue
    return ($null -ne $result)
}

function Get-ContentSafely {
    param(
        [string]$Path,
        [int]$MaxSizeMB = 50
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -gt ($MaxSizeMB * 1MB)) {
        Write-Warning "File exceeds $MaxSizeMB MB ($([math]::Round($item.Length/1MB, 2)) MB). Reading first $MaxSizeMB MB only."
        $stream = [System.IO.StreamReader]::new($Path)
        $buffer = [char[]]::new($MaxSizeMB * 1MB)
        $stream.Read($buffer, 0, $buffer.Length) | Out-Null
        $stream.Close()
        return (-join $buffer)
    }
    try {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        Write-Warning "Could not read file: $_"
        return $null
    }
}

function Out-LineMatches {
    param($Matches, [string]$Label)
    if ($Matches.Count -eq 0) {
        Write-Host "  [-] No $Label found." -ForegroundColor Gray
        return
    }
    Write-Host "  [+] Found $($Matches.Count) $Label:" -ForegroundColor Green
    $Matches | Sort-Object -Unique | ForEach-Object {
        Write-Host "      $_" -ForegroundColor Yellow
    }
}

function New-CacheDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "  [i] Created cache directory: $Path" -ForegroundColor DarkGray
    }
}

function Get-BundleFileName {
    param([string]$Url)
    $uri = [System.Uri]$Url
    $name = [System.IO.Path]::GetFileName($uri.LocalPath)
    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = "bundle-" + ($uri.Host -replace '\.', '-') + ".js"
    }
    if (-not $name.EndsWith('.js')) {
        $name += '.js'
    }
    return $name
}

function Get-CachePath {
    param([string]$Url, [string]$CacheDir)
    $fileName = Get-BundleFileName -Url $Url
    return Join-Path -Path $CacheDir -ChildPath $fileName
}

function Get-HashForFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
        return $hash.Hash
    } catch {
        return $null
    }
}

function Get-HashForString {
    param([string]$String)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($bytes)
    return [System.BitConverter]::ToString($hashBytes) -replace '-', ''
}

function Out-MetadataFile {
    param([string]$Url, [string]$Hash, [string]$CacheDir)
    $fileName = Get-BundleFileName -Url $Url
    $metaFile = Join-Path -Path $CacheDir -ChildPath "$fileName.meta.json"
    $meta = @{
        Url       = $Url
        Hash      = $Hash
        Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        Tool      = 'JS-Analyzer v1.0.0'
    }
    $meta | ConvertTo-Json -Compress | Set-Content -LiteralPath $metaFile -Encoding UTF8
}

#endregion

#region Get-JsBundle

<#
.SYNOPSIS
    Downloads JavaScript bundles from URLs and caches them locally.

.DESCRIPTION
    Fetches JS bundles via curl.exe (Windows native), saves to a local cache
    directory, checks for updates via SHA-256 hash comparison, and returns
    the local file path. Supports custom headers and User-Agent rotation.

.PARAMETER Url
    The full URL to the JavaScript bundle.

.PARAMETER OutFile
    Optional explicit output file path. Defaults to cache directory.

.PARAMETER CacheDir
    Directory for caching bundles. Defaults to ~/.js-analyzer-cache.

.PARAMETER Force
    Force re-download even if cached.

.PARAMETER UserAgent
    Custom User-Agent string for the request.

.EXAMPLE
    Get-JsBundle -Url "https://example.com/assets/app.bundle.js" -Force
    Force re-download a bundle.

.EXAMPLE
    Get-JsBundle -Url "https://example.com/assets/app.bundle.js" -OutFile ".\bundles\app.js"
    Download to a specific file path.
#>
function Get-JsBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url,

        [Parameter(Position = 1)]
        [string]$OutFile,

        [string]$CacheDir = "$env:USERPROFILE\.js-analyzer-cache",

        [switch]$Force,

        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )

    Write-Host "[Get-JsBundle] Processing: $Url" -ForegroundColor Cyan

    if (-not (Test-CommandExists "curl.exe")) {
        Write-Error "curl.exe is required but not found in PATH."
        return $null
    }

    $cachePath = $null
    if (-not $OutFile) {
        New-CacheDirectory -Path $CacheDir
        $cachePath = Get-CachePath -Url $Url -CacheDir $CacheDir
        $OutFile = $cachePath
    }

    $existingHash = Get-HashForFile -Path $OutFile

    if ((-not $Force) -and (Test-Path -LiteralPath $OutFile) -and $existingHash) {
        Write-Host "  [i] Cached bundle exists: $OutFile" -ForegroundColor DarkGray
    } else {
        Write-Host "  [~] Downloading bundle..." -ForegroundColor Yellow
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            $startTime = Get-Date
            $result = & curl.exe -L -s -S -o $tempFile --user-agent "$UserAgent" --connect-timeout 30 --max-time 120 "$Url" 2>&1
            $elapsed = (Get-Date) - $startTime
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Download failed (exit code: $LASTEXITCODE). Curl output: $result"
                if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force }
                return $null
            }
            if (-not (Test-Path -LiteralPath $tempFile)) {
                Write-Error "Download produced no output file."
                return $null
            }
            $fileSize = (Get-Item -LiteralPath $tempFile).Length
            if ($fileSize -eq 0) {
                Write-Error "Downloaded file is empty (0 bytes)."
                Remove-Item -LiteralPath $tempFile -Force
                return $null
            }
            Move-Item -LiteralPath $tempFile -Destination $OutFile -Force
            Write-Host "  [+] Downloaded $($fileSize / 1KB -as [int]) KB in $($elapsed.TotalSeconds -as [int])s -> $OutFile" -ForegroundColor Green
        } catch {
            if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force }
            Write-Error "Download exception: $_"
            return $null
        }
    }

    $newHash = Get-HashForFile -Path $OutFile
    if ($existingHash -and $newHash -and ($existingHash -ne $newHash)) {
        Write-Host "  [!] Bundle has been UPDATED since last download." -ForegroundColor Magenta
    }

    if ($cachePath) {
        Out-MetadataFile -Url $Url -Hash $newHash -CacheDir $CacheDir
    }

    Write-Host "  [i] SHA-256: $newHash" -ForegroundColor DarkGray
    Write-Host "  [i] Path: $OutFile" -ForegroundColor DarkGray
    return [PSCustomObject]@{
        Path     = $OutFile
        Url      = $Url
        Size     = (Get-Item -LiteralPath $OutFile).Length
        Hash     = $newHash
        Cached   = ($existingHash -and ($existingHash -eq $newHash))
    }
}

#endregion

#region Invoke-JsBeautify

<#
.SYNOPSIS
    Beautifies minified JavaScript using node.js (js-beautify) or Python fallback.

.DESCRIPTION
    Attempts to use node.js js-beautify for JS formatting. Falls back to a
    Python-based beautifier if node is unavailable. Saves the beautified output
    and returns the path.

.PARAMETER Path
    Path to the minified JS file.

.PARAMETER OutputPath
    Output path for the beautified file. Defaults to input file with .beautified.js suffix.

.PARAMETER IndentSize
    Number of spaces for indentation (default: 2).

.PARAMETER PreserveNewlines
    Preserve existing newlines during beautification (default: $true).

.EXAMPLE
    Invoke-JsBeautify -Path ".\bundles\app.bundle.js" -OutputPath ".\beautified\app.js"
    Beautify a bundle with custom output path.

.EXAMPLE
    Invoke-JsBeautify -Path ".\bundles\app.bundle.js" -IndentSize 4
    Beautify with 4-space indentation.
#>
function Invoke-JsBeautify {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath,

        [ValidateRange(1, 8)]
        [int]$IndentSize = 2,

        [bool]$PreserveNewlines = $true
    )

    Write-Host "[Invoke-JsBeautify] Beautifying: $Path" -ForegroundColor Cyan

    if (-not $OutputPath) {
        $dir = Split-Path -Parent $Path
        $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $ext = [System.IO.Path]::GetExtension($Path)
        $OutputPath = Join-Path -Path $dir -ChildPath "$name.beautified$ext"
    }

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read source file."
        return $null
    }

    if ($content.Length -eq 0) {
        Write-Error "Source file is empty."
        return $null
    }

    $beautified = $null

    if (Test-CommandExists "node") {
        Write-Host "  [~] Using node.js js-beautify..." -ForegroundColor Yellow
        $jsCode = @"
const beautify = require('js-beautify');
const input = require('fs').readFileSync(0, 'utf-8');
const opts = { indent_size: $IndentSize, preserve_newlines: $PreserveNewlines };
process.stdout.write(beautify.js_beautify(input, opts));
"@
        try {
            $tempInput = [System.IO.Path]::GetTempFileName()
            $content | Set-Content -LiteralPath $tempInput -Encoding UTF8 -NoNewline
            $beautified = & node -e $jsCode -- $tempInput 2>&1
            Remove-Item -LiteralPath $tempInput -Force -ErrorAction SilentlyContinue
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "node.js beautify failed. Falling back to Python."
                $beautified = $null
            }
        } catch {
            Write-Warning "node.js execution error: $_"
            $beautified = $null
        }
    }

    if ($null -eq $beautified) {
        Write-Host "  [~] Using Python fallback beautifier..." -ForegroundColor Yellow
        $pythonScript = @"
import sys
import re

def beautify_js(text, indent_size=2):
    result = []
    indent_level = 0
    in_template = False
    template_depth = 0
    in_regex = False
    lines = text.split('\n')

    if len(lines) == 1 and len(text) > 1000:
        return simple_js_beautify(text, indent_size)

    for line in lines:
        result.append(line)
    return '\n'.join(result)

def simple_js_beautify(text, indent_size=2):
    indent = ' ' * indent_size
    result = []
    current = []
    depth = 0
    in_string = False
    string_char = None
    i = 0

    while i < len(text):
        ch = text[i]

        if in_string:
            current.append(ch)
            if ch == '\\' and i + 1 < len(text):
                i += 1
                if i < len(text):
                    current.append(text[i])
            elif ch == string_char:
                in_string = False
                string_char = None
            i += 1
            continue

        if ch in '"\'':
            in_string = True
            string_char = ch
            current.append(ch)
            i += 1
            continue

        if ch in '{}()[]':
            old_depth = depth
            if ch in '{([':
                depth += 1
            else:
                depth = max(0, depth - 1)

            current.append(ch)
            if ch in '}])':
                result.append(''.join(current))
                current = []
        elif ch == ';':
            current.append(ch)
            result.append(''.join(current))
            current = []
        elif ch == '\n':
            if current:
                result.append(''.join(current))
                current = []
        else:
            current.append(ch)
        i += 1

    if current:
        result.append(''.join(current))

    final = []
    depth = 0
    for line in result:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('}') or stripped.startswith(']') or stripped.startswith(')'):
            depth = max(0, depth - 1)
        final.append(indent * depth + stripped)
        opens = stripped.count('{') + stripped.count('[') + stripped.count('(')
        closes = stripped.count('}') + stripped.count(']') + stripped.count(')')
        depth += opens - closes
        if depth < 0:
            depth = 0

    return '\n'.join(final)

if __name__ == '__main__':
    try:
        data = sys.stdin.buffer.read().decode('utf-8', errors='replace')
        result = beautify_js(data, indent_size=$IndentSize)
        sys.stdout.write(result)
    except Exception as e:
        sys.stderr.write(f'Python beautify error: {e}\n')
        sys.exit(1)
"@
        try {
            $beautified = $content | & python -c $pythonScript 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Python beautify failed. Using original content."
                $beautified = $content
            }
        } catch {
            Write-Warning "Python execution error: $_"
            $beautified = $content
        }
    }

    $beautified | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "  [+] Beautified output: $OutputPath ($((Get-Item -LiteralPath $OutputPath).Length / 1KB -as [int]) KB)" -ForegroundColor Green

    return [PSCustomObject]@{
        Path     = $OutputPath
        Original = (Get-Item -LiteralPath $Path).Length
        Size     = (Get-Item -LiteralPath $OutputPath).Length
    }
}

#endregion

#region Find-ApiEndpoints

<#
.SYNOPSIS
    Extracts API endpoint paths from JavaScript bundles.

.DESCRIPTION
    Uses regex patterns to discover /api/, /v1/, /v2/, /v3/, /graphql,
    /rest, /_api, /_vti_bin, /sdk, and other common API route patterns
    within JavaScript code. Deduplicates and sorts results.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save extracted endpoints as a text file.

.PARAMETER UniqueOnly
    Return only unique endpoint paths (default: $true).

.EXAMPLE
    Find-ApiEndpoints -Path ".\beautified\app.js"
    Extract all API endpoints from a JS file.

.EXAMPLE
    Find-ApiEndpoints -Path ".\beautified\app.js" -OutputPath ".\endpoints.txt"
    Extract and save endpoints to a file.
#>
function Find-ApiEndpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath,

        [bool]$UniqueOnly = $true
    )

    Write-Host "[Find-ApiEndpoints] Scanning for API endpoints..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $patterns = @(
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/api(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/v[12](?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/v3(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/graphql(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/rest(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/_api(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/_vti_bin(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/sdk(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["'']((?:/[a-zA-Z0-9_.-]+)*/ws(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["''](wss?://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["''](https?://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-{}[\]]+)*/api(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["''](https?://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-{}[\]]+)*/graphql(?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']',
        '(?i)["''](https?://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-{}[\]]+)*/v[123](?:/[a-zA-Z0-9_.\-{}[\]]+)*)["'']'
    )

    $endpoints = [System.Collections.Generic.List[string]]::new()

    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($m in $matches) {
            if ($m.Groups[1].Success) {
                $endpoints.Add($m.Groups[1].Value)
            }
        }
    }

    $result = if ($UniqueOnly) {
        $endpoints | Sort-Object -Unique
    } else {
        $endpoints | Sort-Object
    }

    Out-LineMatches -Matches $result -Label "API endpoints"

    if ($OutputPath -and $result.Count -gt 0) {
        $result | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved endpoints to: $OutputPath" -ForegroundColor DarkGray
    }

    return $result
}

#endregion

#region Find-Secrets

<#
.SYNOPSIS
    Scans JavaScript bundles for hardcoded secrets and API keys.

.DESCRIPTION
    Regex-based scanner that detects AWS Access Keys, GCP API keys,
    Stripe keys, GitHub tokens, Slack tokens, JWT tokens, Firebase URLs,
    private keys, and other common secret patterns. Results are deduplicated.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save discovered secrets as a text file.

.PARAMETER MaskSecrets
    Mask the actual secret values in output (default: $true).

.EXAMPLE
    Find-Secrets -Path ".\beautified\app.js"
    Scan a JS file for hardcoded secrets with masked output.

.EXAMPLE
    Find-Secrets -Path ".\beautified\app.js" -MaskSecrets:$false
    Scan with unmasked secret values shown.
#>
function Find-Secrets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath,

        [bool]$MaskSecrets = $true
    )

    Write-Host "[Find-Secrets] Scanning for hardcoded secrets..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $allSecrets = [System.Collections.Generic.List[PSCustomObject]]::new()

    $secretPatterns = @(
        @{
            Name    = "AWS Access Key ID"
            Pattern = '(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
        },
        @{
            Name    = "AWS Secret Access Key"
            Pattern = '(?i)["''](?:aws_secret_access_key|awsSecretKey|AWSSecretKey)["'']\s*[:=]\s*["'']([A-Za-z0-9\/+=]{40})["'']'
        },
        @{
            Name    = "GCP API Key"
            Pattern = 'AIza[0-9A-Za-z\-_]{35}'
        },
        @{
            Name    = "Stripe Live Secret"
            Pattern = '(?i)sk_live_[0-9a-zA-Z]{24,}'
        },
        @{
            Name    = "Stripe Live Publishable"
            Pattern = '(?i)pk_live_[0-9a-zA-Z]{24,}'
        },
        @{
            Name    = "Stripe Test Secret"
            Pattern = '(?i)sk_test_[0-9a-zA-Z]{24,}'
        },
        @{
            Name    = "Stripe Test Publishable"
            Pattern = '(?i)pk_test_[0-9a-zA-Z]{24,}'
        },
        @{
            Name    = "GitHub Personal Access Token"
            Pattern = '(?:ghp_|gho_|ghu_|ghs_|ghr_)[0-9a-zA-Z]{36}'
        },
        @{
            Name    = "GitHub OAuth Access Token"
            Pattern = 'gho_[0-9a-zA-Z]{36}'
        },
        @{
            Name    = "GitHub App Token"
            Pattern = 'ghs_[0-9a-zA-Z]{36}'
        },
        @{
            Name    = "GitHub Refresh Token"
            Pattern = 'ghr_[0-9a-zA-Z]{36}'
        },
        @{
            Name    = "Slack Bot Token"
            Pattern = '(?i)xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'
        },
        @{
            Name    = "Slack App Token"
            Pattern = '(?i)xapp-[0-9]{10,13}-[a-zA-Z0-9]{24}'
        },
        @{
            Name    = "Slack User Token"
            Pattern = '(?i)xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'
        },
        @{
            Name    = "Slack Webhook URL"
            Pattern = 'https?://hooks\.slack\.com/services/[A-Za-z0-9/]{44}'
        },
        @{
            Name    = "JWT Token"
            Pattern = 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
        },
        @{
            Name    = "Firebase URL"
            Pattern = '(?i)https?://[a-zA-Z0-9.-]+\.firebaseio\.com'
        },
        @{
            Name    = "Firebase API Key"
            Pattern = '(?i)["''](?:apiKey|API_KEY|FirebaseApiKey)["'']\s*[:=]\s*["'']([A-Za-z0-9_-]{30,})["'']'
        },
        @{
            Name    = "Private Key (RSA/EC/DSA)"
            Pattern = '-----BEGIN\s?(?:RSA|DSA|EC|OPENSSH|PRIVATE)?\s?PRIVATE KEY-----'
        },
        @{
            Name    = "Heroku API Key"
            Pattern = '(?i)["''](?:heroku|HEROKU)[^"'']{0,20}["'']\s*[:=]\s*["'']([A-Fa-f0-9-]{36})["'']'
        },
        @{
            Name    = "Google OAuth Client ID"
            Pattern = '[0-9]{12,}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'
        },
        @{
            Name    = "Mailgun API Key"
            Pattern = '(?i)key-[0-9a-zA-Z]{32}'
        },
        @{
            Name    = "Twilio API Key"
            Pattern = '(?i)SK[0-9a-fA-F]{32}'
        },
        @{
            Name    = "Twilio Auth Token"
            Pattern = '(?i)(?:AC[a-f0-9]{32}|account_sid|AccountSID)["\'"]?\s*[:=]\s*["\']?[A-Za-z0-9]{32}'
        },
        @{
            Name    = "SendGrid API Key"
            Pattern = '(?i)SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43}'
        },
        @{
            Name    = "Mapbox API Token"
            Pattern = '(?i)pk\.[A-Za-z0-9_-]{60,}\.[A-Za-z0-9_-]{22,}'
        },
        @{
            Name    = "npm Auth Token"
            Pattern = '(?i)//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-]{36}'
        },
        @{
            Name    = "Docker Auth"
            Pattern = '(?i)["\''](?:DOCKER_AUTH|docker_password)["\'']\s*[:=]\s*["\''][A-Za-z0-9_-]{20,}["\''"]'
        },
        @{
            Name    = "SSH Private Key"
            Pattern = '-----BEGIN OPENSSH PRIVATE KEY-----'
        }
    )

    foreach ($entry in $secretPatterns) {
        $matches = [regex]::Matches($content, $entry.Pattern)
        foreach ($m in $matches) {
            $value = $m.Value
            if ($MaskSecrets -and $value.Length -gt 12) {
                $value = $value.Substring(0, [Math]::Min(8, $value.Length)) + '...' + $value.Substring($value.Length - 4)
            }
            $allSecrets.Add([PSCustomObject]@{
                    Type  = $entry.Name
                    Value = $value
                    Raw   = $m.Value
                })
        }
    }

    $unique = $allSecrets | Sort-Object Type, Raw -Unique

    if ($unique.Count -eq 0) {
        Write-Host "  [-] No secrets found." -ForegroundColor Gray
        return @()
    }

    Write-Host "  [+] Found $($unique.Count) potential secrets:" -ForegroundColor Green
    $grouped = $unique | Group-Object Type | Sort-Object Count -Descending
    foreach ($g in $grouped) {
        Write-Host "      [$($g.Count)x] $($g.Name)" -ForegroundColor Yellow
    }
    Write-Host ""

    $unique | Format-Table Type, Value -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

    if ($OutputPath -and $unique.Count -gt 0) {
        $unique | Select-Object Type, Value | Format-Table -AutoSize | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved secrets to: $OutputPath" -ForegroundColor DarkGray
    }

    return $unique
}

#endregion

#region Find-FeatureFlags

<#
.SYNOPSIS
    Extracts feature flags, toggles, and configuration keys from JavaScript bundles.

.DESCRIPTION
    Searches for feature flag patterns including App.Config references,
    activeFeatures, betaFeatures, environment flags, LaunchDarkly keys,
    feature toggles, and A/B testing assignments.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save feature flags as a text file.

.EXAMPLE
    Find-FeatureFlags -Path ".\beautified\app.js"
    Extract all feature flags from a JS bundle.

.EXAMPLE
    Find-FeatureFlags -Path ".\beautified\app.js" -OutputPath ".\flags.txt"
    Extract and save feature flags to a file.
#>
function Find-FeatureFlags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath
    )

    Write-Host "[Find-FeatureFlags] Scanning for feature flags..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $flags = [System.Collections.Generic.List[string]]::new()

    $patterns = @(
        '(?i)App\.Config\.[a-zA-Z0-9_]+',
        '(?i)appConfig\.[a-zA-Z0-9_]+',
        '(?i)featureFlags?\.[a-zA-Z0-9_]+',
        '(?i)featureToggles?\.[a-zA-Z0-9_]+',
        '(?i)activeFeatures\.[a-zA-Z0-9_]+',
        '(?i)betaFeatures?\.[a-zA-Z0-9_]+',
        '(?i)experiments?\.[a-zA-Z0-9_]+',
        '(?i)launchDarkly\.[a-zA-Z0-9_]+',
        '(?i)flags\.[a-zA-Z0-9_]+',
        '(?i)["''](?:FEATURE_|FF_|FLAG_|ENABLE_|DISABLE_|BETA_)[A-Z0-9_]+["'']',
        '(?i)["''](?:feature|flag|toggle|experiment)["'']?\s*[:=]\s*(?:true|false|["\']enabled["\']|["\']disabled["\'])',
        '(?i)AppConfig\s*[\.\[]\s*["\']?([a-zA-Z0-9_]+)["\']?',
        '(?i)(?:isEnabled|isActive|isBeta|isFeature|showFeature|hasFeature|getFlag)\s*[\(\[]\s*["\']([a-zA-Z0-9_]+)["\']',
        '(?i)getFeatureFlag\s*\(\s*["\']([a-zA-Z0-9_]+)["\']',
        '(?i)["\'](?:beta|alpha|preview|early-access|internal|staging)["\']\s*[:=]\s*(?:true|["\']1["\'])'
    )

    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($m in $matches) {
            if ($m.Groups[1].Success) {
                $flags.Add($m.Groups[1].Value.Trim())
            } elseif ($m.Value) {
                $flags.Add($m.Value.Trim())
            }
        }
    }

    $result = $flags | Sort-Object -Unique

    Out-LineMatches -Matches $result -Label "feature flags"

    if ($OutputPath -and $result.Count -gt 0) {
        $result | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved feature flags to: $OutputPath" -ForegroundColor DarkGray
    }

    return $result
}

#endregion

#region Find-InternalRoutes

<#
.SYNOPSIS
    Extracts internal application routes from JavaScript bundles.

.DESCRIPTION
    Discovers React Router, Vue Router, Next.js page paths, and other
    internal route definitions. Identifies path patterns, route components,
    lazy-loaded routes, and navigation structures.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save discovered routes as a text file.

.EXAMPLE
    Find-InternalRoutes -Path ".\beautified\app.js"
    Extract all internal routes from a JS bundle.

.EXAMPLE
    Find-InternalRoutes -Path ".\beautified\app.js" -OutputPath ".\routes.txt"
    Extract and save routes to a file.
#>
function Find-InternalRoutes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath
    )

    Write-Host "[Find-InternalRoutes] Scanning for internal routes..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $routes = [System.Collections.Generic.List[string]]::new()

    $patterns = @(
        # React Router
        '(?i)(?:path|to|href|route)\s*[:=]\s*["\'](/(?:[a-zA-Z0-9_\-./\[\]{}:?*+]+|(?:[a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+)?)["\']',
        # React Router v6 style
        '(?i)(?:path|to)\s*:\s*["\'](/[a-zA-Z0-9_\-./:?*]+)["\']',
        # Vue Router
        '(?i)(?:path|name|component)\s*[:=]\s*["\'](/[a-zA-Z0-9_\-./]+)["\']',
        # Next.js pages
        '(?i)(?:pages|page|view)\s*[:=]\s*["\'](/[a-zA-Z0-9_\-./]+)["\']',
        # Angular routes
        '(?i)(?:path|redirectTo)\s*:\s*["\'](/[a-zA-Z0-9_\-./]+)["\']',
        # React Navigation
        '(?i)(?:routeName|screen|navigate)\s*[:=]\s*["\'](/[a-zA-Z0-9_\-./]+)["\']',
        # Ember routes
        '(?i)this\.route\(["\']([a-zA-Z0-9_\-./]+)["\']',
        # Common route patterns
        '(?i)["\'](/(?:dashboard|admin|settings|profile|account|billing|team|org|project|workspace|config|manage|users|roles|permissions|audit|logs|reports|analytics|search|notifications|messages|inbox|support|help|docs|status|health|metrics)(?:/[a-zA-Z0-9_\-{}[\]]+)*)["\']',
        # Lazy imports
        '(?i)(?:import|require|import\(|\.lazy\()\s*\(?\s*["\'](\.\/[a-zA-Z0-9_\-./]+(?:/page|/index|/route|/view|/component)?)["\']',
        # Route definitions arrays
        '(?i)["\'](/[a-zA-Z0-9_\-./]+)["\']\s*[,:]\s*(?:\{|\[|\{[\s\S]{0,200}component|[\s\S]{0,200}element)'
    )

    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($m in $matches) {
            if ($m.Groups[1].Success) {
                $val = $m.Groups[1].Value.Trim()
                if ($val.Length -gt 1 -and $val -notmatch '^[''"]$' -and $val -notmatch '^http') {
                    $routes.Add($val)
                }
            }
        }
    }

    $result = $routes | Sort-Object -Unique

    Out-LineMatches -Matches $result -Label "internal routes"

    if ($OutputPath -and $result.Count -gt 0) {
        $result | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved routes to: $OutputPath" -ForegroundColor DarkGray
    }

    return $result
}

#endregion

#region Find-ConfigLeaks

<#
.SYNOPSIS
    Detects configuration leaks in JavaScript bundles.

.DESCRIPTION
    Scans for process.env references, API base URLs, OAuth client IDs and secrets,
    Firebase configuration objects, Sentry DSNs, Datadog API keys, and other
    environment configuration leaks.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save config leaks as a text file.

.EXAMPLE
    Find-ConfigLeaks -Path ".\beautified\app.js"
    Scan for configuration leaks in a JS bundle.

.EXAMPLE
    Find-ConfigLeaks -Path ".\beautified\app.js" -OutputPath ".\config-leaks.txt"
    Save configuration leaks to a file.
#>
function Find-ConfigLeaks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath
    )

    Write-Host "[Find-ConfigLeaks] Scanning for configuration leaks..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $leaks = [System.Collections.Generic.List[PSCustomObject]]::new()

    $categories = @(
        @{
            Name = "process.env References"
            Pattern = '(?i)(?:process\.env|import\.meta\.env)(?:\.[a-zA-Z0-9_]+|\[["'']([a-zA-Z0-9_]+)["'']\])'
        },
        @{
            Name = "API Base URLs"
            Pattern = '(?i)(?:baseUrl|baseURL|base_url|apiUrl|apiURL|api_url|apiBase|apiBaseUrl|endpoint)\s*[:=]\s*["''](https?://[^"'']+)["'']'
        },
        @{
            Name = "OAuth Client ID"
            Pattern = '(?i)(?:client_id|clientId|ClientID|oauthClientId|oauth_id)\s*[:=]\s*["'']([a-zA-Z0-9_.-]{10,})["'']'
        },
        @{
            Name = "OAuth Client Secret"
            Pattern = '(?i)(?:client_secret|clientSecret|ClientSecret|oauthSecret)\s*[:=]\s*["'']([a-zA-Z0-9_.-]{10,})["'']'
        },
        @{
            Name = "Firebase Config"
            Pattern = '(?i)firebaseConfig\s*=\s*\{[^}]+apiKey[^}]+authDomain[^}]+}'
        },
        @{
            Name = "Sentry DSN"
            Pattern = 'https?://[a-f0-9]{32}@[a-zA-Z0-9.-]+\.ingest\.sentry\.io/\d+'
        },
        @{
            Name = "Sentry Config"
            Pattern = '(?i)(?:Sentry\.init|sentryConfig|SentryConfig)\s*\(?\s*\{[^}]+dsn[^}]+}'
        },
        @{
            Name = "Datadog API Key"
            Pattern = '(?i)(?:DD_API_KEY|DATADOG_API_KEY|datadogApiKey)\s*[:=]\s*["'']([a-zA-Z0-9]{32})["'']'
        },
        @{
            Name = "Datadog Application Key"
            Pattern = '(?i)(?:DD_APP_KEY|DATADOG_APP_KEY|datadogAppKey)\s*[:=]\s*["'']([a-zA-Z0-9]{40})["'']'
        },
        @{
            Name = "New Relic License Key"
            Pattern = '(?i)(?:NEW_RELIC_LICENSE_KEY|newRelicLicenseKey|newrelic_license_key)\s*[:=]\s*["'']([a-zA-Z0-9]{40})["'']'
        },
        @{
            Name = "Auth0 Config"
            Pattern = '(?i)(?:auth0|Auth0Config|AUTH0_CONFIG)\s*[:=]\s*\{[^}]+domain[^}]+clientID[^}]+}'
        },
        @{
            Name = "Amplitude API Key"
            Pattern = '(?i)(?:AMPLITUDE_API_KEY|amplitudeApiKey|amplitude_key)\s*[:=]\s*["'']([a-zA-Z0-9]{32})["'']'
        },
        @{
            Name = "Segment Write Key"
            Pattern = '(?i)(?:SEGMENT_WRITE_KEY|segmentWriteKey|analytics_key)\s*[:=]\s*["'']([a-zA-Z0-9]{32})["'']'
        },
        @{
            Name = "Mixpanel Token"
            Pattern = '(?i)(?:MIXPANEL_TOKEN|mixpanelToken|mixpanel_token)\s*[:=]\s*["'']([a-zA-Z0-9]{32})["'']'
        },
        @{
            Name = "CORS Origins"
            Pattern = '(?i)(?:allowedOrigins|corsOrigins|CORS_ORIGINS)\s*[:=]\s*\[([^\]]+)\]'
        },
        @{
            Name = "Contentful Space/Space ID"
            Pattern = '(?i)(?:space|spaceId|SPACE_ID|contentful_space)\s*[:=]\s*["'']([a-zA-Z0-9]{12,})["'']'
        },
        @{
            Name = "Contentful Access Token"
            Pattern = '(?i)(?:accessToken|CONTENTFUL_ACCESS_TOKEN|deliveryAccessToken)\s*[:=]\s*["'']([a-zA-Z0-9_-]{43,})["'']'
        },
        @{
            Name = "Web3 / Ethers Provider URL"
            Pattern = '(?i)(?:providerUrl|PROVIDER_URL|WEB3_PROVIDER|ethersProvider|jsonRpc|rpcUrl)\s*[:=]\s*["''](https?://[^"'']+)["'']'
        },
        @{
            Name = "Alchemy API Key"
            Pattern = '(?i)(?:ALCHEMY_API_KEY|alchemyApiKey|alchemy_key)\s*[:=]\s*["'']([a-zA-Z0-9]{32,})["'']'
        },
        @{
            Name = "Infura Project ID"
            Pattern = '(?i)(?:INFURA_PROJECT_ID|infuraProjectId|infura_key)\s*[:=]\s*["'']([a-fA-F0-9]{32})["'']'
        },
        @{
            Name = "OpenAI API Key"
            Pattern = '(?i)(?:OPENAI_API_KEY|openaiApiKey|openai_key)\s*[:=]\s*["''](sk-[a-zA-Z0-9]{20,})["'']'
        },
        @{
            Name = "Anthropic API Key"
            Pattern = '(?i)(?:ANTHROPIC_API_KEY|anthropicApiKey|claude_key)\s*[:=]\s*["''](sk-ant-[a-zA-Z0-9]{20,})["'']'
        },
        @{
            Name = "Environment Mode Flags"
            Pattern = '(?i)(?:NODE_ENV|ENVIRONMENT|APP_ENV|REACT_APP_ENV|NEXT_PUBLIC_ENV)\s*[:=]\s*["''](development|staging|production|test|qa|demo)["'']'
        },
        @{
            Name = "JWT Secret/Signing Key"
            Pattern = '(?i)(?:jwtSecret|JWT_SECRET|jwt_secret|signingKey|SIGNING_KEY|tokenSecret|TOKEN_SECRET)\s*[:=]\s*["'']([^"'']{8,})["'']'
        }
    )

    foreach ($cat in $categories) {
        $matches = [regex]::Matches($content, $cat.Pattern)
        foreach ($m in $matches) {
            $displayVal = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Value }
            if ($displayVal.Length -gt 200) { $displayVal = $displayVal.Substring(0, 200) + '...' }
            $leaks.Add([PSCustomObject]@{
                    Category = $cat.Name
                    Match    = $displayVal
                })
        }
    }

    $unique = $leaks | Sort-Object Category, Match -Unique

    if ($unique.Count -eq 0) {
        Write-Host "  [-] No configuration leaks found." -ForegroundColor Gray
        return @()
    }

    Write-Host "  [+] Found $($unique.Count) configuration leaks:" -ForegroundColor Green
    $grouped = $unique | Group-Object Category | Sort-Object Count -Descending
    foreach ($g in $grouped) {
        Write-Host "      [$($g.Count)x] $($g.Name)" -ForegroundColor Yellow
    }
    Write-Host ""

    $unique | Format-Table Category, Match -AutoSize -Wrap | Out-String | ForEach-Object { Write-Host $_ }

    if ($OutputPath -and $unique.Count -gt 0) {
        $unique | Select-Object Category, Match | Format-Table -AutoSize -Wrap | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved config leaks to: $OutputPath" -ForegroundColor DarkGray
    }

    return $unique
}

#endregion

#region Find-HardcodedCreds

<#
.SYNOPSIS
    Finds hardcoded credentials and test accounts in JavaScript bundles.

.DESCRIPTION
    Locates test accounts, default passwords, database connection strings,
    internal service URLs, test API keys, and other credentials that
    may have been inadvertently included in the bundle.

.PARAMETER Path
    Path to the JavaScript file to scan.

.PARAMETER OutputPath
    Optional path to save discovered credentials as a text file.

.EXAMPLE
    Find-HardcodedCreds -Path ".\beautified\app.js"
    Scan for hardcoded credentials in a JS bundle.

.EXAMPLE
    Find-HardcodedCreds -Path ".\beautified\app.js" -OutputPath ".\creds.txt"
    Save discovered credentials to a file.
#>
function Find-HardcodedCreds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(Position = 1)]
        [string]$OutputPath
    )

    Write-Host "[Find-HardcodedCreds] Scanning for hardcoded credentials..." -ForegroundColor Cyan

    $content = Get-ContentSafely -Path $Path
    if ($null -eq $content) {
        Write-Error "Could not read file: $Path"
        return @()
    }

    $creds = [System.Collections.Generic.List[PSCustomObject]]::new()

    $patterns = @(
        @{
            Name = "Test Account Pattern"
            Pattern = '(?i)(?:test|demo|sample|example|staging|sandbox)\s*[:=_]\s*["''](?:user|account|email|login|password|pass|pwd)["'']'
        },
        @{
            Name = "Test Email"
            Pattern = '(?i)["''](?:test@test\.com|user@example\.com|admin@example\.com|testuser@|demo@|john@|jane@)[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["'']'
        },
        @{
            Name = "Default/Test Password"
            Pattern = '(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["''](?:password|passw0rd|admin|letmein|123456|qwerty|test|default|changeme|secret)["'']'
        },
        @{
            Name = "Default Username"
            Pattern = '(?i)(?:username|user_name|user|login)\s*[:=]\s*["''](?:admin|administrator|root|superuser|test|guest|demo|sa|postgres|oracle|mysql)["'']'
        },
        @{
            Name = "Database URL / Connection String"
            Pattern = '(?i)(?:mongodb(?:\+srv)?://|postgres(?:ql)?://|mysql://|redis://|rediss://|amqp://|rabbitmq://)[^\s"'';]{5,}'
        },
        @{
            Name = "PostgreSQL Connection"
            Pattern = '(?i)postgres(?:ql)?://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_]+'
        },
        @{
            Name = "MongoDB Connection"
            Pattern = '(?i)mongodb(?:\+srv)?://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+(?::\d+)?/[a-zA-Z0-9_]+'
        },
        @{
            Name = "MySQL Connection"
            Pattern = '(?i)mysql://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+:\d+/[a-zA-Z0-9_]+'
        },
        @{
            Name = "Redis Connection"
            Pattern = '(?i)redis://(?::[^@]+@)?[a-zA-Z0-9.-]+:\d+'
        },
        @{
            Name = "Internal Service URL"
            Pattern = '(?i)["''](https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[a-zA-Z0-9_\-./]+)?)["'']'
        },
        @{
            Name = "Internal Hostname"
            Pattern = '(?i)["''](https?://(?:[a-zA-Z0-9-]+\.internal|localhost|local[\.-][a-zA-Z0-9-]+|[a-zA-Z0-9-]+\.local)(?::\d+)?(?:/[a-zA-Z0-9_\-./]+)?)["'']'
        },
        @{
            Name = "Hardcoded IP Address"
            Pattern = '(?i)["''](https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+[^"''\s]*)["'']'
        },
        @{
            Name = "SSH Connection String"
            Pattern = '(?i)ssh://[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:\d+'
        },
        @{
            Name = "Hardcoded Password in URL"
            Pattern = '(?i)["''](https?://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+@[a-zA-Z0-9.-]+)["'']'
        },
        @{
            Name = "Test Credit Card"
            Pattern = '(?i)(?:4111111111111111|4111 1111 1111 1111|5555555555554444|5105105105105100|4012888888881881|4222222222222)'
        },
        @{
            Name = "Hardcoded Cookie/Token"
            Pattern = '(?i)(?:cookie|cookieValue|sessionToken|authToken|access_token|refresh_token)\s*[:=]\s*["'']([a-zA-Z0-9_\-]{20,})["'']'
        }
    )

    foreach ($entry in $patterns) {
        $matches = [regex]::Matches($content, $entry.Pattern)
        foreach ($m in $matches) {
            $displayVal = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Value }
            if ($displayVal.Length -gt 150) { $displayVal = $displayVal.Substring(0, 150) + '...' }
            $creds.Add([PSCustomObject]@{
                    Type  = $entry.Name
                    Match = $displayVal
                })
        }
    }

    $unique = $creds | Sort-Object Type, Match -Unique

    if ($unique.Count -eq 0) {
        Write-Host "  [-] No hardcoded credentials found." -ForegroundColor Gray
        return @()
    }

    Write-Host "  [+] Found $($unique.Count) potential hardcoded credentials:" -ForegroundColor Green
    $grouped = $unique | Group-Object Type | Sort-Object Count -Descending
    foreach ($g in $grouped) {
        Write-Host "      [$($g.Count)x] $($g.Name)" -ForegroundColor Yellow
    }
    Write-Host ""

    $unique | Format-Table Type, Match -AutoSize -Wrap | Out-String | ForEach-Object { Write-Host $_ }

    if ($OutputPath -and $unique.Count -gt 0) {
        $unique | Select-Object Type, Match | Format-Table -AutoSize -Wrap | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Saved credentials to: $OutputPath" -ForegroundColor DarkGray
    }

    return $unique
}

#endregion

#region Get-SourceMap

<#
.SYNOPSIS
    Downloads and extracts original source from JavaScript source maps.

.DESCRIPTION
    Parses sourceMappingURL comments from JS bundles, downloads the
    referenced .map files, and extracts original source files. Useful
    for recovering unminified source code from production bundles.

.PARAMETER Path
    Path to the JavaScript file containing a sourceMappingURL comment.

.PARAMETER SourceMapUrl
    Direct URL to the source map file (skips parsing the JS for the URL).

.PARAMETER OutputDir
    Directory to extract source files into.

.PARAMETER DownloadOnly
    Only download the .map file, do not extract sources.

.EXAMPLE
    Get-SourceMap -Path ".\beautified\app.bundle.js" -OutputDir ".\sources"
    Extract original sources from a bundle's source map.

.EXAMPLE
    Get-SourceMap -SourceMapUrl "https://example.com/assets/app.bundle.js.map" -OutputDir ".\sources"
    Download and extract sources from a direct source map URL.
#>
function Get-SourceMap {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'FromJs', Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(ParameterSetName = 'FromUrl', Mandatory = $true)]
        [string]$SourceMapUrl,

        [Parameter()]
        [string]$OutputDir = "$env:USERPROFILE\.js-analyzer-cache\sourcemaps",

        [Parameter()]
        [switch]$DownloadOnly,

        [Parameter()]
        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    Write-Host "[Get-SourceMap] Processing source map..." -ForegroundColor Cyan

    if (-not (Test-CommandExists "curl.exe")) {
        Write-Error "curl.exe is required but not found in PATH."
        return $null
    }

    if (-not $SourceMapUrl) {
        $content = Get-ContentSafely -Path $Path
        if ($null -eq $content) {
            Write-Error "Could not read file: $Path"
            return $null
        }

        $mapMatch = [regex]::Match($content, '(?i)//#\s*sourceMappingURL\s*=\s*(.+?)(?:\s*$|\n)')
        if (-not $mapMatch.Success) {
            $mapMatch = [regex]::Match($content, '(?i)/\*\s*sourceMappingURL\s*=\s*(.+?)\s*\*/')
        }
        if (-not $mapMatch.Success) {
            Write-Host "  [-] No sourceMappingURL comment found in $Path" -ForegroundColor Gray
            Write-Host "  [i] You can provide a direct URL with -SourceMapUrl" -ForegroundColor DarkGray
            return $null
        }

        $SourceMapUrl = $mapMatch.Groups[1].Value.Trim()

        if (-not $SourceMapUrl.StartsWith('http')) {
            $jsPath = (Get-Item -LiteralPath $Path).DirectoryName
            $resolved = Join-Path -Path $jsPath -ChildPath $SourceMapUrl
            if (Test-Path -LiteralPath $resolved) {
                Write-Host "  [i] Found relative source map at: $resolved" -ForegroundColor DarkGray
                $SourceMapUrl = $resolved
            } else {
                Write-Host "  [i] Relative source map: $SourceMapUrl (not resolved locally)" -ForegroundColor DarkGray
                return $null
            }
        }
    }

    Write-Host "  [~] Source map URL: $SourceMapUrl" -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $mapFileName = [System.IO.Path]::GetFileName($SourceMapUrl)
    if ([string]::IsNullOrWhiteSpace($mapFileName)) { $mapFileName = "sourcemap.json" }

    $mapFile = Join-Path -Path $OutputDir -ChildPath $mapFileName

    if (Test-Path -LiteralPath $mapFile) {
        Write-Host "  [i] Source map already cached: $mapFile" -ForegroundColor DarkGray
    } else {
        Write-Host "  [~] Downloading source map..." -ForegroundColor Yellow
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            $result = & curl.exe -L -s -S -o $tempFile --user-agent "$UserAgent" --connect-timeout 30 --max-time 60 "$SourceMapUrl" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Source map download failed: $result"
                if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force }
                return $null
            }
            Move-Item -LiteralPath $tempFile -Destination $mapFile -Force
            Write-Host "  [+] Downloaded source map: $mapFile" -ForegroundColor Green
        } catch {
            if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force }
            Write-Error "Download exception: $_"
            return $null
        }
    }

    if ($DownloadOnly) {
        Write-Host "  [i] Download-only mode. Source map saved to: $mapFile" -ForegroundColor DarkGray
        return [PSCustomObject]@{
            MapFile  = $mapFile
            Path     = $null
            Sources  = $null
        }
    }

    Write-Host "  [~] Extracting source files..." -ForegroundColor Yellow
    $mapContent = Get-ContentSafely -Path $mapFile
    if ($null -eq $mapContent) {
        Write-Error "Could not read source map file."
        return $null
    }

    try {
        $mapJson = $mapContent | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse source map JSON: $_"
        return $null
    }

    $sources = @()
    $extractedDir = Join-Path -Path $OutputDir -ChildPath "sources"
    if (-not (Test-Path -LiteralPath $extractedDir)) {
        New-Item -ItemType Directory -Path $extractedDir -Force | Out-Null
    }

    if ($null -ne $mapJson.sources -and $null -ne $mapJson.sourcesContent) {
        $sourceCount = [Math]::Min($mapJson.sources.Count, $mapJson.sourcesContent.Count)
        for ($i = 0; $i -lt $sourceCount; $i++) {
            $sourcePath = $mapJson.sources[$i]
            $sourceContent = $mapJson.sourcesContent[$i]
            if ([string]::IsNullOrWhiteSpace($sourceContent)) { continue }

            $cleanPath = $sourcePath -replace '^webpack:///|^webpack://|^file://', ''
            $cleanPath = $cleanPath -replace '^/', ''
            $cleanPath = $cleanPath -replace '\.\./|\./', ''

            $outPath = Join-Path -Path $extractedDir -ChildPath $cleanPath
            $outDir = Split-Path -Parent $outPath

            if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
                New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            }

            try {
                $sourceContent | Set-Content -LiteralPath $outPath -Encoding UTF8 -NoNewline
                $sources += $outPath
            } catch {
                Write-Warning "Could not write source: $cleanPath"
            }
        }
    }

    if ($sources.Count -eq 0) {
        Write-Host "  [-] No source content found in source map (sourcesContent missing or empty)." -ForegroundColor Gray
        Write-Host "  [i] The source map may be external (sourcesContent not embedded)." -ForegroundColor DarkGray
        return [PSCustomObject]@{
            MapFile  = $mapFile
            Path     = $null
            Sources  = @()
        }
    }

    Write-Host "  [+] Extracted $($sources.Count) source files to: $extractedDir" -ForegroundColor Green
    $sources | ForEach-Object {
        Write-Host "      $_" -ForegroundColor DarkGray
    }

    return [PSCustomObject]@{
        MapFile  = $mapFile
        Path     = $extractedDir
        Sources  = $sources
    }
}

#endregion

#region Compare-JsBundles

<#
.SYNOPSIS
    Compares two versions of a JavaScript bundle to find changes.

.DESCRIPTION
    Performs a structural diff between two JS bundle versions to identify
    new API endpoints, changed routes, added secrets, modified configuration,
    and significant structural changes. Useful for monitoring bundle evolution.

.PARAMETER OldPath
    Path to the older version of the bundle.

.PARAMETER NewPath
    Path to the newer version of the bundle.

.PARAMETER BundleName
    Friendly name for the bundle being compared.

.PARAMETER OutputPath
    Optional path to save the diff report.

.PARAMETER LinesOfContext
    Number of context lines around each change (default: 3).

.EXAMPLE
    Compare-JsBundles -OldPath ".\bundles\app.v1.js" -NewPath ".\bundles\app.v2.js" -BundleName "app"
    Compare two versions of a bundle.

.EXAMPLE
    Compare-JsBundles -OldPath ".\bundles\app.v1.js" -NewPath ".\bundles\app.v2.js" -OutputPath ".\diff.md"
    Compare and save a markdown diff report.
#>
function Compare-JsBundles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$OldPath,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$NewPath,

        [string]$BundleName = "bundle",

        [string]$OutputPath,

        [ValidateRange(1, 10)]
        [int]$LinesOfContext = 3
    )

    Write-Host "[Compare-JsBundles] Comparing $BundleName..." -ForegroundColor Cyan

    $oldContent = Get-ContentSafely -Path $OldPath
    $newContent = Get-ContentSafely -Path $NewPath

    if ($null -eq $oldContent -or $null -eq $newContent) {
        Write-Error "Could not read one or both files."
        return $null
    }

    $oldHash = Get-HashForFile -Path $OldPath
    $newHash = Get-HashForFile -Path $NewPath

    if ($oldHash -eq $newHash) {
        Write-Host "  [i] Bundles are identical (same SHA-256 hash)." -ForegroundColor Gray
        return [PSCustomObject]@{
            BundleName = $BundleName
            Identical  = $true
        }
    }

    $oldSize = (Get-Item -LiteralPath $OldPath).Length
    $newSize = (Get-Item -LiteralPath $NewPath).Length
    $sizeDiff = $newSize - $oldSize
    $sizePct = if ($oldSize -gt 0) { [math]::Round(($sizeDiff / $oldSize) * 100, 2) } else { 0 }

    Write-Host "  [i] Old hash: $oldHash" -ForegroundColor DarkGray
    Write-Host "  [i] New hash: $newHash" -ForegroundColor DarkGray
    Write-Host "  [i] Size change: $($oldSize / 1KB -as [int]) KB -> $($newSize / 1KB -as [int]) KB ($($sizeDiff / 1KB -as [int]) KB, $sizePct%)" -ForegroundColor DarkGray

    $oldLines = $oldContent -split '\r?\n'
    $newLines = $newContent -split '\r?\n'

    Write-Host "  [~] Performing structural comparison..." -ForegroundColor Yellow

    $newEndpoints = @()
    $removedEndpoints = @()
    $newSecrets = @()
    $newRoutes = @()
    $newConfigs = @()

    $tempDir = [System.IO.Path]::GetTempPath()
    $oldTemp = Join-Path -Path $tempDir -ChildPath "js_compare_old_$(Get-Random).js"
    $newTemp = Join-Path -Path $tempDir -ChildPath "js_compare_new_$(Get-Random).js"

    try {
        $oldContent | Set-Content -LiteralPath $oldTemp -Encoding UTF8
        $newContent | Set-Content -LiteralPath $newTemp -Encoding UTF8

        $oldEndpoints = Find-ApiEndpoints -Path $oldTemp | ForEach-Object { $_ }
        $newEndpointsResult = Find-ApiEndpoints -Path $newTemp | ForEach-Object { $_ }

        $newEndpoints = $newEndpointsResult | Where-Object { $_ -notin $oldEndpoints }
        $removedEndpoints = $oldEndpoints | Where-Object { $_ -notin $newEndpointsResult }

        $oldConfigs = (Find-ConfigLeaks -Path $oldTemp | ForEach-Object { $_.Match })
        $newConfigsResult = (Find-ConfigLeaks -Path $newTemp | ForEach-Object { $_.Match })
        $newConfigs = $newConfigsResult | Where-Object { $_ -notin $oldConfigs }

        $oldSecrets = (Find-Secrets -Path $oldTemp -MaskSecrets:$true | ForEach-Object { $_.Value })
        $newSecretsResult = (Find-Secrets -Path $newTemp -MaskSecrets:$true | ForEach-Object { $_.Value })
        $newSecrets = $newSecretsResult | Where-Object { $_ -notin $oldSecrets }

        $oldRoutes = Find-InternalRoutes -Path $oldTemp | ForEach-Object { $_ }
        $newRoutesResult = Find-InternalRoutes -Path $newTemp | ForEach-Object { $_ }
        $newRoutes = $newRoutesResult | Where-Object { $_ -notin $oldRoutes }
    } finally {
        Remove-Item -LiteralPath $oldTemp -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $newTemp -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "  === Comparison Results for: $BundleName ===" -ForegroundColor Cyan
    Write-Host ""

    if ($newEndpoints.Count -gt 0) {
        Write-Host "  [+] NEW API Endpoints ($($newEndpoints.Count)):" -ForegroundColor Green
        $newEndpoints | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($removedEndpoints.Count -gt 0) {
        Write-Host "  [-] REMOVED API Endpoints ($($removedEndpoints.Count)):" -ForegroundColor Red
        $removedEndpoints | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        Write-Host ""
    }

    if ($newSecrets.Count -gt 0) {
        Write-Host "  [+] NEW Potential Secrets ($($newSecrets.Count)):" -ForegroundColor Green
        $newSecrets | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($newRoutes.Count -gt 0) {
        Write-Host "  [+] NEW Internal Routes ($($newRoutes.Count)):" -ForegroundColor Green
        $newRoutes | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($newConfigs.Count -gt 0) {
        Write-Host "  [+] NEW Configuration Leaks ($($newConfigs.Count)):" -ForegroundColor Green
        $newConfigs | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($newEndpoints.Count -eq 0 -and $removedEndpoints.Count -eq 0 -and $newSecrets.Count -eq 0 -and $newRoutes.Count -eq 0 -and $newConfigs.Count -eq 0) {
        Write-Host "  [i] No significant structural changes detected." -ForegroundColor Gray
    }

    $result = [PSCustomObject]@{
        BundleName         = $BundleName
        Identical          = $false
        OldHash            = $oldHash
        NewHash            = $newHash
        OldSize            = $oldSize
        NewSize            = $newSize
        SizeDiff           = $sizeDiff
        SizePctChange      = $sizePct
        NewEndpoints       = $newEndpoints
        RemovedEndpoints   = $removedEndpoints
        NewSecrets         = $newSecrets
        NewRoutes          = $newRoutes
        NewConfigLeaks     = $newConfigs
        OldLineCount       = $oldLines.Count
        NewLineCount       = $newLines.Count
    }

    if ($OutputPath) {
        $reportLines = @()
        $reportLines += "# JS Bundle Comparison Report: $BundleName"
        $reportLines += ""
        $reportLines += "**Old Hash:** $oldHash"
        $reportLines += "**New Hash:** $newHash"
        $reportLines += "**Size:** $($oldSize / 1KB -as [int]) KB → $($newSize / 1KB -as [int]) KB ($([math]::Abs($sizeDiff) / 1KB -as [int]) KB, $sizePct%)"
        $reportLines += "**Lines:** $($oldLines.Count) → $($newLines.Count)"
        $reportLines += ""
        $reportLines += "## New Endpoints ($($newEndpoints.Count))"
        if ($newEndpoints.Count -gt 0) { $newEndpoints | ForEach-Object { $reportLines += "- $_" } }
        else { $reportLines += "*None*" }
        $reportLines += ""
        $reportLines += "## Removed Endpoints ($($removedEndpoints.Count))"
        if ($removedEndpoints.Count -gt 0) { $removedEndpoints | ForEach-Object { $reportLines += "- $_" } }
        else { $reportLines += "*None*" }
        $reportLines += ""
        $reportLines += "## New Secrets ($($newSecrets.Count))"
        if ($newSecrets.Count -gt 0) { $newSecrets | ForEach-Object { $reportLines += "- $_" } }
        else { $reportLines += "*None*" }
        $reportLines += ""
        $reportLines += "## New Routes ($($newRoutes.Count))"
        if ($newRoutes.Count -gt 0) { $newRoutes | ForEach-Object { $reportLines += "- $_" } }
        else { $reportLines += "*None*" }
        $reportLines += ""
        $reportLines += "## New Config Leaks ($($newConfigs.Count))"
        if ($newConfigs.Count -gt 0) { $newConfigs | ForEach-Object { $reportLines += "- $_" } }
        else { $reportLines += "*None*" }
        $reportLines += ""

        $reportLines -join "`n" | Out-File -LiteralPath $OutputPath -Encoding UTF8
        Write-Host "  [i] Report saved to: $OutputPath" -ForegroundColor DarkGray
    }

    return $result
}

#endregion

#region Invoke-FullJsScan

<#
.SYNOPSIS
    Runs all analysis functions on a JavaScript bundle.

.DESCRIPTION
    Orchestrates all available scans — API endpoints, secrets, feature flags,
    internal routes, config leaks, and hardcoded credentials — on a given
    bundle. Optionally beautifies the bundle first and extracts source maps.
    Returns a structured object with all findings.

.PARAMETER Path
    Path to the JavaScript bundle to scan.

.PARAMETER Url
    URL to download and scan a bundle (alternative to Path).

.PARAMETER BeautifyBeforeScan
    Beautify the bundle before scanning (improves detection).

.PARAMETER SourceMapExtract
    Attempt source map extraction after scanning.

.PARAMETER OutputDir
    Directory to save scan outputs.

.PARAMETER CacheDir
    Cache directory for downloaded bundles.

.EXAMPLE
    Invoke-FullJsScan -Path ".\beautified\app.js" -OutputDir ".\scan-results"
    Full scan on a local JS file with output directory.

.EXAMPLE
    Invoke-FullJsScan -Url "https://example.com/assets/app.bundle.js" -BeautifyBeforeScan -SourceMapExtract
    Download, beautify, scan, and extract source maps from a remote bundle.
#>
function Invoke-FullJsScan {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Local', Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$Path,

        [Parameter(ParameterSetName = 'Remote', Mandatory = $true)]
        [string]$Url,

        [switch]$BeautifyBeforeScan = $true,

        [switch]$SourceMapExtract,

        [string]$OutputDir,

        [string]$CacheDir = "$env:USERPROFILE\.js-analyzer-cache",

        [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         Invoke-FullJsScan — Comprehensive Scan       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $scanPath = $Path
    $sourceUrl = $Url
    $bundleName = "bundle"

    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        Write-Host "[~] Downloading bundle from: $Url" -ForegroundColor Yellow
        $bundleName = Get-BundleFileName -Url $Url
        $result = Get-JsBundle -Url $Url -CacheDir $CacheDir -UserAgent $UserAgent
        if ($null -eq $result) {
            Write-Error "Failed to download bundle."
            return $null
        }
        $scanPath = $result.Path
        Write-Host ""
    } else {
        Write-Host "[i] Scanning local file: $Path" -ForegroundColor DarkGray
        $bundleName = [System.IO.Path]::GetFileName($Path)
    }

    $baseDir = if ($OutputDir) {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }
        $OutputDir
    } else {
        (Get-Item -LiteralPath $scanPath).DirectoryName
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runDir = Join-Path -Path $baseDir -ChildPath "scan-$bundleName-$timestamp"
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null

    $scanFile = $scanPath

    if ($BeautifyBeforeScan) {
        Write-Host "[~] Beautifying bundle..." -ForegroundColor Yellow
        $beautifiedPath = Join-Path -Path $runDir -ChildPath "$bundleName.beautified.js"
        $beautyResult = Invoke-JsBeautify -Path $scanPath -OutputPath $beautifiedPath
        if ($null -ne $beautyResult) {
            $scanFile = $beautifiedPath
        }
        Write-Host ""
    }

    $findings = @{}
    $executionTimes = @{}

    $scanSteps = @(
        @{ Name = "API Endpoints"; Func = 'Find-ApiEndpoints'; File = "api-endpoints.txt" },
        @{ Name = "Secrets"; Func = 'Find-Secrets'; File = "secrets.txt" },
        @{ Name = "Feature Flags"; Func = 'Find-FeatureFlags'; File = "feature-flags.txt" },
        @{ Name = "Internal Routes"; Func = 'Find-InternalRoutes'; File = "internal-routes.txt" },
        @{ Name = "Config Leaks"; Func = 'Find-ConfigLeaks'; File = "config-leaks.txt" },
        @{ Name = "Hardcoded Credentials"; Func = 'Find-HardcodedCreds'; File = "hardcoded-creds.txt" }
    )

    foreach ($step in $scanSteps) {
        Write-Host ("─" * 50) -ForegroundColor DarkGray
        $startTime = Get-Date
        Write-Host "[~] Running: $($step.Name)..." -ForegroundColor Yellow
        $outFile = Join-Path -Path $runDir -ChildPath $step.File

        switch ($step.Func) {
            'Find-ApiEndpoints' { $result = Find-ApiEndpoints -Path $scanFile -OutputPath $outFile }
            'Find-Secrets' { $result = Find-Secrets -Path $scanFile -OutputPath $outFile }
            'Find-FeatureFlags' { $result = Find-FeatureFlags -Path $scanFile -OutputPath $outFile }
            'Find-InternalRoutes' { $result = Find-InternalRoutes -Path $scanFile -OutputPath $outFile }
            'Find-ConfigLeaks' { $result = Find-ConfigLeaks -Path $scanFile -OutputPath $outFile }
            'Find-HardcodedCreds' { $result = Find-HardcodedCreds -Path $scanFile -OutputPath $outFile }
        }

        $elapsed = (Get-Date) - $startTime
        $findings[$step.Name] = $result
        $executionTimes[$step.Name] = $elapsed.TotalSeconds
        Write-Host "  [i] Completed in $($elapsed.TotalSeconds -as [int])s" -ForegroundColor DarkGray
    }

    Write-Host ("─" * 50) -ForegroundColor DarkGray
    Write-Host ""

    if ($SourceMapExtract) {
        Write-Host "[~] Attempting source map extraction..." -ForegroundColor Yellow
        $sourcesDir = "$env:USERPROFILE\.js-analyzer-cache\sourcemaps"
        $mapResult = Get-SourceMap -Path $scanPath -OutputDir $sourcesDir
        if ($null -ne $mapResult) {
            $findings['SourceMap'] = $mapResult
        }
        Write-Host ""
    }

    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                   Scan Complete                       ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    $totalCount = 0
    foreach ($key in $findings.Keys) {
        if ($findings[$key] -is [array] -or $findings[$key] -is [System.Collections.ICollection]) {
            $count = @($findings[$key]).Count
            $totalCount += $count
            Write-Host "  [+] $key`: $count items" -ForegroundColor Green
        } elseif ($null -ne $findings[$key] -and $findings[$key].GetType().Name -eq 'PSCustomObject') {
            Write-Host "  [+] $key`: $($findings[$key] | Out-String | Measure-Object -Line | Select-Object -ExpandProperty Lines) items" -ForegroundColor Green
        }
    }
    Write-Host "  [i] Total findings: $totalCount" -ForegroundColor Cyan
    Write-Host "  [i] Output directory: $runDir" -ForegroundColor DarkGray
    Write-Host ""

    $summary = [PSCustomObject]@{
        BundleName   = $bundleName
        SourceFile   = $scanPath
        OriginalFile = $scanPath
        Timestamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        OutputDir    = $runDir
        Findings     = $findings
        Timing       = $executionTimes
        TotalItems   = $totalCount
    }

    $summaryPath = Join-Path -Path $runDir -ChildPath "scan-summary.json"
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Host "  [i] Summary JSON: $summaryPath" -ForegroundColor DarkGray

    return $summary
}

#endregion

#region Out-JsReport

<#
.SYNOPSIS
    Formats JS bundle scan results as a structured markdown report.

.DESCRIPTION
    Takes the output of Invoke-FullJsScan (or individual scan functions)
    and produces a professional markdown report suitable for bug bounty
    submissions or engagement deliverables.

.PARAMETER ScanResult
    The result object from Invoke-FullJsScan to format into a report.

.PARAMETER OutputPath
    Path to write the markdown report file.

.PARAMETER Title
    Custom title for the report.

.PARAMETER IncludeRawMatches
    Include raw matched values in the report (not just counts).

.EXAMPLE
    Out-JsReport -ScanResult $result -OutputPath ".\report.md"
    Generate a markdown report from a full scan result.

.EXAMPLE
    Out-JsReport -ScanResult $result -OutputPath ".\report.md" -Title "example.com JS Analysis"
    Generate a report with a custom title.
#>
function Out-JsReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [PSObject]$ScanResult,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [string]$Title = "JS Bundle Analysis Report",

        [switch]$IncludeRawMatches
    )

    Write-Host "[Out-JsReport] Generating markdown report..." -ForegroundColor Cyan

    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("# $Title")
    $lines.Add("")
    $lines.Add("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("**Tool:** JS-Analyzer v1.0.0")
    if ($ScanResult.BundleName) {
        $lines.Add("**Bundle:** $($ScanResult.BundleName)")
    }
    if ($ScanResult.SourceFile) {
        $lines.Add("**Source File:** $($ScanResult.SourceFile)")
    }
    $lines.Add("")

    if ($ScanResult.TotalItems -ge 0) {
        $lines.Add("## Summary")
        $lines.Add("")
        $lines.Add("| Metric | Value |")
        $lines.Add("|--------|-------|")
        $lines.Add("| Total Findings | $($ScanResult.TotalItems) |")
        $lines.Add("| Scan Time | $($ScanResult.Timestamp) |")

        if ($ScanResult.Timing) {
            $totalTime = ($ScanResult.Timing.Values | Measure-Object -Sum).Sum
            $lines.Add("| Total Analysis Time | $($totalTime -as [int])s |")
        }

        if ($ScanResult.Findings) {
            foreach ($key in $ScanResult.Findings.Keys) {
                $items = $ScanResult.Findings[$key]
                $count = if ($items -is [array] -or $items -is [System.Collections.ICollection]) { @($items).Count }
                elseif ($null -eq $items) { 0 }
                elseif ($items.GetType().Name -eq 'PSCustomObject') { 1 }
                else { @($items).Count }
                $lines.Add("| $key | $count |")
            }
        }
        $lines.Add("")
    }

    if ($ScanResult.Findings) {
        foreach ($key in $ScanResult.Findings.Keys) {
            $items = $ScanResult.Findings[$key]
            if ($null -eq $items) { continue }
            if ($items -is [array]) {
                $count = $items.Count
                if ($count -eq 0) { continue }
                $lines.Add("## $key")
                $lines.Add("")
                $lines.Add("**Found:** $count items")
                $lines.Add("")

                if ($IncludeRawMatches) {
                    $lines.Add("| # | Value |")
                    $lines.Add("|---|-------|")
                    $i = 1
                    foreach ($item in $items) {
                        $display = "$item".Substring(0, [Math]::Min(200, "$item".Length))
                        $lines.Add("| $i | $display |")
                        $i++
                    }
                    $lines.Add("")
                } else {
                    $items | ForEach-Object { $lines.Add("- $_") }
                    $lines.Add("")
                }
            } elseif ($items.GetType().Name -eq 'PSCustomObject') {
                $lines.Add("## $key")
                $lines.Add("")
                foreach ($prop in $items.PSObject.Properties) {
                    $val = $prop.Value
                    if ($val -is [array]) {
                        $lines.Add("**$($prop.Name):** $($val.Count) items")
                        if ($IncludeRawMatches) {
                            $val | ForEach-Object { $lines.Add("- $_") }
                        }
                    } else {
                        $lines.Add("**$($prop.Name):** $val")
                    }
                }
                $lines.Add("")
            }
        }
    }

    if ($ScanResult.Timing -and ($ScanResult.Timing.Keys.Count -gt 0)) {
        $lines.Add("## Performance")
        $lines.Add("")
        $lines.Add("| Scan Step | Duration (s) |")
        $lines.Add("|-----------|--------------|")
        foreach ($step in $ScanResult.Timing.Keys) {
            $lines.Add("| $step | $([math]::Round($ScanResult.Timing[$step], 2)) |")
        }
        $lines.Add("")
    }

    $lines.Add("---")
    $lines.Add("")
    $lines.Add("*Report generated by JS-Analyzer v1.0.0 | Bug Bounty Reconnaissance Toolkit*")

    $reportContent = $lines -join "`n"
    $reportContent | Out-File -LiteralPath $OutputPath -Encoding UTF8

    Write-Host "  [+] Report saved: $OutputPath ($((Get-Item -LiteralPath $OutputPath).Length / 1KB -as [int]) KB)" -ForegroundColor Green

    return [PSCustomObject]@{
        Path    = $OutputPath
        Lines   = $lines.Count
    }
}

#endregion

#region MainExecution

Write-Host "PowerShell $($PSVersionTable.PSVersion) | OS: $([Environment]::OSVersion.VersionString)" -ForegroundColor DarkGray
Write-Host ""

switch ($PSCmdlet.ParameterSetName) {
    'Scan' {
        if ($FullScan) {
            if ($BundleUrl) {
                Invoke-FullJsScan -Url $BundleUrl -BeautifyBeforeScan -SourceMapExtract:$SourceMap -OutputDir $ReportPath ? (Split-Path -Parent $ReportPath) : $null
            } elseif ($BundlePath) {
                Invoke-FullJsScan -Path $BundlePath -BeautifyBeforeScan:$Beautify -SourceMapExtract:$SourceMap -OutputDir $ReportPath ? (Split-Path -Parent $ReportPath) : $null
            } else {
                Write-Error "Provide -BundleUrl or -BundlePath for full scan."
            }
            return
        }

        $targetPath = $null
        if ($BundleUrl) {
            $bundle = Get-JsBundle -Url $BundleUrl -CacheDir $CacheDir -SkipCache:$SkipCache
            if ($null -eq $bundle) { return }
            $targetPath = $bundle.Path
        } elseif ($BundlePath) {
            if (-not (Test-Path -LiteralPath $BundlePath)) {
                Write-Error "Bundle path not found: $BundlePath"
                return
            }
            $targetPath = $BundlePath
        } else {
            Write-Host "No action specified. Use -BundleUrl, -BundlePath, or -FullScan." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Available commands:" -ForegroundColor Cyan
            Write-Host "  Get-JsBundle          Download JS bundles from URLs" -ForegroundColor White
            Write-Host "  Invoke-JsBeautify     Beautify minified JavaScript" -ForegroundColor White
            Write-Host "  Find-ApiEndpoints     Extract API endpoint paths" -ForegroundColor White
            Write-Host "  Find-Secrets          Scan for hardcoded secrets" -ForegroundColor White
            Write-Host "  Find-FeatureFlags     Extract feature flags and toggles" -ForegroundColor White
            Write-Host "  Find-InternalRoutes   Discover internal application routes" -ForegroundColor White
            Write-Host "  Find-ConfigLeaks      Detect configuration leaks" -ForegroundColor White
            Write-Host "  Find-HardcodedCreds   Find hardcoded credentials" -ForegroundColor White
            Write-Host "  Get-SourceMap         Download and extract source maps" -ForegroundColor White
            Write-Host "  Compare-JsBundles     Diff two bundle versions" -ForegroundColor White
            Write-Host "  Invoke-FullJsScan     Run all scans on a bundle" -ForegroundColor White
            Write-Host "  Out-JsReport          Format results as markdown report" -ForegroundColor White
            Write-Host ""
            Write-Host "Examples:" -ForegroundColor Cyan
            Write-Host '  .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.js" -FullScan' -ForegroundColor Yellow
            Write-Host '  .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.js" -Secrets -ConfigLeaks' -ForegroundColor Yellow
            Write-Host '  .\js-analyzer.ps1 -CompareOld "old.js" -CompareNew "new.js" -CompareReport' -ForegroundColor Yellow
            return
        }

        if (-not $Beautify -and -not $ApiEndpoints -and -not $Secrets -and -not $FeatureFlags -and -not $InternalRoutes -and -not $ConfigLeaks -and -not $HardcodedCreds -and -not $SourceMap) {
            Write-Host "No scan flags specified. Use -FullScan or individual flags:" -ForegroundColor Yellow
            Write-Host "  -Secrets, -ApiEndpoints, -ConfigLeaks, -FeatureFlags, -InternalRoutes, -HardcodedCreds, -SourceMap, -Beautify" -ForegroundColor White
            return
        }

        if ($Beautify) {
            Invoke-JsBeautify -Path $targetPath
            Write-Host ""
        }

        if ($ApiEndpoints) { Find-ApiEndpoints -Path $targetPath; Write-Host "" }
        if ($Secrets) { Find-Secrets -Path $targetPath; Write-Host "" }
        if ($FeatureFlags) { Find-FeatureFlags -Path $targetPath; Write-Host "" }
        if ($InternalRoutes) { Find-InternalRoutes -Path $targetPath; Write-Host "" }
        if ($ConfigLeaks) { Find-ConfigLeaks -Path $targetPath; Write-Host "" }
        if ($HardcodedCreds) { Find-HardcodedCreds -Path $targetPath; Write-Host "" }
        if ($SourceMap) { Get-SourceMap -Path $targetPath; Write-Host "" }
        break
    }

    'Compare' {
        if (-not $CompareOld -or -not $CompareNew) {
            Write-Error "Both -CompareOld and -CompareNew are required."
            return
        }
        $result = Compare-JsBundles -OldPath $CompareOld -NewPath $CompareNew -BundleName $CompareName
        if ($CompareReport) {
            $reportFile = Join-Path -Path (Get-Location).Path -ChildPath "$CompareName-diff-report.md"
            Out-JsReport -ScanResult $result -OutputPath $reportFile -Title "Bundle Diff: $CompareName"
        }
        break
    }

    default {
        Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║       JS Bundle Analysis Toolkit v1.0.0              ║" -ForegroundColor Cyan
        Write-Host "║       Bug Bounty Reconnaissance Utility              ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage: .\js-analyzer.ps1 [options]" -ForegroundColor White
        Write-Host ""
        Write-Host "Scan Options:" -ForegroundColor Cyan
        Write-Host "  -BundleUrl <url>         URL to a JS bundle to download and scan"
        Write-Host "  -BundlePath <path>       Path to a local JS bundle file"
        Write-Host "  -FullScan                Run all available scans"
        Write-Host "  -Beautify                Beautify the bundle before scanning"
        Write-Host "  -ApiEndpoints            Extract API endpoints"
        Write-Host "  -Secrets                 Scan for hardcoded secrets"
        Write-Host "  -FeatureFlags            Extract feature flags"
        Write-Host "  -InternalRoutes          Discover internal routes"
        Write-Host "  -ConfigLeaks             Detect configuration leaks"
        Write-Host "  -HardcodedCreds          Find hardcoded credentials"
        Write-Host "  -SourceMap               Download and extract source maps"
        Write-Host "  -ReportPath <path>       Output path for reports"
        Write-Host "  -CacheDir <path>         Directory for bundle caching"
        Write-Host "  -SkipCache               Skip cache and force re-download"
        Write-Host ""
        Write-Host "Compare Options:" -ForegroundColor Cyan
        Write-Host "  -CompareOld <path>       Path to the older bundle version"
        Write-Host "  -CompareNew <path>       Path to the newer bundle version"
        Write-Host "  -CompareName <name>      Friendly name for the bundle"
        Write-Host "  -CompareReport           Save a diff report"
        Write-Host ""
        Write-Host "Examples:" -ForegroundColor Cyan
        Write-Host '  .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.js" -FullScan' -ForegroundColor Yellow
        Write-Host '  .\js-analyzer.ps1 -BundleUrl "https://example.com/assets/app.js" -Secrets -ConfigLeaks' -ForegroundColor Yellow
        Write-Host '  .\js-analyzer.ps1 -BundlePath ".\bundles\app.js" -ApiEndpoints -InternalRoutes' -ForegroundColor Yellow
        Write-Host '  .\js-analyzer.ps1 -CompareOld "app.v1.js" -CompareNew "app.v2.js" -CompareReport' -ForegroundColor Yellow
    }
}

#endregion
