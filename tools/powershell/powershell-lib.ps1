<#
.SYNOPSIS
    PowerShell One-Liner & Function Library for Bug Bounty Hunting on Windows
.DESCRIPTION
    A comprehensive library of reusable PowerShell functions for bug bounty
    reconnaissance, HTTP manipulation, data processing, and reporting.

    Includes: HTTP helpers, string/regex tools, file/URL/JSON handlers,
    encoding, crypto, recon, wordlist, output, and session management.

.NOTES
    Author  : Jiggy-2026 Toolchain
    Version : 1.0.0
    Requires: PowerShell 5.1+, Windows OS
    Safety  : This script uses Invoke-WebRequest, Test-NetConnection, and
              other network probes. Use ONLY against authorized targets.
              Some functions call external binaries (curl.exe, nslookup,
              certutil.exe) which may trigger AV/EDR alerts on monitored
              systems.

.WARNING
    ⚠ This library is for AUTHORIZED security testing only.
    ⚠ Network probes (DNS, ping, port scans) may trigger detection.
    ⚠ Do NOT store API keys or tokens in script variables in production.
    ⚠ Review proxy settings before sending traffic to live targets.
#>

using namespace System.Net
using namespace System.Text
using namespace System.IO

# ============================================================================
# SECTION 1 — GLOBAL CONFIGURATION & STATE
# ============================================================================

$Script:BBConfig = @{
    ProxyEnabled   = $false
    ProxyUrl       = $null
    ProxyCreds     = $null
    UserAgent      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
    OutputDir      = Join-Path -Path $env:TEMP -ChildPath 'bb-output'
    LogFile        = $null
    VerboseOutput  = $true
    DefaultTimeout = 30
    SecListsPath   = $null
}

$Script:History = [System.Collections.ArrayList]@()
$Script:Findings = [System.Collections.ArrayList]@()

# ============================================================================
# SECTION 2 — HTTP HELPERS
# ============================================================================

<#
.SYNOPSIS
    Sets proxy configuration for all subsequent HTTP calls.
.PARAMETER Url
    Full proxy URL (e.g. http://127.0.0.1:8080).
.PARAMETER Credential
    Optional PSCredential for authenticated proxies.
.EXAMPLE
    Set-BBProxy -Url 'http://127.0.0.1:8080'
#>
function Set-BBProxy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [System.Management.Automation.PSCredential]$Credential
    )
    $Script:BBConfig.ProxyEnabled = $true
    $Script:BBConfig.ProxyUrl = $Url
    if ($Credential) { $Script:BBConfig.ProxyCreds = $Credential }
    Write-BBInfo "Proxy set to $Url"
}

<#
.SYNOPSIS
    Disables the configured proxy.
#>
function Clear-BBProxy {
    $Script:BBConfig.ProxyEnabled = $false
    $Script:BBConfig.ProxyUrl = $null
    $Script:BBConfig.ProxyCreds = $null
    Write-BBInfo 'Proxy disabled'
}

<#
.SYNOPSIS
    Returns a configured WebSession object based on global settings.
#>
function New-BBWebSession {
    [CmdletBinding()]
    param(
        [string]$UserAgent = $Script:BBConfig.UserAgent,
        [System.Net.CookieContainer]$Cookies
    )
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = $UserAgent
    if ($Cookies) { $session.Cookies = $Cookies }
    return $session
}

<#
.SYNOPSIS
    Wrapper around Invoke-WebRequest with proxy, timeout, and cookie support.
.PARAMETER Uri
    Target URL.
.PARAMETER Method
    HTTP method (GET, POST, PUT, DELETE, etc.).
.PARAMETER Headers
    Hashtable of custom headers.
.PARAMETER Body
    Request body (string or hashtable).
.PARAMETER ContentType
    Content-Type header value.
.PARAMETER Cookie
    Simple string cookie (e.g. "session=abc123").
.PARAMETER OutFile
    Save response body to file.
.PARAMETER NoFollowRedirect
    Switch to disable automatic redirect following.
.PARAMETER Raw
    Switch to return raw HttpResponse instead of processed result.
.EXAMPLE
    Invoke-BBRequest -Uri 'https://target.com/api/users' -Method GET -Headers @{Authorization='Bearer xxx'}
#>
function Invoke-BBRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ $_ -match '^https?://' })]
        [string]$Uri,

        [ValidateSet('GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD')]
        [string]$Method = 'GET',

        [hashtable]$Headers = @{},

        [object]$Body,

        [string]$ContentType,

        [string]$Cookie,

        [string]$OutFile,

        [switch]$NoFollowRedirect,

        [switch]$Raw
    )

    $params = @{
        Uri    = $Uri
        Method = $Method
        UseBasicParsing = $true
    }

    if ($Script:BBConfig.ProxyEnabled -and $Script:BBConfig.ProxyUrl) {
        $params.Proxy = $Script:BBConfig.ProxyUrl
        if ($Script:BBConfig.ProxyCreds) {
            $params.ProxyCredential = $Script:BBConfig.ProxyCreds
        }
    }

    if ($Headers.Count -gt 0) { $params.Headers = $Headers }
    if ($Body) {
        $params.Body = $Body
        if (-not $ContentType -and ($Body -is [hashtable])) {
            $params.ContentType = 'application/x-www-form-urlencoded'
        }
    }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($Cookie) { $params.Headers['Cookie'] = $Cookie }
    if ($OutFile) { $params.OutFile = $OutFile }
    if ($NoFollowRedirect) { $params.MaximumRedirection = 0 }
    if ($Script:BBConfig.UserAgent) { $params.UserAgent = $Script:BBConfig.UserAgent }

    $params.TimeoutSec = $Script:BBConfig.DefaultTimeout

    try {
        $resp = Invoke-WebRequest @params
        Add-BBHistory -Action "HTTP $Method $Uri" -Status $resp.StatusCode
        if ($Raw) { return $resp }
        return @{
            StatusCode   = [int]$resp.StatusCode
            StatusDesc   = $resp.StatusDescription
            Headers      = $resp.Headers
            Content      = $resp.Content
            RawContent   = $resp.RawContent
            ContentLength = $resp.RawContentLength
        }
    }
    catch [System.Net.WebException] {
        $ex = $_.Exception
        $code = if ($ex.Response) { [int]$ex.Response.StatusCode } else { 0 }
        Add-BBHistory -Action "HTTP $Method $Uri" -Status "FAIL:$code"
        Write-BBError "Request failed ($code): $Uri"
        return $null
    }
    catch {
        Add-BBHistory -Action "HTTP $Method $Uri" -Status 'FAIL'
        Write-BBError "Request error: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Quick one-liner GET request returning just the content string.
#>
function Get-BBUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Uri
    )
    $r = Invoke-BBRequest -Uri $Uri -Method GET
    if ($r -and $r.Content) { return [System.Text.Encoding]::UTF8.GetString($r.Content) }
    return $null
}

<#
.SYNOPSIS
    Sends a POST with form data or JSON body.
.PARAMETER Uri
    Target URL.
.PARAMETER Data
    Hashtable of form fields or raw JSON string.
.PARAMETER Json
    Switch to send as application/json.
.EXAMPLE
    Send-BBPost -Uri 'https://target.com/api/login' -Data @{user='admin';pass='test'} -Json
#>
function Send-BBPost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [object]$Data,

        [switch]$Json
    )
    if ($Json) {
        $body = if ($Data -is [string]) { $Data } else { $Data | ConvertTo-Json -Compress }
        return Invoke-BBRequest -Uri $Uri -Method POST -Body $body -ContentType 'application/json'
    }
    return Invoke-BBRequest -Uri $Uri -Method POST -Body $Data
}

<#
.SYNOPSIS
    Extracts cookies from a raw HTTP response string or WebResponse.
#>
function Get-BBCookies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Response
    )
    process {
        if ($Response -is [string]) {
            $lines = $Response -split "`r`n|`n"
            foreach ($line in $lines) {
                if ($line -match '^Set-Cookie:\s*(?<cookie>[^;]+)') {
                    $parts = $matches['cookie'] -split '='
                    [PSCustomObject]@{
                        Name  = $parts[0]
                        Value = if ($parts.Count -gt 1) { $parts[1..($parts.Count-1)] -join '=' } else { '' }
                    }
                }
            }
        }
        elseif ($Response.Headers) {
            $raw = $Response.Headers
            if ($raw['Set-Cookie']) {
                foreach ($c in $raw['Set-Cookie']) {
                    $parts = ($c -split ';')[0] -split '='
                    [PSCustomObject]@{
                        Name  = $parts[0]
                        Value = if ($parts.Count -gt 1) { $parts[1..($parts.Count-1)] -join '=' } else { '' }
                    }
                }
            }
        }
    }
}

<#
.SYNOPSIS
    Measures response time of an HTTP request.
#>
function Measure-BBRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$Count = 1
    )
    $times = for ($i = 0; $i -lt $Count; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Invoke-BBRequest -Uri $Uri -Method GET
        $sw.Stop()
        $sw.ElapsedMilliseconds
    }
    [PSCustomObject]@{
        Uri        = $Uri
        Count      = $Count
        Min        = ($times | Measure-Object -Minimum).Minimum
        Max        = ($times | Measure-Object -Maximum).Maximum
        Avg        = [math]::Round(($times | Measure-Object -Average).Average, 1)
        Total      = ($times | Measure-Object -Sum).Sum
    }
}

<#
.SYNOPSIS
    Searches HTTP response content for a regex pattern.
#>
function Search-BBResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$Pattern
    )
    $content = Get-BBUrl -Uri $Uri
    if (-not $content) { return }
    $content | Select-String -Pattern $Pattern -AllMatches | ForEach-Object {
        [PSCustomObject]@{
            Line    = $_.LineNumber
            Match   = $_.Matches.Value
            Context = $_.Line.Trim()
        }
    }
}

# ============================================================================
# SECTION 3 — STRING / REGEX HELPERS
# ============================================================================

<#
.SYNOPSIS
    Greps an array of strings or file content for multiple patterns.
.PARAMETER InputObject
    String array or file path.
.PARAMETER Patterns
    Array of regex patterns.
.PARAMETER SimpleMatch
    Treat patterns as literal strings.
.PARAMETER CaseSensitive
    Perform case-sensitive matching.
#>
function Select-BBString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Pattern,

        [switch]$SimpleMatch,

        [switch]$CaseSensitive
    )
    begin { $list = [System.Collections.ArrayList]@() }
    process { $null = $list.Add($InputObject) }
    end {
        $opts = @{Pattern = $Pattern}
        if ($SimpleMatch) { $opts.SimpleMatch = $true }
        if ($CaseSensitive) { $opts.CaseSensitive = $true }
        $list | Select-String @opts
    }
}

<#
.SYNOPSIS
    Returns only lines matching a pattern (grep -o style).
#>
function Get-BBMatchingLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$InputObject,

        [Parameter(Mandatory)]
        [string]$Pattern
    )
    process {
        if ($InputObject -match $Pattern) { $InputObject }
    }
}

<#
.SYNOPSIS
    Extracts all regex matches from a string.
#>
function Get-BBMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [switch]$All,

        [int]$Group = 0
    )
    process {
        if ($All) {
            [regex]::Matches($Text, $Pattern) | ForEach-Object {
                if ($_.Groups.Count -gt $Group) { $_.Groups[$Group].Value } else { $_.Value }
            }
        }
        else {
            if ($Text -match $Pattern) {
                if ($Matches.Count -gt $Group) { $Matches[$Group] } else { $Matches[0] }
            }
        }
    }
}

<#
.SYNOPSIS
    Deduplicates an array of strings (case-insensitive by default).
#>
function Remove-BBDuplicate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$InputObject,

        [switch]$CaseSensitive
    )
    begin { $seen = @{} }
    process {
        foreach ($item in $InputObject) {
            $key = if ($CaseSensitive) { $item } else { $item.ToLowerInvariant() }
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $item
            }
        }
    }
}

<#
.SYNOPSIS
    Escapes special regex characters in a string.
#>
function ConvertTo-BBRegexPattern {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$LiteralText
    )
    process { [regex]::Escape($LiteralText) }
}

<#
.SYNOPSIS
    Splits a string on multiple delimiters and trims results.
#>
function Split-BBString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$InputObject,

        [string[]]$Delimiter = @(' ', "`t", ',', ';', '|'),

        [switch]$NoEmpty
    )
    process {
        $opts = [System.StringSplitOptions]::None
        if ($NoEmpty) { $opts = [System.StringSplitOptions]::RemoveEmptyEntries }
        $InputObject.Split($Delimiter, $opts) | ForEach-Object { $_.Trim() }
    }
}

<#
.SYNOPSIS
    Displays n lines of context around each match in a multi-line string.
#>
function Show-BBContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$Lines,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [int]$Before = 2,
        [int]$After = 2
    )
    begin { $all = @() }
    process { $all += $Lines }
    end {
        $idx = 0
        foreach ($line in $all) {
            if ($line -match $Pattern) {
                $start = [Math]::Max(0, $idx - $Before)
                $end   = [Math]::Min($all.Count - 1, $idx + $After)
                Write-BBInfo "--- match at line $($idx + 1) ---"
                for ($i = $start; $i -le $end; $i++) {
                    $prefix = if ($i -eq $idx) { '>>' } else { '  ' }
                    Write-Host "$prefix $($all[$i])"
                }
            }
            $idx++
        }
    }
}

# ============================================================================
# SECTION 4 — FILE HELPERS
# ============================================================================

<#
.SYNOPSIS
    Recursively finds files by pattern, with optional size and date filters.
#>
function Find-BBFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$Pattern = '*',

        [string[]]$Include,

        [string[]]$Exclude,

        [int]$MinSize,

        [int]$MaxSize,

        [datetime]$NewerThan,

        [int]$MaxDepth = 5
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-BBError "Path not found: $Path"; return
    }
    $opts = @{
        Path        = $Path
        Filter      = $Pattern
        Recurse     = $true
        ErrorAction = 'SilentlyContinue'
        File        = $true
    }
    if ($Include) { $opts.Include = $Include }
    if ($Exclude) { $opts.Exclude = $Exclude }
    $files = Get-ChildItem @opts
    if ($MinSize) { $files = $files | Where-Object { $_.Length -ge $MinSize } }
    if ($MaxSize) { $files = $files | Where-Object { $_.Length -le $MaxSize } }
    if ($NewerThan) { $files = $files | Where-Object { $_.LastWriteTime -gt $NewerThan } }
    $files | ForEach-Object { $_.FullName }
}

<#
.SYNOPSIS
    Finds files containing a specific string pattern.
#>
function Find-BBInFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [string[]]$Include = @('*.txt', '*.json', '*.xml', '*.html', '*.js', '*.ps1', '*.py', '*.conf'),

        [switch]$SimpleMatch
    )
    $files = Find-BBFile -Path $Path -Include $Include
    foreach ($f in $files) {
        try {
            $content = Get-Content -LiteralPath $f -Raw -ErrorAction Stop
            $match = if ($SimpleMatch) { $content.Contains($Pattern) } else { $content -match $Pattern }
            if ($match) { $f }
        }
        catch { continue }
    }
}

<#
.SYNOPSIS
    Reads a file and returns trimmed non-empty lines.
#>
function Get-BBFileLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$SkipBlank,

        [switch]$Trim
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-BBError "File not found: $Path"; return
    }
    $lines = Get-Content -LiteralPath $Path
    if ($SkipBlank) { $lines = $lines | Where-Object { $_.Trim() -ne '' } }
    if ($Trim) { $lines = $lines | ForEach-Object { $_.Trim() } }
    $lines
}

<#
.SYNOPSIS
    Removes duplicate lines from a file, optionally writing back.
#>
function Remove-BBFileDuplicateLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$InPlace,

        [string]$OutPath
    )
    $lines = Get-Content -LiteralPath $Path
    $unique = $lines | Select-Object -Unique
    if ($InPlace) { $unique | Set-Content -LiteralPath $Path }
    elseif ($OutPath) { $unique | Set-Content -LiteralPath $OutPath }
    [PSCustomObject]@{ Original = $lines.Count; Unique = $unique.Count; Removed = $lines.Count - $unique.Count }
}

<#
.SYNOPSIS
    Extracts files from a zip archive.
#>
function Expand-BBArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$Destination,

        [switch]$Force
    )
    if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "Archive not found: $Path"; return }
    if (-not $Destination) { $Destination = Join-Path -Path (Split-Path -Parent $Path) -ChildPath (Get-Item $Path).BaseName }
    if ($Force -and (Test-Path -LiteralPath $Destination)) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    try {
        Expand-Archive -LiteralPath $Path -DestinationPath $Destination -Force
        Write-BBInfo "Extracted to: $Destination"
        return $Destination
    }
    catch { Write-BBError "Extraction failed: $_" }
}

<#
.SYNOPSIS
    Creates a directory if it doesn't exist.
#>
function New-BBDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
        Write-BBInfo "Created directory: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

<#
.SYNOPSIS
    Cleans up temp files and empty directories.
#>
function Clear-BBTemp {
    [CmdletBinding()]
    param(
        [string]$Path = $Script:BBConfig.OutputDir,

        [switch]$Force
    )
    if (Test-Path -LiteralPath $Path) {
        $count = 0
        Get-ChildItem -LiteralPath $Path -Recurse -File | ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -Force; $count++ } catch {}
        }
        if ($Force) {
            Get-ChildItem -LiteralPath $Path -Recurse -Directory | Sort-Object FullName -Descending | ForEach-Object {
                try { if (-not (Get-ChildItem -LiteralPath $_.FullName)) { Remove-Item -LiteralPath $_.FullName -Force } } catch {}
            }
        }
        Write-BBInfo "Removed $count temp file(s) from $Path"
    }
}

<#
.SYNOPSIS
    Splits a large file into smaller chunks by line count.
#>
function Split-BBFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Lines = 1000,

        [string]$OutputPrefix
    )
    if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "File not found: $Path"; return }
    if (-not $OutputPrefix) { $OutputPrefix = "$(Get-Item $Path).BaseName-chunk" }

    $reader = [System.IO.StreamReader]::new($Path)
    $chunk = 1
    $lineCount = 0
    $writer = $null
    try {
        while ($reader.Peek() -ge 0) {
            if ($lineCount -eq 0) {
                $outPath = "$OutputPrefix-$chunk.txt"
                $writer = [System.IO.StreamWriter]::new($outPath, $false)
                $chunk++
            }
            $writer.WriteLine($reader.ReadLine())
            $lineCount++
            if ($lineCount -ge $Lines) { $writer.Close(); $lineCount = 0 }
        }
    }
    finally {
        if ($writer) { $writer.Close() }
        $reader.Close()
    }
    Write-BBInfo "Split into $($chunk-1) files"
}

# ============================================================================
# SECTION 5 — URL HELPERS
# ============================================================================

<#
.SYNOPSIS
    Parses a URL into its components.
#>
function Get-BBUrlParts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Url
    )
    process {
        try {
            $u = [System.Uri]$Url
            [PSCustomObject]@{
                Scheme         = $u.Scheme
                Host           = $u.Host
                Port           = $u.Port
                Authority      = $u.Authority
                AbsolutePath   = $u.AbsolutePath
                Query          = $u.Query
                QueryTrimmed   = $u.Query.TrimStart('?')
                Fragment       = $u.Fragment
                PathAndQuery   = $u.PathAndQuery
                AbsoluteUri    = $u.AbsoluteUri
                DnsSafeHost    = $u.DnsSafeHost
                IsDefaultPort  = $u.IsDefaultPort
            }
        }
        catch { Write-BBError "Invalid URL: $Url" }
    }
}

<#
.SYNOPSIS
    Extracts query parameters from a URL as a hashtable.
#>
function Get-BBQueryParams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Url
    )
    process {
        $result = @{}
        $qidx = $Url.IndexOf('?')
        if ($qidx -ge 0) {
            $qs = $Url.Substring($qidx + 1)
            $fidx = $qs.IndexOf('#')
            if ($fidx -ge 0) { $qs = $qs.Substring(0, $fidx) }
            foreach ($pair in ($qs -split '&')) {
                $eq = $pair.IndexOf('=')
                if ($eq -gt 0) {
                    $k = [System.Uri]::UnescapeDataString($pair.Substring(0, $eq))
                    $v = [System.Uri]::UnescapeDataString($pair.Substring($eq + 1))
                    $result[$k] = $v
                }
                elseif ($eq -eq -1 -and $pair) {
                    $result[[System.Uri]::UnescapeDataString($pair)] = ''
                }
            }
        }
        return $result
    }
}

<#
.SYNOPSIS
    Replaces or adds a query parameter value in a URL.
#>
function Set-BBQueryParam {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Value = '',

        [switch]$Encode
    )
    $parts = Get-BBUrlParts -Url $Url
    $params = Get-BBQueryParams -Url $Url
    $v = if ($Encode) { [System.Uri]::EscapeDataString($Value) } else { $Value }
    $params[$Name] = $v
    $newQuery = ($params.GetEnumerator() | ForEach-Object { "$([System.Uri]::EscapeDataString($_.Key))=$([System.Uri]::EscapeDataString($_.Value))" }) -join '&'
    $base = $parts.AbsoluteUri.Split('?')[0]
    return "$base`?$newQuery"
}

<#
.SYNOPSIS
    Removes a query parameter from a URL.
#>
function Remove-BBQueryParam {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$Name
    )
    $parts = Get-BBUrlParts -Url $Url
    $params = Get-BBQueryParams -Url $Url
    $params.Remove($Name)
    if ($params.Count -eq 0) { return $parts.AbsoluteUri.Split('?')[0] }
    $newQuery = ($params.GetEnumerator() | ForEach-Object { "$([System.Uri]::EscapeDataString($_.Key))=$([System.Uri]::EscapeDataString($_.Value))" }) -join '&'
    $base = $parts.AbsoluteUri.Split('?')[0]
    return "$base`?$newQuery"
}

<#
.SYNOPSIS
    Validates a URL string format.
#>
function Test-BBUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Url
    )
    process { [System.Uri]::IsWellFormedUriString($Url, [System.UriKind]::Absolute) }
}

<#
.SYNOPSIS
    Attempts base64 decode on a URL parameter value (common JWT/API token pattern).
#>
function ConvertFrom-BBUrlBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Value,

        [switch]$UrlSafe
    )
    process {
        try {
            $decoded = if ($UrlSafe) {
                $s = $Value -replace '-', '+' -replace '_', '/'
                $pad = 4 - ($s.Length % 4)
                if ($pad -ne 4) { $s += '=' * $pad }
                [System.Convert]::FromBase64String($s)
            }
            else {
                [System.Convert]::FromBase64String($Value)
            }
            [System.Text.Encoding]::UTF8.GetString($decoded)
        }
        catch { Write-BBWarning "Base64 decode failed: $_"; return $Value }
    }
}

<#
.SYNOPSIS
    Extracts all URLs from a string or file content using regex.
#>
function Get-BBUrlsFromText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process {
        $urlPattern = 'https?://[^\s"''<>(){}|\\^`\[\]]+'
        [regex]::Matches($Text, $urlPattern) | ForEach-Object { $_.Value.TrimEnd('/', '.', ',', ':', ';') } | Remove-BBDuplicate
    }
}

# ============================================================================
# SECTION 6 — JSON HELPERS
# ============================================================================

<#
.SYNOPSIS
    Converts JSON string to object with error handling.
#>
function ConvertFrom-BBJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Json
    )
    process {
        try {
            $Json | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-BBError "JSON parse failed: $_"
            return $null
        }
    }
}

<#
.SYNOPSIS
    Extracts a nested property from a JSON object using dot-notation path.
.PARAMETER InputObject
    JSON string or PSCustomObject.
.PARAMETER PropertyPath
    Dot-notation path (e.g. "data.users[0].name").
.EXAMPLE
    Get-BBJsonProperty -InputObject $obj -PropertyPath 'response.results[1].email'
#>
function Get-BBJsonProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyPath
    )
    process {
        if ($InputObject -is [string]) {
            try { $InputObject = $InputObject | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
        }
        $current = $InputObject
        $parts = $PropertyPath -split '\.'
        foreach ($part in $parts) {
            if ($null -eq $current) { return $null }
            if ($part -match '^(?<name>\w+)\[(?<idx>\d+)\]$') {
                $current = $current.($matches['name'])
                if ($current -is [array] -and $current.Count -gt [int]$matches['idx']) {
                    $current = $current[[int]$matches['idx']]
                }
                else { return $null }
            }
            elseif ($part -match '^(?<name>\w+)$') {
                $current = $current.($matches['name'])
            }
            else { return $null }
        }
        return $current
    }
}

<#
.SYNOPSIS
    Pretty-prints JSON with indentation.
#>
function Format-BBJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [int]$Depth = 10
    )
    process {
        if ($InputObject -is [string]) {
            try { $InputObject = $InputObject | ConvertFrom-Json -ErrorAction Stop } catch { return $InputObject }
        }
        $InputObject | ConvertTo-Json -Depth $Depth
    }
}

<#
.SYNOPSIS
    Highlights differences between two JSON objects or strings.
#>
function Compare-BBJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ReferenceObject,

        [Parameter(Mandatory)]
        [object]$DifferenceObject
    )
    if ($ReferenceObject -is [string]) { $ReferenceObject = $ReferenceObject | ConvertFrom-BBJson }
    if ($DifferenceObject -is [string]) { $DifferenceObject = $DifferenceObject | ConvertFrom-BBJson }
    if (-not $ReferenceObject -or -not $DifferenceObject) { return }

    $ref = $ReferenceObject | ConvertTo-Json -Depth 10
    $diff = $DifferenceObject | ConvertTo-Json -Depth 10
    $refLines = $ref -split "`n"
    $diffLines = $diff -split "`n"

    for ($i = 0; $i -lt [Math]::Max($refLines.Count, $diffLines.Count); $i++) {
        $r = if ($i -lt $refLines.Count) { $refLines[$i] } else { $null }
        $d = if ($i -lt $diffLines.Count) { $diffLines[$i] } else { $null }
        if ($r -ne $d) {
            [PSCustomObject]@{
                Line           = $i + 1
                ReferenceLine  = $r
                DifferenceLine = $d
            }
        }
    }
}

<#
.SYNOPSIS
    Searches JSON values for a regex pattern.
#>
function Search-BBJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Pattern
    )
    process {
        if ($InputObject -is [string]) { $InputObject = $InputObject | ConvertFrom-BBJson }
        $json = $InputObject | ConvertTo-Json -Depth 10
        $json | Select-String -Pattern $Pattern -AllMatches | ForEach-Object {
            [PSCustomObject]@{
                Line  = $_.LineNumber
                Match = $_.Matches.Value
                LineContent = $_.Line.Trim()
            }
        }
    }
}

# ============================================================================
# SECTION 7 — ENCODING HELPERS
# ============================================================================

<#
.SYNOPSIS
    Base64 encodes a string.
#>
function ConvertTo-BBBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text,

        [switch]$UrlSafe
    )
    process {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $b64 = [System.Convert]::ToBase64String($bytes)
        if ($UrlSafe) { return ($b64 -replace '\+', '-' -replace '/', '_' -replace '=', '') }
        return $b64
    }
}

<#
.SYNOPSIS
    Base64 decodes a string.
#>
function ConvertFrom-BBBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text,

        [switch]$UrlSafe
    )
    process {
        try {
            $s = if ($UrlSafe) { $Text -replace '-', '+' -replace '_', '/' } else { $Text }
            $pad = 4 - ($s.Length % 4)
            if ($pad -ne 4) { $s += '=' * $pad }
            $bytes = [System.Convert]::FromBase64String($s)
            [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        catch { Write-BBError "Base64 decode failed: $_"; return $Text }
    }
}

<#
.SYNOPSIS
    URL encodes a string.
#>
function ConvertTo-BBUrlEncode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process { [System.Uri]::EscapeDataString($Text) }
}

<#
.SYNOPSIS
    URL decodes a string.
#>
function ConvertFrom-BBUrlEncode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process { [System.Uri]::UnescapeDataString($Text) }
}

<#
.SYNOPSIS
    Converts a string to hex representation.
#>
function ConvertTo-BBHex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text,

        [switch]$AsBytes,

        [string]$Separator = ' '
    )
    process {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        if ($AsBytes) {
            ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join $Separator
        }
        else {
            '$' + (($bytes | ForEach-Object { '{0:X2}' -f $_ }) -join $Separator) + '$'
        }
    }
}

<#
.SYNOPSIS
    Converts hex string back to text.
#>
function ConvertFrom-BBHex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$HexString
    )
    process {
        try {
            $clean = $HexString -replace '[^0-9a-fA-F]', ''
            $bytes = for ($i = 0; $i -lt $clean.Length; $i += 2) {
                [Convert]::ToByte($clean.Substring($i, 2), 16)
            }
            [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        catch { Write-BBError "Hex decode failed: $_"; return $HexString }
    }
}

<#
.SYNOPSIS
    Decodes a JWT token (header + payload only, no signature verification).
#>
function ConvertFrom-BBJwt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Token
    )
    process {
        $parts = $Token -split '\.'
        if ($parts.Count -lt 2) { Write-BBError 'Not a valid JWT (need at least 2 dot-separated parts)'; return }

        $result = @{}
        $result.Header = ConvertFrom-BBBase64 -Text $parts[0] -UrlSafe | ConvertFrom-BBJson
        $result.Payload = ConvertFrom-BBBase64 -Text $parts[1] -UrlSafe | ConvertFrom-BBJson
        if ($parts.Count -ge 3) { $result.Signature = $parts[2] }
        [PSCustomObject]$result
    }
}

<#
.SYNOPSIS
    Converts string to Unicode escape sequences (\uXXXX).
#>
function ConvertTo-BBUnicodeEscape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process {
        $sb = [System.Text.StringBuilder]::new()
        foreach ($ch in $Text.ToCharArray()) {
            if ([int]$ch -gt 127) { $null = $sb.AppendFormat('\u{0:x4}', [int]$ch) }
            else { $null = $sb.Append($ch) }
        }
        $sb.ToString()
    }
}

<#
.SYNOPSIS
    Converts Unicode escape sequences back to characters.
#>
function ConvertFrom-BBUnicodeEscape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process {
        [regex]::Replace($Text, '\\u([0-9a-fA-F]{4})', {
            param($m) [char][int]('0x' + $m.Groups[1].Value)
        })
    }
}

# ============================================================================
# SECTION 8 — SYSTEM HELPERS
# ============================================================================

<#
.SYNOPSIS
    Copies text to the Windows clipboard.
#>
function Set-BBClipboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Text
    )
    process {
        try {
            $Text | Set-Clipboard
            Write-BBInfo 'Copied to clipboard'
        }
        catch { Write-BBError "Clipboard failed: $_" }
    }
}

<#
.SYNOPSIS
    Gets text from the Windows clipboard.
#>
function Get-BBClipboard {
    try { return Get-Clipboard -Raw } catch { Write-BBError "Clipboard read failed: $_" }
}

<#
.SYNOPSIS
    Computes a file hash.
#>
function Get-BBFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path,

        [ValidateSet('SHA256','MD5','SHA1','SHA384','SHA512')]
        [string]$Algorithm = 'SHA256'
    )
    process {
        if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "File not found: $Path"; return }
        try {
            $hash = Get-FileHash -LiteralPath $Path -Algorithm $Algorithm
            [PSCustomObject]@{
                Path      = $hash.Path
                Algorithm = $Algorithm
                Hash      = $hash.Hash.ToLowerInvariant()
            }
        }
        catch { Write-BBError "Hash failed: $_" }
    }
}

<#
.SYNOPSIS
    Returns a formatted timestamp string.
#>
function Get-BBTimestamp {
    [CmdletBinding()]
    param(
        [datetime]$Date = (Get-Date),

        [ValidateSet('ISO','File','Log','Short','Unix')]
        [string]$Format = 'ISO'
    )
    switch ($Format) {
        'ISO'   { return $Date.ToString('yyyy-MM-ddTHH:mm:ssK') }
        'File'  { return $Date.ToString('yyyyMMdd-HHmmss') }
        'Log'   { return $Date.ToString('yyyy-MM-dd HH:mm:ss') }
        'Short' { return $Date.ToString('yyyy-MM-dd') }
        'Unix'  { return [int][double]::Parse($(Get-Date -Date $Date -UFormat %s)) }
    }
}

<#
.SYNOPSIS
    Writes a colored message to the console.
#>
function Write-BBHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [System.ConsoleColor]$ForegroundColor = 'White',

        [System.ConsoleColor]$BackgroundColor,

        [switch]$NoNewline
    )
    $params = @{ Object = $Message; ForegroundColor = $ForegroundColor }
    if ($BackgroundColor) { $params.BackgroundColor = $BackgroundColor }
    if ($NoNewline) { $params.NoNewline = $true }
    Write-Host @params
}

<#
.SYNOPSIS
    Writes an info message (cyan).
#>
function Write-BBInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
    process { Write-BBHost -Message "[INFO] $Message" -ForegroundColor Cyan }
}

<#
.SYNOPSIS
    Writes a success message (green).
#>
function Write-BBSuccess {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
    process { Write-BBHost -Message "[+] $Message" -ForegroundColor Green }
}

<#
.SYNOPSIS
    Writes a warning message (yellow).
#>
function Write-BBWarning {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
    process { Write-BBHost -Message "[!] $Message" -ForegroundColor Yellow }
}

<#
.SYNOPSIS
    Writes an error message (red).
#>
function Write-BBError {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
    process {
        Write-BBHost -Message "[-] $Message" -ForegroundColor Red
        if ($Script:BBConfig.LogFile) { Add-BBLog -Message "ERROR: $Message" }
    }
}

<#
.SYNOPSIS
    Shows a simple text-based progress indicator on the same line.
#>
function Show-BBProgress {
    [CmdletBinding()]
    param(
        [string]$Label = 'Progress',
        [int]$Current,
        [int]$Total,
        [switch]$Complete
    )
    if ($Complete) {
        Write-Host "`r$Label: Done! $Total/$Total" -ForegroundColor Green
        return
    }
    $pct = if ($Total -gt 0) { [math]::Round($Current / $Total * 100, 1) } else { 0 }
    Write-Host "`r$Label: $Current/$Total ($pct%)" -NoNewline
}

<#
.SYNOPSIS
    Opens a file in the default editor.
#>
function Open-BBFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (Test-Path -LiteralPath $Path) { Invoke-Item -LiteralPath $Path }
    else { Write-BBError "File not found: $Path" }
}

# ============================================================================
# SECTION 9 — CRYPTO HELPERS
# ============================================================================

<#
.SYNOPSIS
    Generates a cryptographically random string.
.PARAMETER Length
    Length of the output string.
.PARAMETER Characters
    Character set to draw from. Defaults to alphanumeric + specials.
#>
function New-BBRandomString {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 1024)]
        [int]$Length = 16,

        [string]$Characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    )
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $sb = [System.Text.StringBuilder]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) {
        $null = $sb.Append($Characters[$bytes[$i] % $Characters.Length])
    }
    return $sb.ToString()
}

<#
.SYNOPSIS
    Computes HMAC-SHA256 for JWT signing tests.
.PARAMETER Message
    The message to sign.
.PARAMETER Secret
    The shared secret key.
.PARAMETER Algorithm
    Hash algorithm (SHA256, SHA384, SHA512).
#>
function Get-BBHmac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [string]$Secret,

        [ValidateSet('SHA256','SHA384','SHA512')]
        [string]$Algorithm = 'SHA256'
    )
    $algoMap = @{
        SHA256 = [System.Security.Cryptography.HMACSHA256]
        SHA384 = [System.Security.Cryptography.HMACSHA384]
        SHA512 = [System.Security.Cryptography.HMACSHA512]
    }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $msgBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    $hash = $hmac.ComputeHash($msgBytes)
    $b64 = [System.Convert]::ToBase64String($hash)
    return $b64 -replace '\+', '-' -replace '/', '_' -replace '=', ''
}

<#
.SYNOPSIS
    Compares two hash strings (case-insensitive).
#>
function Test-BBHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hash1,

        [Parameter(Mandatory)]
        [string]$Hash2
    )
    return [string]::Equals($Hash1, $Hash2, [StringComparison]::OrdinalIgnoreCase)
}

<#
.SYNOPSIS
    Generates a random UUID.
#>
function New-BBUuid {
    [System.Guid]::NewGuid().ToString()
}

# ============================================================================
# SECTION 10 — RECON HELPERS
# ============================================================================

<#
.SYNOPSIS
    Resolves a hostname to IP addresses.
.PARAMETER Name
    Hostname to resolve.
.PARAMETER Type
    Record type (A, AAAA, CNAME, MX, NS, TXT).
#>
function Resolve-BBDns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [ValidateSet('A','AAAA','CNAME','MX','NS','TXT','SOA')]
        [string]$Type = 'A'
    )
    try {
        $records = Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop
        if ($Type -in @('A','AAAA')) {
            return $records | ForEach-Object { $_.IPAddress }
        }
        elseif ($Type -eq 'MX') {
            return $records | ForEach-Object { "$($_.NameExchange) [pref $($_.Preference)]" }
        }
        elseif ($Type -eq 'TXT') {
            return $records | ForEach-Object { $_.Strings -join '' }
        }
        else {
            return $records | ForEach-Object { $_.NameHost }
        }
    }
    catch {
        Write-BBWarning "DNS resolution failed for $Name ($Type): $_"
        return $null
    }
}

<#
.SYNOPSIS
    Performs a reverse DNS lookup.
#>
function Resolve-BBReverseDns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )
    try {
        $result = Resolve-DnsName -Name $IPAddress -Type PTR -ErrorAction Stop
        return $result.NameHost
    }
    catch { return $null }
}

<#
.SYNOPSIS
    Pings a host (returns $true if reachable).
#>
function Test-BBPing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int]$Count = 2,

        [int]$Timeout = 2000
    )
    try {
        $result = Test-Connection -TargetName $Target -Count $Count -TimeoutSeconds ($Timeout / 1000) -ErrorAction Stop
        return $true
    }
    catch { return $false }
}

<#
.SYNOPSIS
    Checks if a TCP port is open on a remote host.
.PARAMETER Target
    Hostname or IP.
.PARAMETER Port
    Port number(s) to check.
.PARAMETER Timeout
    Timeout in milliseconds per port.
#>
function Test-BBPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [int[]]$Port,

        [int]$Timeout = 3000
    )
    foreach ($p in $Port) {
        try {
            $result = Test-NetConnection -ComputerName $Target -Port $p -WarningAction SilentlyContinue -ErrorAction Stop
            [PSCustomObject]@{
                Target   = $Target
                Port     = $p
                Open     = $result.TcpTestSucceeded
            }
        }
        catch {
            [PSCustomObject]@{
                Target   = $Target
                Port     = $p
                Open     = $false
                Error    = $_.Exception.Message
            }
        }
    }
}

<#
.SYNOPSIS
    Fast TCP port scanner using .NET Socket (faster than Test-NetConnection for many ports).
#>
function Invoke-BBPortScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int[]]$Ports = @(80, 443, 22, 21, 8080, 8443, 3306, 3389, 5432, 27017),

        [int]$Timeout = 1000
    )
    $openPorts = [System.Collections.ArrayList]@()
    foreach ($p in $Ports) {
        $socket = [System.Net.Sockets.TcpClient]::new()
        $async = $socket.BeginConnect($Target, $p, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($Timeout)
        if ($wait -and $socket.Connected) {
            $socket.EndConnect($async)
            $null = $openPorts.Add($p)
        }
        $socket.Close()
    }
    return $openPorts
}

<#
.SYNOPSIS
    Attempts to retrieve SSL/TLS certificate info from a host.
.PARAMETER Target
    Hostname to connect to.
.PARAMETER Port
    Port (default 443).
#>
function Get-BBCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int]$Port = 443
    )
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.Connect($Target, $Port)
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })
        $ssl.AuthenticateAsClient($Target)
        $cert = $ssl.RemoteCertificate
        $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
        $ssl.Close(); $tcp.Close()
        return [PSCustomObject]@{
            Subject        = $cert2.Subject
            Issuer         = $cert2.Issuer
            Thumbprint     = $cert2.Thumbprint
            NotBefore      = $cert2.NotBefore
            NotAfter       = $cert2.NotAfter
            SerialNumber   = $cert2.SerialNumber
            DNSNames       = ($cert2.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsFromAlternativeName, $false) -split ',\s*')
            KeyAlgorithm   = $cert2.PublicKey.Key.KeyAlgorithm
            Version        = $cert2.Version
        }
    }
    catch {
        Write-BBError "Certificate retrieval failed: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Performs a DNS zone transfer attempt (AXFR).
#>
function Request-BBAxfr {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [string]$NameServer
    )
    try {
        if (-not $NameServer) {
            $ns = Resolve-DnsName -Name $Domain -Type NS -ErrorAction Stop
            $NameServer = $ns | Select-Object -First 1 -ExpandProperty NameHost
        }
        $result = nslookup -type=any $Domain $NameServer 2>$null
        if ($LASTEXITCODE -eq 0) { return $result }
        else { Write-BBWarning "AXFR failed or not permitted for $Domain via $NameServer" }
    }
    catch { Write-BBWarning "AXFR error: $_" }
}

<#
.SYNOPSIS
    Enumerates subdomains from a wordlist file.
#>
function Invoke-BBSubdomainEnum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$Wordlist,

        [int]$Threads = 10,

        [switch]$Resolve
    )
    if (-not (Test-Path -LiteralPath $Wordlist)) { Write-BBError "Wordlist not found: $Wordlist"; return }
    $subs = Get-Content -LiteralPath $Wordlist
    $found = [System.Collections.ArrayList]@()
    $total = $subs.Count
    $count = 0

    foreach ($sub in $subs) {
        $fqdn = "$sub.$Domain"
        $count++
        Show-BBProgress -Label "Subdomains" -Current $count -Total $total
        if ($Resolve) {
            $ip = Resolve-BBDns -Name $fqdn -Type A -ErrorAction SilentlyContinue
            if ($ip) {
                $null = $found.Add([PSCustomObject]@{ Domain = $fqdn; IP = $ip })
            }
        }
        else {
            try {
                $null = [System.Net.Dns]::GetHostEntry($fqdn)
                $null = $found.Add($fqdn)
            }
            catch {}
        }
    }
    Show-BBProgress -Complete -Label "Subdomains" -Current $total -Total $total
    return $found
}

<#
.SYNOPSIS
    Retrieves HTTP response headers from a URL.
#>
function Get-BBResponseHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )
    $resp = Invoke-BBRequest -Uri $Uri -Method HEAD -Raw
    if ($resp) {
        $resp.Headers
    }
}

# ============================================================================
# SECTION 11 — WORDLIST HELPERS
# ============================================================================

<#
.SYNOPSIS
    Loads a wordlist from a file, returning unique non-empty lines.
#>
function Get-BBWordlist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$MaxLines,

        [string]$Filter
    )
    if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "Wordlist not found: $Path"; return }
    $words = Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }
    if ($Filter) { $words = $words | Where-Object { $_ -match $Filter } }
    if ($MaxLines -gt 0 -and $words.Count -gt $MaxLines) { $words = $words | Select-Object -First $MaxLines }
    $words | Select-Object -Unique
}

<#
.SYNOPSIS
    Generates a numeric wordlist (e.g., for IDOR bruteforce).
.EXAMPLE
    Get-BBNumberWordlist -Start 1000 -End 9999 -Padding 4
#>
function Get-BBNumberWordlist {
    [CmdletBinding()]
    param(
        [int]$Start = 0,
        [int]$End = 999,
        [int]$Step = 1,
        [int]$Padding
    )
    $seq = for ($i = $Start; $i -le $End; $i += $Step) {
        if ($Padding -gt 0) { $i.ToString().PadLeft($Padding, '0') }
        else { $i.ToString() }
    }
    return $seq
}

<#
.SYNOPSIS
    Generates date strings (useful for log file discovery).
.EXAMPLE
    Get-BBDateWordlist -Year 2024 -Month 1 -Day 1 -Count 365 -Format 'yyyyMMdd'
#>
function Get-BBDateWordlist {
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddYears(-1),
        [int]$Count = 365,
        [string]$Format = 'yyyy-MM-dd'
    )
    $dates = for ($i = 0; $i -lt $Count; $i++) {
        $StartDate.AddDays($i).ToString($Format)
    }
    return $dates
}

<#
.SYNOPSIS
    Attempts to find SecLists install path.
#>
function Get-BBSecListsPath {
    $common = @(
        "C:\Tools\SecLists",
        "C:\SecLists",
        "$env:USERPROFILE\Tools\SecLists",
        "$env:USERPROFILE\SecLists",
        "D:\Tools\SecLists",
        "E:\Tools\SecLists"
    )
    foreach ($p in $common) {
        if (Test-Path -LiteralPath $p) {
            $Script:BBConfig.SecListsPath = $p
            return $p
        }
    }
    Write-BBWarning 'SecLists not found at common paths. Set manually with Set-BBSecListsPath.'
    return $null
}

<#
.SYNOPSIS
    Sets the SecLists path manually.
#>
function Set-BBSecListsPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (Test-Path -LiteralPath $Path) {
        $Script:BBConfig.SecListsPath = $Path
        Write-BBSuccess "SecLists path set to $Path"
    }
    else { Write-BBError "Path not found: $Path" }
}

<#
.SYNOPSIS
    Returns a SecLists wordlist path by relative path.
#>
function Get-BBSecListFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath
    )
    if (-not $Script:BBConfig.SecListsPath) {
        $null = Get-BBSecListsPath
        if (-not $Script:BBConfig.SecListsPath) { Write-BBError 'SecLists path not configured'; return }
    }
    $full = Join-Path -Path $Script:BBConfig.SecListsPath -ChildPath $RelativePath
    if (Test-Path -LiteralPath $full) { return $full }
    Write-BBError "SecLists file not found: $full"; return
}

<#
.SYNOPSIS
    Generates a wordlist from a pattern with placeholder replacement.
#>
function Get-BBPatternWordlist {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Pattern,

        [Parameter(Mandatory)]
        [string[]]$Replacements,

        [string]$Placeholder = '{0}'
    )
    $Replacements | ForEach-Object { $Pattern -replace [regex]::Escape($Placeholder), $_ } | Select-Object -Unique
}

<#
.SYNOPSIS
    Samples N random entries from a wordlist.
#>
function Get-BBRandomWordlistSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Count = 10
    )
    $words = Get-BBWordlist -Path $Path
    if ($words.Count -le $Count) { return $words }
    $random = [System.Random]::new()
    $indices = @{}
    while ($indices.Count -lt $Count) {
        $indices[$random.Next(0, $words.Count)] = $true
    }
    return $indices.Keys | ForEach-Object { $words[$_] }
}

# ============================================================================
# SECTION 12 — OUTPUT HELPERS
# ============================================================================

<#
.SYNOPSIS
    Initializes structured logging to a file.
#>
function Start-BBLog {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) {
        $null = New-BBDirectory -Path $Script:BBConfig.OutputDir
        $Path = Join-Path -Path $Script:BBConfig.OutputDir -ChildPath "bb-session-$(Get-BBTimestamp -Format File).log"
    }
    $Script:BBConfig.LogFile = $Path
    "=== BB Session Log started $(Get-BBTimestamp -Format ISO) ===" | Out-File -LiteralPath $Path -Encoding utf8
    Write-BBSuccess "Logging to: $Path"
    return $Path
}

<#
.SYNOPSIS
    Writes a message to the log file.
#>
function Add-BBLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Message
    )
    process {
        if ($Script:BBConfig.LogFile) {
            $timestamp = Get-BBTimestamp -Format Log
            "$timestamp | $Message" | Out-File -LiteralPath $Script:BBConfig.LogFile -Encoding utf8 -Append
        }
    }
}

<#
.SYNOPSIS
    Stops structured logging and closes the log.
#>
function Stop-BBLog {
    if ($Script:BBConfig.LogFile) {
        $ts = Get-BBTimestamp -Format ISO
        "=== BB Session Log ended $ts ===" | Out-File -LiteralPath $Script:BBConfig.LogFile -Encoding utf8 -Append
        Write-BBInfo "Log saved: $($Script:BBConfig.LogFile)"
        $Script:BBConfig.LogFile = $null
    }
}

<#
.SYNOPSIS
    Exports data to CSV file.
#>
function Export-BBCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$NoTypeInformation
    )
    process {
        try {
            $dir = Split-Path -Parent $Path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-BBDirectory -Path $dir }
            $opts = @{LiteralPath = $Path; Encoding = 'utf8'; NoTypeInformation = $true}
            $InputObject | Export-Csv @opts
            Write-BBSuccess "Exported CSV: $Path ($($InputObject.Count) rows)"
        }
        catch { Write-BBError "CSV export failed: $_" }
    }
}

<#
.SYNOPSIS
    Exports data to JSON file.
#>
function Export-BBJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [int]$Depth = 10
    )
    process {
        try {
            $dir = Split-Path -Parent $Path
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-BBDirectory -Path $dir }
            $InputObject | ConvertTo-Json -Depth $Depth | Out-File -LiteralPath $Path -Encoding utf8
            Write-BBSuccess "Exported JSON: $Path"
        }
        catch { Write-BBError "JSON export failed: $_" }
    }
}

<#
.SYNOPSIS
    Creates a finding record and optionally writes it to a report file.
#>
function New-BBFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,

        [string]$Target,

        [string]$Endpoint,

        [string]$Description,

        [string]$Impact,

        [string]$PoC,

        [string]$Remediation,

        [string]$CweId,

        [string]$CvssVector,

        [string]$ReportPath
    )
    $finding = [PSCustomObject]@{
        Id          = "BB-$(Get-BBTimestamp -Format File)-$(New-BBRandomString -Length 4)"
        Title       = $Title
        Severity    = $Severity
        Target      = $Target
        Endpoint    = $Endpoint
        Description = $Description
        Impact      = $Impact
        PoC         = $PoC
        Remediation = $Remediation
        CweId       = $CweId
        CvssVector  = $CvssVector
        Timestamp   = Get-BBTimestamp -Format ISO
        Status      = 'Open'
    }
    $null = $Script:Findings.Add($finding)

    if ($ReportPath) {
        $report = @"
========================================
FINDING: $($finding.Id)
========================================
Title     : $Title
Severity  : $Severity
Target    : $Target
Endpoint  : $Endpoint
Timestamp : $($finding.Timestamp)

Description:
$Description

Impact:
$Impact

PoC:
$PoC

Remediation:
$Remediation

CWE-ID  : $CweId
CVSS    : $CvssVector
Status  : Open
========================================

"@
        $report | Out-File -LiteralPath $ReportPath -Encoding utf8 -Append
        Write-BBSuccess "Finding written to: $ReportPath"
    }

    Write-BBSuccess "Finding created: [$Severity] $Title ($($finding.Id))"
    return $finding
}

<#
.SYNOPSIS
    Exports all findings to a JSON report file.
#>
function Export-BBFindings {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) {
        $null = New-BBDirectory -Path $Script:BBConfig.OutputDir
        $Path = Join-Path -Path $Script:BBConfig.OutputDir -ChildPath "findings-$(Get-BBTimestamp -Format File).json"
    }
    $Script:Findings | Export-BBJsonFile -Path $Path
    return $Path
}

<#
.SYNOPSIS
    Prints a finding summary table to the console.
#>
function Show-BBFindings {
    $Script:Findings | Select-Object Id, Severity, Title, Target, Timestamp, Status | Format-Table -AutoSize
}

<#
.SYNOPSIS
    Formats output as a formatted table with color.
#>
function Format-BBTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,

        [string[]]$Property
    )
    process {
        if ($Property) { $InputObject | Select-Object $Property | Format-Table -AutoSize }
        else { $InputObject | Format-Table -AutoSize }
    }
}

# ============================================================================
# SECTION 13 — SESSION HELPERS
# ============================================================================

<#
.SYNOPSIS
    Saves the current session state to a JSON file.
#>
function Save-BBSession {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) {
        $null = New-BBDirectory -Path $Script:BBConfig.OutputDir
        $Path = Join-Path -Path $Script:BBConfig.OutputDir -ChildPath "session-$(Get-BBTimestamp -Format File).json"
    }
    $session = @{
        Config  = $Script:BBConfig
        History = $Script:History
        Findings = $Script:Findings
        SavedAt = Get-BBTimestamp -Format ISO
    }
    $session | Export-BBJsonFile -Path $Path
    Write-BBSuccess "Session saved: $Path"
}

<#
.SYNOPSIS
    Loads a saved session from a JSON file.
#>
function Restore-BBSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "Session file not found: $Path"; return }
    try {
        $session = Get-Content -LiteralPath $Path -Raw | ConvertFrom-BBJson
        $Script:BBConfig = $session.Config
        $Script:History = [System.Collections.ArrayList]@($session.History)
        $Script:Findings = [System.Collections.ArrayList]@($session.Findings)
        Write-BBSuccess "Session restored from: $Path"
    }
    catch { Write-BBError "Failed to restore session: $_" }
}

<#
.SYNOPSIS
    Adds an entry to the session history.
#>
function Add-BBHistory {
    [CmdletBinding()]
    param(
        [string]$Action,
        [string]$Target = '',
        [string]$Status = '',
        [string]$Notes = ''
    )
    $entry = [PSCustomObject]@{
        Timestamp = Get-BBTimestamp -Format ISO
        Action    = $Action
        Target    = $Target
        Status    = $Status
        Notes     = $Notes
    }
    $null = $Script:History.Add($entry)
    if ($Script:BBConfig.LogFile) { "$($entry.Timestamp) | $Action | $Target | $Status" | Add-BBLog }
}

<#
.SYNOPSIS
    Shows the session history.
#>
function Show-BBHistory {
    [CmdletBinding()]
    param(
        [int]$Last
    )
    $history = $Script:History
    if ($Last -gt 0 -and $history.Count -gt $Last) {
        $history = $history | Select-Object -Last $Last
    }
    $history | Select-Object Timestamp, Action, Target, Status | Format-Table -AutoSize
}

<#
.SYNOPSIS
    Reads an environment variable.
#>
function Get-BBEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Default = ''
    )
    $val = [System.Environment]::GetEnvironmentVariable($Name)
    if ($val) { return $val }
    return $Default
}

<#
.SYNOPSIS
    Sets an environment variable for the current session.
#>
function Set-BBEnv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Value
    )
    [System.Environment]::SetEnvironmentVariable($Name, $Value, [System.EnvironmentVariableTarget]::Process)
}

<#
.SYNOPSIS
    Loads configuration from a JSON config file.
.PARAMETER Path
    Path to JSON config file.
.EXAMPLE
    Import-BBConfig -Path 'C:\Tools\bb-config.json'
#>
function Import-BBConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { Write-BBError "Config not found: $Path"; return }
    try {
        $cfg = Get-Content -LiteralPath $Path -Raw | ConvertFrom-BBJson
        if ($cfg.ProxyUrl) { Set-BBProxy -Url $cfg.ProxyUrl }
        if ($cfg.UserAgent) { $Script:BBConfig.UserAgent = $cfg.UserAgent }
        if ($cfg.OutputDir) { $Script:BBConfig.OutputDir = $cfg.OutputDir }
        if ($cfg.DefaultTimeout) { $Script:BBConfig.DefaultTimeout = $cfg.DefaultTimeout }
        if ($cfg.SecListsPath) { Set-BBSecListsPath -Path $cfg.SecListsPath }
        Write-BBSuccess "Config loaded: $Path"
    }
    catch { Write-BBError "Config parse failed: $_" }
}

<#
.SYNOPSIS
    Exports the current configuration as JSON (safe — no credentials).
#>
function Export-BBConfig {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    $config = [PSCustomObject]@{
        ProxyEnabled   = $Script:BBConfig.ProxyEnabled
        ProxyUrl       = $Script:BBConfig.ProxyUrl
        UserAgent      = $Script:BBConfig.UserAgent
        OutputDir      = $Script:BBConfig.OutputDir
        DefaultTimeout = $Script:BBConfig.DefaultTimeout
        SecListsPath   = $Script:BBConfig.SecListsPath
        ExportedAt     = Get-BBTimestamp -Format ISO
    }
    if ($Path) {
        $config | Export-BBJsonFile -Path $Path
        return $Path
    }
    return $config | ConvertTo-Json -Depth 5
}

<#
.SYNOPSIS
    Resets all session state (history, findings, config).
#>
function Reset-BBSession {
    [CmdletBinding()]
    param([switch]$Force)
    if (-not $Force) {
        Write-BBWarning 'Use -Force to reset all session state'
        return
    }
    $Script:History.Clear()
    $Script:Findings.Clear()
    $Script:BBConfig.ProxyEnabled = $false
    $Script:BBConfig.ProxyUrl = $null
    $Script:BBConfig.ProxyCreds = $null
    Write-BBSuccess 'Session state reset'
}

<#
.SYNOPSIS
    Shows a summary of the current session.
#>
function Get-BBSessionSummary {
    [PSCustomObject]@{
        SessionStart  = if ($Script:History.Count -gt 0) { $Script:History[0].Timestamp } else { 'N/A' }
        Actions       = $Script:History.Count
        Findings      = $Script:Findings.Count
        ProxyEnabled  = $Script:BBConfig.ProxyEnabled
        ProxyUrl      = $Script:BBConfig.ProxyUrl
        OutputDir     = $Script:BBConfig.OutputDir
        LogFile       = $Script:BBConfig.LogFile
        SecLists      = $Script:BBConfig.SecListsPath
        UserAgent     = $Script:BBConfig.UserAgent
    } | Format-List
}

<#
.SYNOPSIS
    Returns the version info for this library.
#>
function Get-BBLibVersion {
    [PSCustomObject]@{
        Name    = 'PowerShell Bug Bounty Library'
        Version = '1.0.0'
        Author  = 'Jiggy-2026 Toolchain'
        PSVersion = $PSVersionTable.PSVersion.ToString()
        Functions = @(
                    'Set-BBProxy', 'Clear-BBProxy', 'New-BBWebSession', 'Invoke-BBRequest',
                    'Get-BBUrl', 'Send-BBPost', 'Get-BBCookies', 'Measure-BBRequest', 'Search-BBResponse',
                    'Select-BBString', 'Get-BBMatchingLines', 'Get-BBMatches', 'Remove-BBDuplicate',
                    'ConvertTo-BBRegexPattern', 'Split-BBString', 'Show-BBContext',
                    'Find-BBFile', 'Find-BBInFile', 'Get-BBFileLines', 'Remove-BBFileDuplicateLine',
                    'Expand-BBArchive', 'New-BBDirectory', 'Clear-BBTemp', 'Split-BBFile',
                    'Get-BBUrlParts', 'Get-BBQueryParams', 'Set-BBQueryParam', 'Remove-BBQueryParam',
                    'Test-BBUrl', 'ConvertFrom-BBUrlBase64', 'Get-BBUrlsFromText',
                    'ConvertFrom-BBJson', 'Get-BBJsonProperty', 'Format-BBJson', 'Compare-BBJson', 'Search-BBJson',
                    'ConvertTo-BBBase64', 'ConvertFrom-BBBase64', 'ConvertTo-BBUrlEncode', 'ConvertFrom-BBUrlEncode',
                    'ConvertTo-BBHex', 'ConvertFrom-BBHex', 'ConvertFrom-BBJwt',
                    'ConvertTo-BBUnicodeEscape', 'ConvertFrom-BBUnicodeEscape',
                    'Set-BBClipboard', 'Get-BBClipboard', 'Get-BBFileHash', 'Get-BBTimestamp',
                    'Write-BBHost', 'Write-BBInfo', 'Write-BBSuccess', 'Write-BBWarning', 'Write-BBError',
                    'Show-BBProgress', 'Open-BBFile',
                    'New-BBRandomString', 'Get-BBHmac', 'Test-BBHash', 'New-BBUuid',
                    'Resolve-BBDns', 'Resolve-BBReverseDns', 'Test-BBPing', 'Test-BBPort',
                    'Invoke-BBPortScan', 'Get-BBCertificate', 'Request-BBAxfr', 'Invoke-BBSubdomainEnum',
                    'Get-BBResponseHeaders',
                    'Get-BBWordlist', 'Get-BBNumberWordlist', 'Get-BBDateWordlist',
                    'Get-BBSecListsPath', 'Set-BBSecListsPath', 'Get-BBSecListFile',
                    'Get-BBPatternWordlist', 'Get-BBRandomWordlistSample',
                    'Start-BBLog', 'Add-BBLog', 'Stop-BBLog',
                    'Export-BBCsv', 'Export-BBJsonFile', 'New-BBFinding', 'Export-BBFindings',
                    'Show-BBFindings', 'Format-BBTable',
                    'Save-BBSession', 'Restore-BBSession', 'Add-BBHistory', 'Show-BBHistory',
                    'Get-BBEnv', 'Set-BBEnv', 'Import-BBConfig', 'Export-BBConfig',
                    'Reset-BBSession', 'Get-BBSessionSummary', 'Get-BBLibVersion'
                )
    }
}

# ============================================================================
# INIT — Auto-run on dot-source
# ============================================================================

Write-BBHost -Message "╔══════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
Write-BBHost -Message "║  PowerShell Bug Bounty Library v1.0.0              ║" -ForegroundColor DarkGray
Write-BBHost -Message "║  Loaded $(@(Get-BBLibVersion).Functions.Count) functions                   ║" -ForegroundColor DarkGray
Write-BBHost -Message "║  Run Get-BBLibVersion for details                  ║" -ForegroundColor DarkGray
Write-BBHost -Message "║  Use ONLY against authorized targets               ║" -ForegroundColor DarkGray
Write-BBHost -Message "╚══════════════════════════════════════════════════════╝" -ForegroundColor DarkGray
