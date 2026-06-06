<#
.SYNOPSIS
    curl-hunter.ps1 - curl.exe Master Toolkit for Bug Bounty Hunting on Windows

.DESCRIPTION
    A comprehensive PowerShell module wrapping curl.exe for bug bounty
    reconnaissance and vulnerability testing.  All network operations use
    curl.exe (native Windows binary) - NOT Invoke-WebRequest - so the
    wire-level behaviour matches real browser/API-client tools.

    Provides 15 functions:
      1. Invoke-CurlRequest    core curl wrapper with logging
      2. Save-CurlSession      save/load cookie jars
      3. Test-Endpoint         single-endpoint probe
      4. Test-JsonApi          JSON API helper
      5. Test-AuthBypass       auth-bypass primitives
      6. Test-ParameterFuzz    parameter fuzzing (size diffs)
      7. Test-IdorRange        sequential-ID enumeration
      8. Test-MethodBypass     HTTP-verb enumeration
      9. Test-SsrfParams       SSRF-prone parameter detection
     10. Test-Cors             CORS misconfiguration check
     11. Compare-ResponseDiff  side-by-side response diff
     12. ConvertTo-Har         convert curl output -> HAR JSON
     13. Send-BatchRequests    throttled batch sender
     14. Invoke-RateLimitTest  rate-limit stress test
     15. Invoke-CurlHunterMenu interactive menu (optional)

.PARAMETER LogDir
    Directory where per-session logs and cookie jars are stored.
    Default: "$env:TEMP\curl-hunter-logs"

.EXAMPLE
    # Dot-source the script in an existing session
    . .\curl-hunter.ps1

    Test-JsonApi -Method POST -Url "https://api.target.com/login" -Body '{"user":"test","pass":"test"}'

.NOTES
    Author    : bug-bounty toolkit
    Requires  : Windows 10+ / Windows Server 2016+, curl.exe
    Safety    : This tool sends real HTTP requests to targets.
               Only use against systems you are authorised to test.
               The author assumes no liability for misuse.

.LINK
    https://curl.se/docs/manpage.html
#>

#Requires -Version 5.1

# -- Module-level defaults ---------------------------------------------------
$Script:LogDir = "$env:TEMP\curl-hunter-logs"
if (-not (Test-Path -LiteralPath $Script:LogDir)) {
    $null = New-Item -ItemType Directory -Path $Script:LogDir -Force
}

$Script:DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# -- Helper: resolve full path to curl.exe -----------------------------------
# -- Helper: null-coalescing for PS 5.1 --------------------------------------
function Coalesce($Value, $Fallback) {
    if ($null -ne $Value) { $Value } else { $Fallback }
}

function Get-CurlPath {
    <#
    .SYNOPSIS
        Returns the full path to curl.exe.
    #>
    $exe = Get-Command curl.exe -ErrorAction Stop
    return $exe.Source
}

# -- Helper: timestamp -------------------------------------------------------
function Get-Timestamp {
    <#
    .SYNOPSIS
        Returns a timestamp string suitable for filenames.
    #>
    return Get-Date -Format "yyyyMMdd-HHmmss"
}

function Get-LogTimestamp {
    <#
    .SYNOPSIS
        Returns a human-readable log timestamp.
    #>
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
}

# -- Helper: write log entry -------------------------------------------------
function Write-CurlLog {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [string] $Level = "INFO",
        [string] $LogFile
    )
    $ts = Get-LogTimestamp
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    }
}

# -- Helper: random delay (jitter) -------------------------------------------
function Get-JitterDelay {
    param(
        [int] $BaseMs = 500,
        [int] $RangeMs = 300
    )
    $rng = [Random]::new()
    return [int]($BaseMs + $rng.Next(0, $RangeMs + 1))
}

# ===========================================================================
# FUNCTION  1 : Invoke-CurlRequest
# ===========================================================================
<#
.SYNOPSIS
    Core wrapper around curl.exe with cookie-jar, header-dump, timing, and logging.

.DESCRIPTION
    Builds and executes a curl.exe command with the supplied parameters.
    Automatically manages:
      - Cookie jar (-b / -c)
      - Response-header dump (-D)
      - Timing via -w format string
      - Verbose logging to a session log file
    Returns a hashtable with StatusCode, Headers, Body, Timing, CurlExitCode, RequestUrl.

.PARAMETER Url
    Target URL (required).

.PARAMETER Method
    HTTP method: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, etc.

.PARAMETER Headers
    Hashtable of custom headers (e.g. @{Authorization = "Bearer ..."}).

.PARAMETER Body
    Request body string (used with -d flag).

.PARAMETER ContentType
    Shorthand for Content-Type header.  Overrides Headers if both set.

.PARAMETER CookieFile
    Path to a Netscape-format cookie file to SEND (-b).

.PARAMETER CookieJar
    Path where curl WRITES new cookies (-c).

.PARAMETER Insecure
    Skip TLS certificate verification (-k).

.PARAMETER FollowRedirects
    Follow Location redirects (-L).

.PARAMETER MaxRedirects
    Maximum redirects (--max-redirs).

.PARAMETER ConnectTimeoutSec
    Connection timeout in seconds (--connect-timeout).

.PARAMETER MaxTimeSec
    Total transfer timeout in seconds (--max-time).

.PARAMETER Proxy
    Proxy URL (e.g. http://127.0.0.1:8080).

.PARAMETER OutFile
    Write response body to file (-o).

.PARAMETER DumpHeadersToFile
    Write response headers to file (-D).  Auto-generated if not provided.

.PARAMETER UserAgent
    Override the default User-Agent string.

.PARAMETER LogFile
    Path to session log file.  Auto-generated if not provided.

.PARAMETER Raw
    If set, returns the raw curl.exe output instead of the parsed hashtable.

.EXAMPLE
    Invoke-CurlRequest -Url "https://api.target.com/users/me" -Method GET -Headers @{Authorization = "Bearer eyJ..."}

.EXAMPLE
    Invoke-CurlRequest -Url "https://target.com/login" -Method POST -Body "user=admin&pass=test" -CookieJar .\cookies.txt -FollowRedirects
#>
function Invoke-CurlRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Url,

        [Parameter(Position = 1)]
        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $Body,

        [string] $ContentType,

        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string] $CookieFile,

        [string] $CookieJar,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [ValidateRange(0, 300)]
        [int] $MaxRedirects = 10,

        [ValidateRange(1, 120)]
        [int] $ConnectTimeoutSec = 15,

        [ValidateRange(1, 300)]
        [int] $MaxTimeSec = 60,

        [string] $Proxy,

        [string] $OutFile,

        [string] $DumpHeadersToFile,

        [string] $UserAgent = $Script:DefaultUserAgent,

        [string] $LogFile,

        [switch] $Raw
    )

    # -- build log file path -------------------------------------------------
    if (-not $LogFile) {
        $ts = Get-Timestamp
        $safeUrl = $Url -replace '[^a-zA-Z0-9]', '_'
        if ($safeUrl.Length -gt 60) { $safeUrl = $safeUrl.Substring(0, 60) }
        $LogFile = Join-Path -Path $Script:LogDir -ChildPath "curl_${ts}_${safeUrl}.log"
    }

    # -- default headers file ------------------------------------------------
    if (-not $DumpHeadersToFile) {
        $ts = Get-Timestamp
        $safeUrl2 = $Url -replace '[^a-zA-Z0-9]', '_'
        if ($safeUrl2.Length -gt 40) { $safeUrl2 = $safeUrl2.Substring(0, 40) }
        $DumpHeadersToFile = Join-Path -Path $Script:LogDir -ChildPath "headers_${ts}_${safeUrl2}.txt"
    }

    # -- resolve curl.exe ----------------------------------------------------
    $curl = Get-CurlPath

    # -- build argument list -------------------------------------------------
    $argsList = [System.Collections.Generic.List[string]]::new()

    # method
    if ($Method -ne "GET") {
        $argsList.Add("-X")
        $argsList.Add($Method)
    }

    # headers
    if ($ContentType) {
        $argsList.Add("-H")
        $argsList.Add("Content-Type: $ContentType")
    }
    foreach ($kv in $Headers.GetEnumerator()) {
        $argsList.Add("-H")
        $argsList.Add("$($kv.Key): $($kv.Value)")
    }

    # user-agent
    $argsList.Add("-H")
    $argsList.Add("User-Agent: $UserAgent")

    # body
    if ($Body) {
        $argsList.Add("--data")
        $argsList.Add($Body)
    }

    # cookie file (send)
    if ($CookieFile) {
        $argsList.Add("-b")
        $argsList.Add($CookieFile)
    }

    # cookie jar (write)
    if ($CookieJar) {
        $argsList.Add("-c")
        $argsList.Add($CookieJar)
    }

    # insecure
    if ($Insecure) {
        $argsList.Add("-k")
    }

    # follow redirects
    if ($FollowRedirects) {
        $argsList.Add("-L")
    }

    # max redirects
    if ($MaxRedirects -ne 10 -or $FollowRedirects) {
        $argsList.Add("--max-redirs")
        $argsList.Add([string]$MaxRedirects)
    }

    # timeouts
    $argsList.Add("--connect-timeout")
    $argsList.Add([string]$ConnectTimeoutSec)
    $argsList.Add("--max-time")
    $argsList.Add([string]$MaxTimeSec)

    # proxy
    if ($Proxy) {
        $argsList.Add("-x")
        $argsList.Add($Proxy)
    }

    # output file
    if ($OutFile) {
        $argsList.Add("-o")
        $argsList.Add($OutFile)
    }

    # dump headers
    $argsList.Add("-D")
    $argsList.Add($DumpHeadersToFile)

    # silent but show errors
    $argsList.Add("-sS")

    # include response headers in stdout (for parsing)
    $argsList.Add("-i")

    # write-out for timing
    $argsList.Add("-w")
    $argsList.Add("`n---CURL-META---`n%{http_code}|%{time_total}|%{time_connect}|%{time_starttransfer}|%{size_download}|%{size_header}|%{num_redirects}|%{url_effective}|%{content_type}")

    # the URL
    $argsList.Add($Url)

    # -- log the invocation --------------------------------------------------
    $maskedArgs = & {
        $copy = $argsList.ToArray()
        for ($i = 0; $i -lt $copy.Length; $i++) {
            if ($copy[$i] -match '(?i)(authorization|cookie|set-cookie|x-api-key|token|secret|password|apikey)') {
                $copy[$i] = "***REDACTED***"
            }
        }
        $copy -join ' '
    }

    $safeLogMsg = "curl $maskedArgs"
    Write-CurlLog -Message "Invoke-CurlRequest: $safeLogMsg" -LogFile $LogFile

    # -- execute -------------------------------------------------------------
    $start = Get-Date
    try {
        if ($Raw) {
            $output = & $curl $argsList 2>&1
            $exitCode = $LASTEXITCODE
            $elapsed = (Get-Date) - $start
            return @{
                RawOutput   = $output
                ExitCode    = $exitCode
                Elapsed     = $elapsed
                LogFile     = $LogFile
                HeadersFile = $DumpHeadersToFile
            }
        }

        $output = & $curl $argsList 2>&1
        $exitCode = $LASTEXITCODE
        $elapsed = (Get-Date) - $start
    }
    catch {
        Write-CurlLog -Message "curl.exe threw an exception: $_" -Level "ERROR" -LogFile $LogFile
        return @{
            StatusCode = $null
            Body       = $null
            Headers    = $null
            Timing     = $null
            ExitCode   = -1
            Error      = $_.ToString()
            RequestUrl = $Url
        }
    }

    # -- parse output --------------------------------------------------------
    $bodyText = ""
    $headerText = ""
    $metaLine = ""

    # split on the marker
    $marker = "---CURL-META---"
    $markerIdx = $output.IndexOf($marker)

    if ($markerIdx -ge 0) {
        $metaLine = $output.Substring($markerIdx + $marker.Length).Trim()
        $responsePart = $output.Substring(0, $markerIdx).Trim()

        # split headers from body at first blank line
        $lines = $responsePart -split "`r`n|`n"
        $inBody = $false
        $hdrLines = [System.Collections.Generic.List[string]]::new()
        $bdLines = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $lines) {
            if (-not $inBody) {
                if ($line -match '^HTTP\/') {
                    $hdrLines.Add($line)
                }
                elseif ($line -match '^[a-zA-Z][a-zA-Z0-9._-]+:' -or $line -match '^\s+' -or $line -eq '') {
                    if ($line -eq '' -and $hdrLines.Count -gt 0) {
                        $inBody = $true
                        continue
                    }
                    $hdrLines.Add($line)
                }
                else {
                    $inBody = $true
                    $bdLines.Add($line)
                }
            }
            else {
                $bdLines.Add($line)
            }
        }

        $headerText = $hdrLines -join "`r`n"
        $bodyText = $bdLines -join "`r`n"
    }
    else {
        $bodyText = $output
    }

    # -- parse timing metadata -----------------------------------------------
    $timing = @{}
    $statusCode = $null
    if ($metaLine) {
        $parts = $metaLine.Split('|')
        if ($parts.Length -ge 8) {
            $statusCode = if ($parts[0]) { [int]$parts[0] } else { $null }
            $timing = @{
                TotalSeconds       = if ($parts[1]) { [double]$parts[1] } else { 0.0 }
                ConnectSeconds     = if ($parts[2]) { [double]$parts[2] } else { 0.0 }
                StartTransferSec   = if ($parts[3]) { [double]$parts[3] } else { 0.0 }
                SizeDownloadBytes  = if ($parts[4]) { [long]$parts[4] } else { 0 }
                SizeHeaderBytes    = if ($parts[5]) { [long]$parts[5] } else { 0 }
                NumRedirects       = if ($parts[6]) { [int]$parts[6] } else { 0 }
                EffectiveUrl       = if ($parts[7]) { $parts[7] } else { $Url }
                ContentType        = if ($parts[8]) { $parts[8] } else { "" }
                WallClockSeconds   = [math]::Round($elapsed.TotalSeconds, 3)
            }
        }
    }

    # -- parse headers into hashtable ----------------------------------------
    $headersHash = @{}
    $hdrLines = $headerText -split "`r`n|`n"
    foreach ($h in $hdrLines) {
        if ($h -match '^([a-zA-Z][a-zA-Z0-9._-]+):\s*(.*)') {
            $name = $Matches[1]
            $val  = $Matches[2].Trim()
            if ($headersHash.ContainsKey($name)) {
                $existing = $headersHash[$name]
                if ($existing -is [string]) { $headersHash[$name] = @($existing, $val) }
                else { $headersHash[$name] += $val }
            }
            else {
                $headersHash[$name] = $val
            }
        }
    }

    # -- log results ---------------------------------------------------------
    Write-CurlLog -Message "HTTP $statusCode | ${elapsed}s | ${timing.SizeDownloadBytes}b | $Url" -LogFile $LogFile

    return @{
        StatusCode  = $statusCode
        Headers     = $headersHash
        HeadersRaw  = $headerText
        Body        = $bodyText
        Timing      = $timing
        ExitCode    = $exitCode
        LogFile     = $LogFile
        HeadersFile = $DumpHeadersToFile
        RequestUrl  = $Url
        Elapsed     = $elapsed
        CurlArgs    = $argsList
    }
}


# ===========================================================================
# FUNCTION  2 : Save-CurlSession
# ===========================================================================
<#
.SYNOPSIS
    Save or load curl cookie-jar / session files for multi-request workflows.

.DESCRIPTION
    Manages persistent cookie jars on disk so you can authenticate once and
    re-use the session across multiple Invoke-CurlRequest calls.

.PARAMETER Action
    "Save"   - copy current cookies to a named session file.
    "Load"   - return the path to a named session file (for use with -CookieFile).
    "List"   - show all saved sessions.
    "Remove" - delete a saved session file.

.PARAMETER Name
    Friendly session name (e.g. "target-com-auth").

.PARAMETER SourceFile
    Path to the cookie jar file to save (for Save action).

.PARAMETER SessionDir
    Directory where session files are stored.  Default: "$Script:LogDir\sessions".

.EXAMPLE
    Save-CurlSession -Action Save -Name "target-com-auth" -SourceFile .\cookies.txt
    $jar = Save-CurlSession -Action Load -Name "target-com-auth"
    Invoke-CurlRequest -Url "https://target.com/me" -CookieFile $jar
#>
function Save-CurlSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Save", "Load", "List", "Remove")]
        [string] $Action,

        [string] $Name,

        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string] $SourceFile,

        [string] $SessionDir = (Join-Path -Path $Script:LogDir -ChildPath "sessions")
    )

    # ensure session directory
    if (-not (Test-Path -LiteralPath $SessionDir)) {
        $null = New-Item -ItemType Directory -Path $SessionDir -Force
    }

    switch ($Action) {
        "Save" {
            if (-not $Name) { throw "Parameter -Name is required for Save action." }
            if (-not $SourceFile) { throw "Parameter -SourceFile is required for Save action." }
            $dest = Join-Path -Path $SessionDir -ChildPath "${Name}.cookies.txt"
            Copy-Item -LiteralPath $SourceFile -Destination $dest -Force
            Write-CurlLog -Message "Session saved: $Name -> $dest"
            return $dest
        }
        "Load" {
            if (-not $Name) { throw "Parameter -Name is required for Load action." }
            $path = Join-Path -Path $SessionDir -ChildPath "${Name}.cookies.txt"
            if (Test-Path -LiteralPath $path) {
                Write-CurlLog -Message "Session loaded: $Name <- $path"
                return $path
            }
            else {
                Write-CurlLog -Message "Session not found: $Name" -Level "WARN"
                return $null
            }
        }
        "List" {
            $files = Get-ChildItem -LiteralPath $SessionDir -Filter "*.cookies.txt" -ErrorAction SilentlyContinue
            if (-not $files) {
                Write-Host "No saved sessions found in $SessionDir" -ForegroundColor Yellow
                return @()
            }
            $result = foreach ($f in $files) {
                $size = "{0:N0} bytes" -f $f.Length
                $mod = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                [PSCustomObject]@{
                    Name       = $f.BaseName -replace '\.cookies$', ''
                    FilePath   = $f.FullName
                    Size       = $size
                    Modified   = $mod
                }
            }
            $result | Format-Table -AutoSize
            return $result
        }
        "Remove" {
            if (-not $Name) { throw "Parameter -Name is required for Remove action." }
            $path = Join-Path -Path $SessionDir -ChildPath "${Name}.cookies.txt"
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
                Write-CurlLog -Message "Session removed: $Name"
            }
            else {
                Write-CurlLog -Message "Session not found for removal: $Name" -Level "WARN"
            }
        }
    }
}


# ===========================================================================
# FUNCTION  3 : Test-Endpoint
# ===========================================================================
<#
.SYNOPSIS
    Test a single endpoint with full response capture, timing, and diagnostics.

.DESCRIPTION
    A convenience wrapper around Invoke-CurlRequest that adds:
      - A "diagnostics" section with wall-clock time and response-size summary
      - Status-bar display in the console
      - Conditional verbose output of response headers

.PARAMETER Url
    Target URL.

.PARAMETER Method
    HTTP method.  Default GET.

.PARAMETER Headers
    Hashtable of custom headers.

.PARAMETER Body
    Request body.

.PARAMETER ContentType
    Content-Type header shorthand.

.PARAMETER CookieFile
    Path to cookie file to send.

.PARAMETER CookieJar
    Path where cookies are written.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER ShowHeaders
    Display response headers in the console after the request.

.PARAMETER OutVariable
    Variable name to store the full result object.  Same as -OutVariable common
    parameter but also stored to script scope for later inspection.

.PARAMETER Raw
    Return raw curl output.

.PARAMETER Quiet
    Suppress console output except for errors.

.EXAMPLE
    Test-Endpoint -Url "https://api.target.com/health" -ShowHeaders

.EXAMPLE
    Test-Endpoint -Url "https://target.com/login" -Method POST -Body "user=admin&pass=test" -FollowRedirects -CookieJar cookies.txt
#>
function Test-Endpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $Body,

        [string] $ContentType,

        [string] $CookieFile,

        [string] $CookieJar,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [switch] $ShowHeaders,

        [string] $OutVariable,

        [switch] $Raw,

        [switch] $Quiet
    )

    if (-not $Quiet) {
        $methodColor = @{
            "GET"    = "Green"
            "POST"   = "Yellow"
            "PUT"    = "Cyan"
            "PATCH"  = "Magenta"
            "DELETE" = "Red"
            "OPTIONS" = "DarkYellow"
            "HEAD"   = "DarkGreen"
        }
        $mc = if ($methodColor.ContainsKey($Method)) { $methodColor[$Method] } else { "White" }
        Write-Host "[Test-Endpoint] " -NoNewline -ForegroundColor DarkCyan
        Write-Host "$Method " -NoNewline -ForegroundColor $mc
        Write-Host "$Url" -ForegroundColor White
    }

    $splat = @{
        Url              = $Url
        Method           = $Method
        Headers          = $Headers
        Insecure         = $Insecure
        FollowRedirects  = $FollowRedirects
        Raw              = $Raw
    }
    if ($Body) { $splat.Body = $Body }
    if ($ContentType) { $splat.ContentType = $ContentType }
    if ($CookieFile) { $splat.CookieFile = $CookieFile }
    if ($CookieJar) { $splat.CookieJar = $CookieJar }

    $result = Invoke-CurlRequest @splat

    # diagnostics
    $diag = @{}
    if ($result.Timing) {
        $t = $result.Timing
        $diag = @{
            StatusCode     = $result.StatusCode
            BodySize       = if ($null -ne $result.Body) { "{0:N0} chars" -f $result.Body.Length } else { "N/A" }
            TotalSeconds   = [math]::Round($t.TotalSeconds, 3)
            ConnectSeconds = [math]::Round($t.ConnectSeconds, 3)
            SizeBytes      = $t.SizeDownloadBytes
            EffectiveUrl   = $t.EffectiveUrl
            ContentType    = $t.ContentType
        }
    }

    if (-not $Quiet) {
        Write-Host ("  -> Status: {0}" -f (Coalesce $result.StatusCode "N/A")) -ForegroundColor $(if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 300) { "Green" } elseif ($result.StatusCode -ge 400) { "Red" } else { "Yellow" })
        Write-Host ("  -> Time:   {0}s connect, {1}s total" -f $diag.ConnectSeconds, $diag.TotalSeconds) -ForegroundColor DarkGray
        Write-Host ("  -> Size:   {0} bytes ({1})" -f $diag.SizeBytes, $diag.BodySize) -ForegroundColor DarkGray

        if ($ShowHeaders -and $result.HeadersRaw) {
            Write-Host "`n-- Response Headers --" -ForegroundColor DarkCyan
            $result.HeadersRaw | Write-Host
        }
    }

    if ($OutVariable) {
        Set-Variable -Name $OutVariable -Value $result -Scope Script
    }

    return $result
}


# ===========================================================================
# FUNCTION  4 : Test-JsonApi
# ===========================================================================
<#
.SYNOPSIS
    Send a JSON payload to an API endpoint and parse the JSON response.

.DESCRIPTION
    Automatically sets Content-Type: application/json, sends the body, and
    tries to parse the response body as JSON for structured display.

.PARAMETER Method
    HTTP method (POST, PUT, PATCH).  Default POST.

.PARAMETER Url
    Target URL.

.PARAMETER Body
    JSON string to send.  If given as a hashtable, it is converted to JSON.

.PARAMETER Headers
    Additional headers hashtable.

.PARAMETER CookieFile
    Cookie file path.

.PARAMETER CookieJar
    Cookie jar path.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER Pretty
    Pretty-print the parsed JSON response.

.PARAMETER Raw
    Return raw unparsed result.

.EXAMPLE
    Test-JsonApi -Method POST -Url "https://api.target.com/login" -Body '{"user":"admin","pass":"test"}' -Pretty

.EXAMPLE
    Test-JsonApi -Method PUT -Url "https://api.target.com/profile" -Body @{name = "test"} -CookieFile session.txt
#>
function Test-JsonApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("POST", "PUT", "PATCH", "GET", "DELETE")]
        [string] $Method = "POST",

        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [Parameter(Mandatory)]
        $Body,

        [hashtable] $Headers = @{},

        [string] $CookieFile,

        [string] $CookieJar,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [switch] $Pretty,

        [switch] $Raw
    )

    # convert hashtable body to JSON
    $jsonBody = $Body
    if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
        $jsonBody = $Body | ConvertTo-Json -Compress
    }

    Write-Host "[Test-JsonApi] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "$Method " -NoNewline -ForegroundColor Yellow
    Write-Host $Url -ForegroundColor White
    Write-Host "  JSON payload: " -NoNewline -ForegroundColor DarkGray
    Write-Host $jsonBody -ForegroundColor Gray

    $splat = @{
        Url             = $Url
        Method          = $Method
        Body            = $jsonBody
        ContentType     = "application/json"
        Headers         = $Headers
        Insecure        = $Insecure
        FollowRedirects = $FollowRedirects
    }
    if ($CookieFile) { $splat.CookieFile = $CookieFile }
    if ($CookieJar) { $splat.CookieJar = $CookieJar }

    $result = Invoke-CurlRequest @splat

    Write-Host ("  Status: {0}" -f (Coalesce $result.StatusCode "N/A")) -ForegroundColor $(if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 300) { "Green" } elseif ($result.StatusCode -ge 400) { "Red" } else { "Yellow" })
    Write-Host ("  Time:   {0}s" -f ($result.Timing.TotalSeconds)) -ForegroundColor DarkGray

    if ($result.Body -and $result.Body.Length -gt 0) {
        try {
            $parsed = $result.Body | ConvertFrom-Json -ErrorAction Stop
            if ($Pretty -and -not $Raw) {
                Write-Host "`n-- Response JSON --" -ForegroundColor DarkCyan
                $parsed | ConvertTo-Json -Depth 10 | Write-Host
            }
            if ($Raw) {
                return $result
            }
            return $parsed
        }
        catch {
            Write-Host "  (response is not JSON or is empty)" -ForegroundColor DarkGray
            if (-not $Raw) { return $result.Body }
        }
    }

    if ($Raw) { return $result }
    return $result.Body
}


# ===========================================================================
# FUNCTION  5 : Test-AuthBypass
# ===========================================================================
<#
.SYNOPSIS
    Test an endpoint for authentication bypass vulnerabilities.

.DESCRIPTION
    Sends multiple requests to the same endpoint with different auth states:
      1. No auth headers at all
      2. Empty / invalid Bearer token
      3. Modified / tampered token
      4. Different auth scheme (Basic vs Bearer)
      5. Different HTTP methods (for method-based bypass)
      6. Path traversal variant (/../admin vs /api/admin)

.PARAMETER Url
    Target endpoint URL.

.PARAMETER OriginalToken
    The valid auth token (if known) to use as a baseline.

.PARAMETER OriginalMethod
    The original HTTP method for the endpoint.  Default GET.

.PARAMETER Methods
    Array of methods to test.  Default GET, POST, PUT, PATCH, DELETE, OPTIONS.

.PARAMETER Headers
    Additional headers to include in all requests.

.PARAMETER CookieFile
    Cookie file for authenticated baseline.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER DelayMs
    Milliseconds between requests to avoid tripping rate-limiters.

.EXAMPLE
    Test-AuthBypass -Url "https://api.target.com/admin/users" -OriginalToken "eyJhbGciOiJIUzI1NiIs..." -OriginalMethod GET

.EXAMPLE
    Test-AuthBypass -Url "https://target.com/api/profile" -CookieFile .\cookies.txt -DelayMs 200
#>
function Test-AuthBypass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [string] $OriginalToken,

        [string] $OriginalMethod = "GET",

        [string[]] $Methods = @("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),

        [hashtable] $Headers = @{},

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [int] $DelayMs = 150
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $baselineCode = $null

    # -- Baseline (authenticated) -------------------------------------------
    Write-Host "`n[Test-AuthBypass] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Testing auth bypass on: $Url" -ForegroundColor White

    if ($OriginalToken -or $CookieFile) {
        Write-Host "  -- Baseline (with auth) --" -ForegroundColor DarkGray
        $authHeaders = $Headers.Clone()
        if ($OriginalToken -and -not $authHeaders.ContainsKey("Authorization")) {
            $authHeaders["Authorization"] = "Bearer $OriginalToken"
        }
        $base = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $authHeaders -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects
        $baselineCode = $base.StatusCode
        $results.Add(@{
            Label      = "Baseline (authenticated)"
            StatusCode = $base.StatusCode
            BodySize   = $base.Body.Length
            Timing     = $base.Timing.TotalSeconds
        })
        Write-Host "    Baseline: HTTP $($base.StatusCode)" -ForegroundColor Green
        Start-Sleep -Milliseconds $DelayMs
    }

    # -- 1. No auth ---------------------------------------------------------
    Write-Host "  -- 1. No auth headers --" -ForegroundColor DarkGray
    $r1 = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $Headers -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    $results.Add(@{
        Label      = "No auth"
        StatusCode = $r1.StatusCode
        BodySize   = $r1.Body.Length
        Timing     = $r1.Timing.TotalSeconds
    })
    Write-Host "    No auth:       HTTP $($r1.StatusCode)" -ForegroundColor $(if ($r1.StatusCode -ne $baselineCode -and $r1.StatusCode -lt 400) { "Red" } else { "Gray" })
    Start-Sleep -Milliseconds $DelayMs

    # -- 2. Empty Bearer ----------------------------------------------------
    $h2 = $Headers.Clone(); $h2["Authorization"] = "Bearer "
    $r2 = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $h2 -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    $results.Add(@{
        Label      = "Empty Bearer"
        StatusCode = $r2.StatusCode
        BodySize   = $r2.Body.Length
        Timing     = $r2.Timing.TotalSeconds
    })
    Write-Host "    Empty Bearer:  HTTP $($r2.StatusCode)" -ForegroundColor $(if ($r2.StatusCode -ne $baselineCode -and $r2.StatusCode -lt 400) { "Red" } else { "Gray" })
    Start-Sleep -Milliseconds $DelayMs

    # -- 3. Invalid Bearer --------------------------------------------------
    $h3 = $Headers.Clone(); $h3["Authorization"] = "Bearer INVALID_TOKEN_12345"
    $r3 = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $h3 -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    $results.Add(@{
        Label      = "Invalid Bearer"
        StatusCode = $r3.StatusCode
        BodySize   = $r3.Body.Length
        Timing     = $r3.Timing.TotalSeconds
    })
    Write-Host "    Invalid Bearer: HTTP $($r3.StatusCode)" -ForegroundColor $(if ($r3.StatusCode -ne $baselineCode -and $r3.StatusCode -lt 400) { "Red" } else { "Gray" })
    Start-Sleep -Milliseconds $DelayMs

    # -- 4. Basic auth with dummy creds ------------------------------------
    $h4 = $Headers.Clone(); $h4["Authorization"] = "Basic YWRtaW46YWRtaW4="
    $r4 = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $h4 -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    $results.Add(@{
        Label      = "Basic auth"
        StatusCode = $r4.StatusCode
        BodySize   = $r4.Body.Length
        Timing     = $r4.Timing.TotalSeconds
    })
    Write-Host "    Basic auth:    HTTP $($r4.StatusCode)" -ForegroundColor $(if ($r4.StatusCode -ne $baselineCode -and $r4.StatusCode -lt 400) { "Red" } else { "Gray" })
    Start-Sleep -Milliseconds $DelayMs

    # -- 5. X-Forwarded-For / internal header bypass ------------------------
    $h5 = $Headers.Clone()
    $h5["X-Forwarded-For"] = "127.0.0.1"
    $h5["X-Real-IP"] = "127.0.0.1"
    $h5["X-Forwarded-Host"] = "localhost"
    $r5 = Invoke-CurlRequest -Url $Url -Method $OriginalMethod -Headers $h5 -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    $results.Add(@{
        Label      = "Internal headers"
        StatusCode = $r5.StatusCode
        BodySize   = $r5.Body.Length
        Timing     = $r5.Timing.TotalSeconds
    })
    Write-Host "    Internal hdrs: HTTP $($r5.StatusCode)" -ForegroundColor $(if ($r5.StatusCode -ne $baselineCode -and $r5.StatusCode -lt 400) { "Red" } else { "Gray" })
    Start-Sleep -Milliseconds $DelayMs

    # -- 6. Method bypass --------------------------------------------------
    Write-Host "  -- 6. Method bypass tests --" -ForegroundColor DarkGray
    foreach ($m in $Methods) {
        if ($m -eq $OriginalMethod) { continue }
        $rm = Invoke-CurlRequest -Url $Url -Method $m -Headers $Headers -Insecure:$Insecure -FollowRedirects:$FollowRedirects
        $results.Add(@{
            Label      = "Method: $m"
            StatusCode = $rm.StatusCode
            BodySize   = $rm.Body.Length
            Timing     = $rm.Timing.TotalSeconds
        })
        Write-Host "    $m`: HTTP $($rm.StatusCode)" -ForegroundColor $(if ($rm.StatusCode -ne $baselineCode -and $rm.StatusCode -lt 400) { "Red" } else { "Gray" })
        Start-Sleep -Milliseconds ($DelayMs / 2)
    }

    # -- Summary table -----------------------------------------------------
    Write-Host "`n-- Auth Bypass Summary --" -ForegroundColor DarkCyan
    $summary = $results | ForEach-Object {
        [PSCustomObject]@{
            Test       = $_.Label
            StatusCode = $_.StatusCode
            BodySize   = $_.BodySize
            TimingS    = [math]::Round($_.Timing, 3)
            Interesting = if ($null -ne $baselineCode -and $_.StatusCode -ne $baselineCode -and $_.StatusCode -lt 400) { "YES" } else { "" }
        }
    }
    $summary | Format-Table -AutoSize

    return $results
}


# ===========================================================================
# FUNCTION  6 : Test-ParameterFuzz
# ===========================================================================
<#
.SYNOPSIS
    Fuzz URL parameters with a wordlist and detect response-size changes.

.DESCRIPTION
    Iterates over a wordlist, injecting each word into the specified URL
    parameter, and records status code, response size, and timing.
    Useful for detecting hidden functionality, path traversal, or SSTI.

.PARAMETER Url
    Base URL with a {fuzz} placeholder, or the parameter value to replace.
    Example: "https://target.com/file?name={fuzz}"

.PARAMETER Parameter
    If specified, the query parameter to fuzz.  The function appends
    "?Parameter=VALUE" or "&Parameter=VALUE" for each word.

.PARAMETER Wordlist
    Array of strings to inject.  If omitted, a default mini-wordlist is used.

.PARAMETER WordlistFile
    Path to a file containing one word per line.  Mutually exclusive with Wordlist.

.PARAMETER Method
    HTTP method.  Default GET.

.PARAMETER Headers
    Additional headers.

.PARAMETER CookieFile
    Cookie file path.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER DelayMs
    Delay between requests in milliseconds.

.PARAMETER BaselineSize
    Expected/known baseline response size.  Entries that differ significantly
    are highlighted.

.PARAMETER ThresholdPct
    Percentage difference threshold for flagging.  Default 20 (%).

.PARAMETER MaxWords
    Maximum number of words to test.  Useful for large wordlists.

.PARAMETER OutCsv
    Export results to CSV file.

.EXAMPLE
    Test-ParameterFuzz -Url "https://target.com/page?id={fuzz}" -Wordlist @("1","2","3","admin","true","null")
#>
function Test-ParameterFuzz {
    [CmdletBinding(DefaultParameterSetName = "Wordlist")]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [string] $Parameter,

        [Parameter(ParameterSetName = "Wordlist")]
        [string[]] $Wordlist,

        [Parameter(ParameterSetName = "WordlistFile")]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string] $WordlistFile,

        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [int] $DelayMs = 100,

        [int] $BaselineSize,

        [ValidateRange(1, 100)]
        [int] $ThresholdPct = 20,

        [ValidateRange(1, 100000)]
        [int] $MaxWords = 500,

        [string] $OutCsv
    )

    # -- resolve wordlist ----------------------------------------------------
    $words = if ($Wordlist) {
        $Wordlist
    }
    elseif ($WordlistFile) {
        Get-Content -LiteralPath $WordlistFile -Encoding UTF8 | Where-Object { $_.Trim() -ne '' }
    }
    else {
        # default mini wordlist
        @(
            "1", "0", "-1", "null", "true", "false", "undefined",
            "admin", "root", "test", "debug", "dev", "stage", "prod",
            "..", "../", "../../", "..\..\",
            "flag", "key", "token", "secret", "password", "api_key",
            "id", "user_id", "account_id", "profile_id", "document_id",
            "file", "file_name", "path", "url", "redirect", "dest",
            "order", "sort", "limit", "offset", "page", "page_size",
            "callback", "jsonp", "format", "type", "mode",
            "{{7*7}}", "{{config}}", "${7*7}", "<script>", "' OR '1'='1",
            "../../etc/passwd", "..\..\windows\win.ini",
            "http://evil.com", "https://evil.com",
            "%00", "test\n", "test\r\n", "../robots.txt",
            "*", ".*", ".json", ".xml", ".html", ".php"
        )
    }

    # trim if needed
    if ($words.Count -gt $MaxWords) {
        Write-Warning "Wordlist truncated from $($words.Count) to $MaxWords words."
        $words = $words[0..($MaxWords - 1)]
    }

    # -- prepare baseline ----------------------------------------------------
    $baselineReq = Invoke-CurlRequest -Url $Url -Method $Method -Headers $Headers -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects
    if (-not $BaselineSize) {
        $BaselineSize = $baselineReq.Body.Length
    }

    Write-Host "[Test-ParameterFuzz] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Fuzzing $($words.Count) values on: $Url" -ForegroundColor White
    Write-Host "  Baseline: HTTP $($baselineReq.StatusCode) | ${BaselineSize}b" -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $count = 0
    $interesting = 0

    foreach ($word in $words) {
        # build the fuzzed URL
        $fuzzedUrl = if ($Parameter) {
            $separator = if ($Url -match '\?') { '&' } else { '?' }
            $encodedWord = [System.Uri]::EscapeDataString($word)
            "${Url}${separator}${Parameter}=${encodedWord}"
        }
        else {
            $Url -replace '{fuzz}', $word
        }

        $r = Invoke-CurlRequest -Url $fuzzedUrl -Method $Method -Headers $Headers -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects
        $count++

        $sizeDiff = [math]::Abs(($r.Body.Length) - $BaselineSize)
        $pctDiff = if ($BaselineSize -gt 0) {
            [math]::Round(($sizeDiff / $BaselineSize) * 100, 1)
        }
        else { 0 }

        $flagged = $false
        if ($r.StatusCode -ne $baselineReq.StatusCode) { $flagged = $true }
        elseif ($pctDiff -ge $ThresholdPct) { $flagged = $true }

        if ($flagged) { $interesting++ }

        $results.Add(@{
            Word       = $word
            FuzzedUrl  = $fuzzedUrl
            StatusCode = $r.StatusCode
            BodySize   = $r.Body.Length
            PctDiff    = $pctDiff
            Timing     = [math]::Round($r.Timing.TotalSeconds, 3)
            Flagged    = $flagged
        })

        # progress indicator
        if ($count % 25 -eq 0 -or $count -eq $words.Count) {
            Write-Host ("  [{0}/{1}] interesting: {2}" -f $count, $words.Count, $interesting) -ForegroundColor DarkGray
        }

        if ($flagged) {
            $color = if ($r.StatusCode -lt 400) { "Yellow" } else { "DarkYellow" }
            Write-Host "    -> $word | HTTP $($r.StatusCode) | ${pctDiff}% diff" -ForegroundColor $color
        }

        Start-Sleep -Milliseconds $DelayMs
    }

    # -- summary -------------------------------------------------------------
    Write-Host "`n-- Parameter Fuzz Summary --" -ForegroundColor DarkCyan
    Write-Host "  Total: $count | Interesting: $interesting" -ForegroundColor $(if ($interesting -gt 0) { "Yellow" } else { "DarkGray" })

    $flaggedResults = $results | Where-Object { $_.Flagged }
    if ($flaggedResults) {
        $flaggedResults | ForEach-Object {
            [PSCustomObject]@{
                Word       = $_.Word
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                DiffPct    = $_.PctDiff
                Timing     = $_.Timing
            }
        } | Format-Table -AutoSize
    }

    if ($OutCsv) {
        $results | ForEach-Object {
            [PSCustomObject]@{
                Word       = $_.Word
                Url        = $_.FuzzedUrl
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                PctDiff    = $_.PctDiff
                Timing     = $_.Timing
                Flagged    = $_.Flagged
            }
        } | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $OutCsv" -ForegroundColor DarkGray
    }

    return $results
}


# ===========================================================================
# FUNCTION  7 : Test-IdorRange
# ===========================================================================
<#
.SYNOPSIS
    Enumerate sequential IDs on an endpoint to detect Insecure Direct Object
    Reference (IDOR) vulnerabilities.

.DESCRIPTION
    Sends requests for a range of numeric IDs (or IDs from a list) and
    identifies responses that differ from the expected 403/404 - which may
    indicate unauthorised access to another user's data.

.PARAMETER Url
    URL template with {id} placeholder.  Example: "https://target.com/api/users/{id}/profile"

.PARAMETER StartId
    Starting ID for sequential enumeration.  Default 1.

.PARAMETER EndId
    Ending ID for sequential enumeration.  Default 100.

.PARAMETER IdList
    Array of specific IDs to test instead of a range.

.PARAMETER Step
    Step between IDs.  Default 1.

.PARAMETER BaselineCode
    Expected status code for unauthorised access (e.g. 403 or 404).
    If not set, the function uses the first response as baseline.

.PARAMETER Method
    HTTP method.  Default GET.

.PARAMETER Headers
    Headers hashtable.

.PARAMETER CookieFile
    Cookie/ session file.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER DelayMs
    Delay between requests in milliseconds.

.PARAMETER StopOnData
    Stop scanning when data is found (status 200 with content).

.PARAMETER OutCsv
    Export findings to CSV.

.EXAMPLE
    Test-IdorRange -Url "https://target.com/api/invoices/{id}" -StartId 1000 -EndId 1100 -CookieFile session.txt

.EXAMPLE
    Test-IdorRange -Url "https://target.com/api/users/{id}" -IdList @(1,2,3,100,101,1000,1001,5000) -Headers @{Authorization = "Bearer eyJ..."}
#>
function Test-IdorRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [int] $StartId = 1,

        [int] $EndId = 100,

        [int[]] $IdList,

        [ValidateRange(1, 1000)]
        [int] $Step = 1,

        [int] $BaselineCode,

        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [int] $DelayMs = 200,

        [switch] $StopOnData,

        [string] $OutCsv
    )

    $ids = if ($IdList) { $IdList } else { $StartId..$EndId | Where-Object { $_ % $Step -eq 0 } }
    $total = $ids.Count

    Write-Host "[Test-IdorRange] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Enumerating $total IDs on: $Url" -ForegroundColor White

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $baselineCode = $BaselineCode
    $interesting = 0

    for ($i = 0; $i -lt $total; $i++) {
        $id = $ids[$i]
        $targetUrl = $Url -replace '{id}', $id

        $r = Invoke-CurlRequest -Url $targetUrl -Method $Method -Headers $Headers -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects

        if ($i -eq 0 -and -not $baselineCode) {
            $baselineCode = $r.StatusCode
            Write-Host "  Baseline status: HTTP $baselineCode (from ID $id)" -ForegroundColor DarkGray
        }

        $isInteresting = $false
        if ($null -ne $baselineCode -and $r.StatusCode -ne $baselineCode) {
            # 200/201 when baseline is 403/404 = potential IDOR
            if ($r.StatusCode -eq 200 -or $r.StatusCode -eq 201) {
                $isInteresting = $true
            }
            # Any 20x when baseline is 40x
            elseif ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300 -and $baselineCode -ge 400) {
                $isInteresting = $true
            }
        }

        $bodyLen = if ($r.Body) { $r.Body.Length } else { 0 }

        $results.Add(@{
            Id         = $id
            Url        = $targetUrl
            StatusCode = $r.StatusCode
            BodySize   = $bodyLen
            Timing     = [math]::Round($r.Timing.TotalSeconds, 3)
            Interesting = $isInteresting
        })

        if ($isInteresting) {
            $interesting++
            Write-Host ("  [!] ID $id -> HTTP $($r.StatusCode) | ${bodyLen}b") -ForegroundColor Red
            if ($r.Body -and $r.Body.Length -le 2000) {
                Write-Host ("      Body (truncated): " + $r.Body.Substring(0, [Math]::Min(200, $r.Body.Length))) -ForegroundColor DarkRed
            }
            if ($StopOnData) {
                Write-Host "  StopOnData set - halting." -ForegroundColor Yellow
                break
            }
        }
        else {
            if (($i + 1) % 20 -eq 0) {
                Write-Host ("  [{0}/{1}] interesting: {2}" -f ($i + 1), $total, $interesting) -ForegroundColor DarkGray
            }
        }

        Start-Sleep -Milliseconds $DelayMs
    }

    # -- summary -------------------------------------------------------------
    Write-Host "`n-- IDOR Scan Summary --" -ForegroundColor DarkCyan
    Write-Host "  Total: $total | Interesting: $interesting" -ForegroundColor $(if ($interesting -gt 0) { "Red" } else { "DarkGray" })

    $interestingResults = $results | Where-Object { $_.Interesting }
    if ($interestingResults) {
        $interestingResults | ForEach-Object {
            [PSCustomObject]@{
                ID         = $_.Id
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                Timing     = $_.Timing
                Url        = $_.Url
            }
        } | Format-Table -AutoSize
    }

    if ($OutCsv) {
        $results | ForEach-Object {
            [PSCustomObject]@{
                ID         = $_.Id
                Url        = $_.Url
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                Timing     = $_.Timing
                Interesting = $_.Interesting
            }
        } | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
    }

    return $results
}


# ===========================================================================
# FUNCTION  8 : Test-MethodBypass
# ===========================================================================
<#
.SYNOPSIS
    Test all common HTTP methods on a single endpoint looking for bypasses.

.DESCRIPTION
    Sends GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD to the same URL
    and reports which methods return unusual status codes or response sizes.

.PARAMETER Url
    Target URL.

.PARAMETER Headers
    Headers to include in all requests.

.PARAMETER Body
    Body to include in mutating requests (POST, PUT, PATCH).

.PARAMETER BodyMethod
    The content to send for methods that accept a body.
    Default: "test".

.PARAMETER CookieFile
    Cookie file path.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow Location redirects.

.PARAMETER DelayMs
    Delay between requests.

.EXAMPLE
    Test-MethodBypass -Url "https://target.com/api/admin/deleteUser" -CookieFile session.txt
#>
function Test-MethodBypass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [hashtable] $Headers = @{},

        [string] $Body = "test",

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [int] $DelayMs = 100
    )

    $allMethods = @("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
    $bodyMethods = @("POST", "PUT", "PATCH")

    Write-Host "[Test-MethodBypass] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Testing $($allMethods.Count) methods on: $Url" -ForegroundColor White

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $codes = @{}

    foreach ($m in $allMethods) {
        $splat = @{
            Url             = $Url
            Method          = $m
            Headers         = $Headers
            CookieFile      = $CookieFile
            Insecure        = $Insecure
            FollowRedirects = $FollowRedirects
        }
        if ($bodyMethods -contains $m -and $Body) {
            $splat.Body = $Body
        }

        $r = Invoke-CurlRequest @splat
        $codes[$m] = $r.StatusCode
        $bodyLen = if ($r.Body) { $r.Body.Length } else { 0 }

        $results.Add(@{
            Method     = $m
            StatusCode = $r.StatusCode
            BodySize   = $bodyLen
            Timing     = [math]::Round($r.Timing.TotalSeconds, 3)
            ContentType = if ($r.Timing) { $r.Timing.ContentType } else { "" }
        })

        Start-Sleep -Milliseconds $DelayMs
    }

    # determine "normal" code (most common)
    $commonCode = $codes.Values | Group-Object | Sort-Object Count -Descending | Select-Object -First 1 -ExpandProperty Name

    Write-Host "`n-- Method Bypass Results --" -ForegroundColor DarkCyan
    foreach ($res in $results) {
        $isBypass = ($res.StatusCode -ne $commonCode -and $null -ne $res.StatusCode -and $res.StatusCode -ge 200 -and $res.StatusCode -lt 400)
        $color = if ($isBypass) { "Red" } elseif ($res.StatusCode -ge 400) { "DarkGray" } else { "Gray" }
        $marker = if ($isBypass) { " [!]" } else { "    " }
        $parts = @($marker, $res.Method.PadRight(8), "HTTP", $res.StatusCode.ToString().PadLeft(4), "$($res.BodySize)b", "$($res.Timing)s", $res.ContentType)
        Write-Host ($parts -join " ") -ForegroundColor $color
    }

    return $results
}


# ===========================================================================
# FUNCTION  9 : Test-SsrfParams
# ===========================================================================
<#
.SYNOPSIS
    Test a URL for SSRF-prone parameters by injecting a callback URL.

.DESCRIPTION
    Scans the given URL's query string for common SSRF-prone parameter names
    (url, file, path, dest, redirect, uri, host, domain, target, endpoint,
    callback, webhook, image, src, href, folder, document, page, load, fetch)
    and sends each to a test URL (default http://BurpCollab/$PID) to detect
    server-side request forgery.

.PARAMETER Url
    Target URL containing query parameters.

.PARAMETER CallbackUrl
    Your Burp Collaborator / webhook URL.  Default: http://ssrf-test.example/callback.

.PARAMETER TestUrl
    Alternative test URL to inject (e.g. http://169.254.169.254/latest/meta-data/).

.PARAMETER Headers
    Headers to include.

.PARAMETER Method
    HTTP method.

.PARAMETER CookieFile
    Cookie file path.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER DelayMs
    Delay between requests.

.PARAMETER OutCsv
    Export results to CSV.

.EXAMPLE
    Test-SsrfParams -Url "https://target.com/proxy?url=http://example.com" -CallbackUrl "http://your.burpcollaborator.net/test"
#>
function Test-SsrfParams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [string] $CallbackUrl = "http://ssrf-test.example/callback/$(Get-Random -Maximum 99999)",

        [string] $TestUrl,

        [hashtable] $Headers = @{},

        [ValidateSet("GET", "POST")]
        [string] $Method = "GET",

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [int] $DelayMs = 200,

        [string] $OutCsv
    )

    $ssrfParams = @(
        "url", "file", "path", "dest", "redirect", "uri", "host",
        "domain", "target", "endpoint", "callback", "webhook",
        "image", "src", "href", "folder", "document", "page",
        "load", "fetch", "resource", "source", "data", "location"
    )

    $injectUrl = if ($TestUrl) { $TestUrl } else { $CallbackUrl }

    Write-Host "[Test-SsrfParams] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Scanning for SSRF parameters on: $Url" -ForegroundColor White
    Write-Host "  Injecting: $injectUrl" -ForegroundColor DarkGray

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $found = 0

    foreach ($param in $ssrfParams) {
        # Build URL - replace if parameter exists, otherwise append
        if ($Url -match "[?&]${param}=([^&]*)") {
            $fuzzedUrl = $Url -replace "([?&])${param}=[^&]*", "`$1${param}=$([System.Uri]::EscapeDataString($injectUrl))"
        }
        else {
            $separator = if ($Url -match '\?') { '&' } else { '?' }
            $fuzzedUrl = "${Url}${separator}${param}=$([System.Uri]::EscapeDataString($injectUrl))"
        }

        $r = Invoke-CurlRequest -Url $fuzzedUrl -Method $Method -Headers $Headers -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects
        $bodyLen = if ($r.Body) { $r.Body.Length } else { 0 }

        # Heuristic: status 200 with meaningful body = parameter may be processed
        $interesting = ($r.StatusCode -eq 200 -and $bodyLen -gt 0) -or
                       ($r.StatusCode -ge 300 -and $r.StatusCode -lt 400) -or
                       ($r.Body -and $r.Body -match '(?i)(error|failed|timeout|refused|could not connect)')

        if ($interesting) {
            $found++
            Write-Host ("  [!] $param -> HTTP $($r.StatusCode) | ${bodyLen}b") -ForegroundColor Yellow
        }

        $results.Add(@{
            Parameter  = $param
            StatusCode = $r.StatusCode
            BodySize   = $bodyLen
            Timing     = [math]::Round($r.Timing.TotalSeconds, 3)
            Interesting = $interesting
        })

        Start-Sleep -Milliseconds $DelayMs
    }

    Write-Host "`n-- SSRF Scan Summary --" -ForegroundColor DarkCyan
    Write-Host "  Parameters tested: $($ssrfParams.Count) | Potentially interesting: $found" -ForegroundColor $(if ($found -gt 0) { "Yellow" } else { "DarkGray" })

    $interestingRes = $results | Where-Object { $_.Interesting }
    if ($interestingRes) {
        $interestingRes | ForEach-Object {
            [PSCustomObject]@{
                Parameter  = $_.Parameter
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                Timing     = $_.Timing
            }
        } | Format-Table -AutoSize
    }

    if ($OutCsv) {
        $results | ForEach-Object {
            [PSCustomObject]@{
                Parameter  = $_.Parameter
                StatusCode = $_.StatusCode
                BodySize   = $_.BodySize
                Timing     = $_.Timing
                Interesting = $_.Interesting
            }
        } | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
    }

    return $results
}


# ===========================================================================
# FUNCTION 10 : Test-Cors
# ===========================================================================
<#
.SYNOPSIS
    Test an endpoint for CORS misconfiguration by sending various Origin
    headers and examining the Access-Control-* response headers.

.DESCRIPTION
    Sends requests with different Origin values (null, attacker domains,
    subdomain variants, preflight OPTIONS) and reports which origins are
    reflected in Access-Control-Allow-Origin or which allow credentials.

.PARAMETER Url
    Target URL.

.PARAMETER Method
    HTTP method.  Default GET.

.PARAMETER Headers
    Additional headers.

.PARAMETER CookieFile
    Cookie file.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER DelayMs
    Delay between requests.

.EXAMPLE
    Test-Cors -Url "https://api.target.com/user/profile"
#>
function Test-Cors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $CookieFile,

        [switch] $Insecure,

        [int] $DelayMs = 150
    )

    $parsed = [System.Uri]$Url
    $baseDomain = $parsed.Host

    $origins = @(
        "null",
        "https://evil.com",
        "http://evil.com",
        "https://${baseDomain}.evil.com",
        "https://evil${baseDomain}",
        "https://${baseDomain}x",
        "http://${baseDomain}",
        "https://www.${baseDomain}",
        "https://${baseDomain}.attacker.com",
        "https://sub.${baseDomain}",
        "http://localhost",
        "http://127.0.0.1",
        "file://",
        "https://evil.com/${baseDomain}"
    )

    Write-Host "[Test-Cors] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Testing $($origins.Count) origins on: $Url" -ForegroundColor White

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $vulnerable = 0

    foreach ($origin in $origins) {
        $reqHeaders = $Headers.Clone()
        $reqHeaders["Origin"] = $origin
        $reqHeaders["Access-Control-Request-Method"] = $Method

        $r = Invoke-CurlRequest -Url $Url -Method $Method -Headers $reqHeaders -CookieFile $CookieFile -Insecure:$Insecure

        $acao = $null
        $acac = $null
        $acam = $null
        $acah = $null
        $aceh = $null

        if ($r.Headers) {
            $acao = $r.Headers["Access-Control-Allow-Origin"]
            $acac = $r.Headers["Access-Control-Allow-Credentials"]
            $acam = $r.Headers["Access-Control-Allow-Methods"]
            $acah = $r.Headers["Access-Control-Allow-Headers"]
            $aceh = $r.Headers["Access-Control-Expose-Headers"]
        }

        # vulnerability checks
        $originReflected = ($acao -eq $origin -or $acao -eq "*")
        $credsAllowed = ($acac -eq "true")
        $wildcardWithCreds = ($acao -eq "*" -and $acac -eq "true")
        $nullAccepted = ($acao -eq "null")

        $isVuln = $originReflected -or $wildcardWithCreds -or $nullAccepted

        if ($isVuln) { $vulnerable++ }

        $results.Add(@{
            Origin                       = $origin
            StatusCode                   = $r.StatusCode
            ACAO                         = if ($acao) { $acao } else { "-" }
            ACAC                         = if ($acac) { $acac } else { "-" }
            ACAM                         = if ($acam) { $acam } else { "-" }
            ACAH                         = if ($acah) { $acah } else { "-" }
            OriginReflected              = $originReflected
            WildcardWithCreds            = $wildcardWithCreds
            NullAccepted                 = $nullAccepted
            Vulnerable                   = $isVuln
        })

        $color = if ($isVuln) { "Red" } else { "DarkGray" }
        Write-Host ("  {0,-45} HTTP {1,-4} ACAO: {2,-20} ACAC: {3}" -f $origin, (Coalesce $r.StatusCode "N/A"), (Coalesce $acao "-"), (Coalesce $acac "-")) -ForegroundColor $color

        Start-Sleep -Milliseconds $DelayMs
    }

    Write-Host "`n-- CORS Scan Summary --" -ForegroundColor DarkCyan
    Write-Host "  Origins tested: $($origins.Count) | Vulnerable/variant: $vulnerable" -ForegroundColor $(if ($vulnerable -gt 0) { "Red" } else { "DarkGray" })

    $vulnRes = $results | Where-Object { $_.Vulnerable }
    if ($vulnRes) {
        $vulnRes | ForEach-Object {
            [PSCustomObject]@{
                Origin    = $_.Origin
                ACAO      = $_.ACAO
                ACAC      = $_.ACAC
                VulnType  = if ($_.WildcardWithCreds) { "WILDCARD+CREDS" } elseif ($_.NullAccepted) { "NULL_ORIGIN" } else { "ORIGIN_REFLECTED" }
            }
        } | Format-Table -AutoSize
    }

    return $results
}


# ===========================================================================
# FUNCTION 11 : Compare-ResponseDiff
# ===========================================================================
<#
.SYNOPSIS
    Compare two API responses and highlight differences in status, size,
    timing, headers, and body content.

.DESCRIPTION
    Takes two response hashtables (as returned by Invoke-CurlRequest or
    Test-Endpoint) and produces a structured diff report.  Useful for
    A/B testing (authenticated vs unauthenticated, different parameters).

.PARAMETER ResponseA
    First response object (hashtable from Invoke-CurlRequest).

.PARAMETER ResponseB
    Second response object.

.PARAMETER LabelA
    Display label for Response A.  Default "A".

.PARAMETER LabelB
    Display label for Response B.  Default "B".

.PARAMETER ShowBodyDiff
    If set, also diff the body content line by line (only for short bodies).

.PARAMETER MaxBodyLines
    Maximum number of body lines to compare.  Default 100.

.EXAMPLE
    $r1 = Test-Endpoint -Url "https://target.com/api/me" -Headers @{Authorization = "Bearer TOKEN_A"}
    $r2 = Test-Endpoint -Url "https://target.com/api/me" -Headers @{Authorization = "Bearer TOKEN_B"}
    Compare-ResponseDiff -ResponseA $r1 -ResponseB $r2 -LabelA "User A" -LabelB "User B"
#>
function Compare-ResponseDiff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable] $ResponseA,

        [Parameter(Mandatory, Position = 1)]
        [hashtable] $ResponseB,

        [string] $LabelA = "A",

        [string] $LabelB = "B",

        [switch] $ShowBodyDiff,

        [ValidateRange(1, 1000)]
        [int] $MaxBodyLines = 100
    )

    Write-Host "-- Response Diff: $LabelA vs $LabelB --" -ForegroundColor DarkCyan

    # -- Status Code --------------------------------------------------------
    $scA = $ResponseA.StatusCode
    $scB = $ResponseB.StatusCode
    $scMatch = $scA -eq $scB
    Write-Host ("  Status:  {0,-8} {1}  |  {2,-8} {3}" -f $LabelA, (Coalesce $scA "N/A"), $LabelB, (Coalesce $scB "N/A")) -ForegroundColor $(if ($scMatch) { "Gray" } else { "Yellow" })
    if (-not $scMatch) {
        Write-Host "           [!] Status differs!" -ForegroundColor Yellow
    }

    # -- Body Size ----------------------------------------------------------
    $sizeA = if ($ResponseA.Body) { $ResponseA.Body.Length } else { 0 }
    $sizeB = if ($ResponseB.Body) { $ResponseB.Body.Length } else { 0 }
    $sizeDiff = $sizeA - $sizeB
    $sizeMatch = $sizeA -eq $sizeB
    Write-Host ("  Body:    {0,-8} {1,7}b | {2,-8} {3,7}b  ({4:+0;-0;0} diff)" -f $LabelA, $sizeA, $labelB, $sizeB, $sizeDiff) -ForegroundColor $(if ($sizeMatch) { "Gray" } else { "Yellow" })

    # -- Timing -------------------------------------------------------------
    $tA = if ($ResponseA.Timing) { $ResponseA.Timing.TotalSeconds } else { 0 }
    $tB = if ($ResponseB.Timing) { $ResponseB.Timing.TotalSeconds } else { 0 }
    $tDiff = $tA - $tB
    Write-Host ("  Timing:  {0,-8} {1,5}s  | {2,-8} {3,5}s  ({4:+0.000;-0.000;0} diff)" -f $LabelA, [math]::Round($tA, 3), $LabelB, [math]::Round($tB, 3), [math]::Round($tDiff, 3)) -ForegroundColor DarkGray

    # -- Headers Diff -------------------------------------------------------
    $hA = if ($ResponseA.Headers) { $ResponseA.Headers } else { @{} }
    $hB = if ($ResponseB.Headers) { $ResponseB.Headers } else { @{} }
    $allKeys = $hA.Keys + $hB.Keys | Select-Object -Unique | Sort-Object

    Write-Host "`n  -- Headers --" -ForegroundColor DarkGray
    $headerDiffs = 0
    foreach ($k in $allKeys) {
        $vA = if ($hA.ContainsKey($k)) { $hA[$k] } else { $null }
        $vB = if ($hB.ContainsKey($k)) { $hB[$k] } else { $null }
        $vAStr = if ($vA -is [array]) { $vA -join ', ' } else { $vA }
        $vBStr = if ($vB -is [array]) { $vB -join ', ' } else { $vB }
        if ($vAStr -ne $vBStr) {
            Write-Host ("  [!] {0}:" -f $k) -ForegroundColor Yellow
            Write-Host ("        {0}: {1}" -f $LabelA, $vAStr) -ForegroundColor Gray
            Write-Host ("        {0}: {1}" -f $LabelB, $vBStr) -ForegroundColor Gray
            $headerDiffs++
        }
    }
    if ($headerDiffs -eq 0) {
        Write-Host "      All headers identical" -ForegroundColor DarkGray
    }

    # -- Body Diff ----------------------------------------------------------
    if ($ShowBodyDiff -and $sizeA -lt 10000 -and $sizeB -lt 10000) {
        Write-Host "`n  -- Body Content Diff --" -ForegroundColor DarkGray
        $linesA = ($ResponseA.Body -split "`r`n|`n")[0..([Math]::Min($MaxBodyLines - 1, $sizeA))]
        $linesB = ($ResponseB.Body -split "`r`n|`n")[0..([Math]::Min($MaxBodyLines - 1, $sizeB))]
        $maxLine = [Math]::Max($linesA.Count, $linesB.Count)

        for ($i = 0; $i -lt $maxLine; $i++) {
            $lA = if ($i -lt $linesA.Count) { $linesA[$i] } else { $null }
            $lB = if ($i -lt $linesB.Count) { $linesB[$i] } else { $null }
            if ($lA -ne $lB) {
                Write-Host ("  L{0,4} {1,-8}: {2}" -f $i, $LabelA, (Coalesce $lA "(missing)")) -ForegroundColor Gray
                Write-Host ("  L{0,4} {1,-8}: {2}" -f $i, $LabelB, (Coalesce $lB "(missing)")) -ForegroundColor Gray
                Write-Host ("  " + ("-" * 60)) -ForegroundColor DarkGray
            }
        }
    }

    return @{
        StatusMatch  = $scMatch
        SizeDiff     = $sizeDiff
        TimeDiff     = [math]::Round($tDiff, 3)
        HeaderDiffs  = $headerDiffs
    }
}


# ===========================================================================
# FUNCTION 12 : ConvertTo-Har
# ===========================================================================
<#
.SYNOPSIS
    Convert a curl response object into a HAR (HTTP Archive) JSON structure.

.DESCRIPTION
    Takes a hashtable returned by Invoke-CurlRequest and builds a valid HAR
    JSON object suitable for attaching to bug-bounty reports or importing
    into browser devtools.

.PARAMETER Response
    Response object from Invoke-CurlRequest.

.PARAMETER RequestUrl
    Override request URL (if not embedded in response).

.PARAMETER RequestMethod
    Override request method.

.PARAMETER RequestHeaders
    Hashtable of request headers sent.

.PARAMETER RequestBody
    Request body sent (if any).

.PARAMETER OutFile
    Write HAR JSON to a file.

.EXAMPLE
    $r = Invoke-CurlRequest -Url "https://target.com/api/data"
    ConvertTo-Har -Response $r -OutFile .\report.har
#>
function ConvertTo-Har {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [hashtable] $Response,

        [string] $RequestUrl,

        [string] $RequestMethod = "GET",

        [hashtable] $RequestHeaders = @{},

        [string] $RequestBody,

        [string] $OutFile
    )

    $url = if ($RequestUrl) { $RequestUrl } else { $Response.RequestUrl }
    $method = if ($Response.CurlArgs -and $Response.CurlArgs -contains "-X") {
        $idx = [array]::IndexOf($Response.CurlArgs, "-X")
        if ($idx -ge 0 -and $idx -lt $Response.CurlArgs.Count - 1) { $Response.CurlArgs[$idx + 1] } else { $RequestMethod }
    }
    else { $RequestMethod }

    $statusCode = Coalesce $Response.StatusCode 0
    $bodyText = Coalesce $Response.Body ""
    $headersRaw = Coalesce $Response.HeadersRaw ""

    $now = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $timeTotal = if ($Response.Timing) { [math]::Round($Response.Timing.TotalSeconds * 1000) } else { 0 }
    $timeConnect = if ($Response.Timing) { [math]::Round($Response.Timing.ConnectSeconds * 1000) } else { 0 }
    $timeSend = [math]::Max(1, [math]::Round($timeConnect * 0.3))
    $timeWait = if ($Response.Timing) { [math]::Max(1, [math]::Round(($timeTotal - $timeConnect) * 0.7)) } else { 10 }
    $timeReceive = [math]::Max(1, $timeTotal - $timeSend - $timeWait)

    $bodySize = if ($bodyText) { [System.Text.Encoding]::UTF8.GetByteCount($bodyText) } else { 0 }

    # parse request headers from curl args
    $reqHeadersArr = @()
    if ($Response.CurlArgs) {
        $args = $Response.CurlArgs
        for ($i = 0; $i -lt $args.Count; $i++) {
            if ($args[$i] -eq "-H" -and $i + 1 -lt $args.Count) {
                $hdrStr = $args[$i + 1]
                if ($hdrStr -match '^([^:]+):\s*(.*)') {
                    $reqHeadersArr += @{ name = $Matches[1]; value = $Matches[2] }
                }
            }
        }
    }
    foreach ($kv in $RequestHeaders.GetEnumerator()) {
        $reqHeadersArr += @{ name = $kv.Key; value = $kv.Value }
    }

    # parse response headers
    $resHeadersArr = @()
    $hdrLines = $headersRaw -split "`r`n|`n"
    foreach ($h in $hdrLines) {
        if ($h -match '^([a-zA-Z][a-zA-Z0-9._-]+):\s*(.*)') {
            $resHeadersArr += @{ name = $Matches[1]; value = $Matches[2].Trim() }
        }
    }

    # build HAR
    $har = @{
        log = @{
            version = "1.2"
            creator = @{ name = "curl-hunter.ps1"; version = "1.0" }
            entries = @(
                @{
                    startedDateTime = $now
                    time = $timeTotal
                    request = @{
                        method = $method
                        url = $url
                        httpVersion = "HTTP/1.1"
                        headers = $reqHeadersArr
                        queryString = @()
                        cookies = @()
                        headersSize = -1
                        bodySize = if ($RequestBody) { [System.Text.Encoding]::UTF8.GetByteCount($RequestBody) } else { -1 }
                        postData = if ($RequestBody) {
                            @{ mimeType = "application/x-www-form-urlencoded"; text = $RequestBody }
                        } else { $null }
                    }
                    response = @{
                        status = $statusCode
                        statusText = if ($statusCode -eq 200) { "OK" } elseif ($statusCode -eq 201) { "Created" } elseif ($statusCode -eq 204) { "No Content" } elseif ($statusCode -eq 301) { "Moved Permanently" } elseif ($statusCode -eq 302) { "Found" } elseif ($statusCode -eq 304) { "Not Modified" } elseif ($statusCode -eq 400) { "Bad Request" } elseif ($statusCode -eq 401) { "Unauthorized" } elseif ($statusCode -eq 403) { "Forbidden" } elseif ($statusCode -eq 404) { "Not Found" } elseif ($statusCode -eq 405) { "Method Not Allowed" } elseif ($statusCode -eq 500) { "Internal Server Error" } elseif ($statusCode -eq 502) { "Bad Gateway" } elseif ($statusCode -eq 503) { "Service Unavailable" } else { "" }
                        httpVersion = "HTTP/1.1"
                        headers = $resHeadersArr
                        cookies = @()
                        content = @{
                            size = $bodySize
                            mimeType = if ($Response.Timing -and $Response.Timing.ContentType) { $Response.Timing.ContentType } else { "application/octet-stream" }
                            text = if ($bodyText) { $bodyText } else { "" }
                        }
                        redirectURL = ""
                        headersSize = -1
                        bodySize = $bodySize
                    }
                    cache = @{}
                    timings = @{
                        send = $timeSend
                        wait = $timeWait
                        receive = $timeReceive
                        connect = $timeConnect
                        ssl = [math]::Max(1, [math]::Round($timeConnect * 0.6))
                    }
                    _curlExitCode = $Response.ExitCode
                }
            )
        }
    }

    $json = $har | ConvertTo-Json -Depth 10

    if ($OutFile) {
        $json | Out-File -LiteralPath $OutFile -Encoding UTF8
        Write-Host "HAR written to: $OutFile" -ForegroundColor Green
    }

    return $json
}


# ===========================================================================
# FUNCTION 13 : Send-BatchRequests
# ===========================================================================
<#
.SYNOPSIS
    Send multiple requests sequentially with configurable delay between them.

.DESCRIPTION
    Takes an array of request definitions (hashtables with Url, Method,
    Headers, Body, etc.) and sends each one in order with jittered delays.
    Useful for multi-step workflows and chained testing.

.PARAMETER Requests
    Array of hashtables.  Each hashtable supports:
        Url         (required)
        Method      (default GET)
        Headers     (hashtable)
        Body        (string)
        ContentType (string)
        Label       (string for logging)

.PARAMETER DelayMs
    Base delay between requests in ms.  Default 300.  Jitter of ±150 added.

.PARAMETER StopOnError
    Stop the batch if any request returns status >= 500.

.PARAMETER LogFile
    Path to log file for batch output.

.PARAMETER OutResults
    Variable to store all results (scoped to caller).

.EXAMPLE
    $reqs = @(
        @{Url = "https://target.com/login"; Method = "POST"; Body = "user=admin&pass=test"; Label = "Login"},
        @{Url = "https://target.com/profile"; Method = "GET"; Label = "Profile"},
        @{Url = "https://target.com/logout"; Method = "POST"; Label = "Logout"}
    )
    Send-BatchRequests -Requests $reqs -DelayMs 500
#>
function Send-BatchRequests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ $_.Count -gt 0 })]
        [hashtable[]] $Requests,

        [int] $DelayMs = 300,

        [switch] $StopOnError,

        [string] $LogFile,

        [string] $OutResults
    )

    $count = $Requests.Count
    Write-Host "[Send-BatchRequests] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Sending $count requests in sequence" -ForegroundColor White

    $results = [System.Collections.Generic.List[hashtable]]::new()

    for ($i = 0; $i -lt $count; $i++) {
        $req = $Requests[$i]
        $label = if ($req.Label) { $req.Label } else { "Request #$($i + 1)" }
        $url = $req.Url
        $method = if ($req.Method) { $req.Method } else { "GET" }
        $headers = if ($req.Headers) { $req.Headers } else { @{} }
        $body = $req.Body
        $contentType = $req.ContentType

        Write-Host ("  [{0}/{1}] {2}: {3} {4}" -f ($i + 1), $count, $label, $method, $url) -ForegroundColor DarkGray

        $splat = @{
            Url     = $url
            Method  = $method
            Headers = $headers
            LogFile = $LogFile
        }
        if ($body) { $splat.Body = $body }
        if ($contentType) { $splat.ContentType = $contentType }
        if ($req.CookieFile) { $splat.CookieFile = $req.CookieFile }
        if ($req.CookieJar) { $splat.CookieJar = $req.CookieJar }
        if ($req.Insecure) { $splat.Insecure = $true }

        $r = Invoke-CurlRequest @splat
        $results.Add($r)

        $color = if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) { "Green" } elseif ($r.StatusCode -ge 400) { "Red" } else { "Yellow" }
        Write-Host ("    -> HTTP {0} | {1}s" -f (Coalesce $r.StatusCode "N/A"), [math]::Round($r.Timing.TotalSeconds, 3)) -ForegroundColor $color

        if ($StopOnError -and $r.StatusCode -ge 500) {
            Write-Warning "Stopping batch due to HTTP $($r.StatusCode) on $label"
            break
        }

        # jittered delay (skip on last)
        if ($i -lt $count - 1) {
            $jitter = Get-JitterDelay -BaseMs $DelayMs
            Start-Sleep -Milliseconds $jitter
        }
    }

    # summary
    $success = ($results | Where-Object { $_.StatusCode -ge 200 -and $_.StatusCode -lt 300 }).Count
    $errors = ($results | Where-Object { $_.StatusCode -ge 400 }).Count
    Write-Host "  Done: $success OK, $errors errors" -ForegroundColor $(if ($errors -eq 0) { "Green" } else { "Red" })

    if ($OutResults) {
        Set-Variable -Name $OutResults -Value $results -Scope "Script"
    }

    return $results
}


# ===========================================================================
# FUNCTION 14 : Invoke-RateLimitTest
# ===========================================================================
<#
.SYNOPSIS
    Test an endpoint for rate-limiting by sending rapid consecutive requests.

.DESCRIPTION
    Sends N requests in quick succession (configurable concurrency / delay)
    and reports when the endpoint starts returning 429 (Too Many Requests),
    403, connection resets, or other rate-limit signals.

.PARAMETER Url
    Target URL.

.PARAMETER Method
    HTTP method.  Default GET.

.PARAMETER Headers
    Headers to include.

.PARAMETER Body
    Request body (for POST / PUT).

.PARAMETER CookieFile
    Cookie file.

.PARAMETER Insecure
    Skip TLS verification.

.PARAMETER FollowRedirects
    Follow redirects.

.PARAMETER TotalRequests
    Total number of requests to send.  Default 50.

.PARAMETER Concurrency
    Number of parallel requests.  Default 1 (sequential).
    Uses PowerShell jobs for concurrency > 1.

.PARAMETER DelayMs
    Delay between requests (sequential mode) or between batches (concurrent).
    Default 50.

.PARAMETER StopOnLimit
    Stop testing as soon as a rate-limit signal is detected.

.PARAMETER ExpectedLimitCode
    Expected rate-limit status code.  Default 429.  Also checks 403, 503.

.PARAMETER OutCsv
    Export timing data to CSV.

.PARAMETER Quiet
    Suppress per-request output.

.EXAMPLE
    Invoke-RateLimitTest -Url "https://api.target.com/login" -Method POST -Body "user=admin&pass=test" -TotalRequests 100 -DelayMs 20
#>
function Invoke-RateLimitTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Url,

        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]
        [string] $Method = "GET",

        [hashtable] $Headers = @{},

        [string] $Body,

        [string] $CookieFile,

        [switch] $Insecure,

        [switch] $FollowRedirects,

        [ValidateRange(1, 10000)]
        [int] $TotalRequests = 50,

        [ValidateRange(1, 20)]
        [int] $Concurrency = 1,

        [int] $DelayMs = 50,

        [switch] $StopOnLimit,

        [ValidateSet(429, 403, 503)]
        [int] $ExpectedLimitCode = 429,

        [string] $OutCsv,

        [switch] $Quiet
    )

    Write-Host "[Invoke-RateLimitTest] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "Sending $TotalRequests requests ($Concurrency concurrent) to: $Url" -ForegroundColor White

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $rateLimited = $false
    $limitThreshold = 0
    $normalCodes = @{}

    $remaining = $TotalRequests
    $batchSize = if ($Concurrency -gt 1) { $Concurrency } else { 1 }
    $batchIndex = 0

    while ($remaining -gt 0 -and -not $rateLimited) {
        $currentBatch = [Math]::Min($batchSize, $remaining)

        if ($Concurrency -le 1) {
            # sequential
            for ($j = 0; $j -lt $currentBatch; $j++) {
                $r = Invoke-CurlRequest -Url $Url -Method $Method -Headers $Headers -Body $Body -CookieFile $CookieFile -Insecure:$Insecure -FollowRedirects:$FollowRedirects
                Process-RateResult -Result $r -Index ($TotalRequests - $remaining + $j) -Quiet:$Quiet

                if ($StopOnLimit -and $rateLimited) { break }
                if ($j -lt $currentBatch - 1) { Start-Sleep -Milliseconds $DelayMs }
            }
        }
        else {
            # concurrent via PowerShell jobs
            $jobs = @()
            $jobIndexStart = $TotalRequests - $remaining
            for ($j = 0; $j -lt $currentBatch; $j++) {
                $jobIdx = $jobIndexStart + $j
                $jobSplat = @{
                    Url             = $Url
                    Method          = $Method
                    Headers         = $Headers
                    Body            = $Body
                    CookieFile      = $CookieFile
                    Insecure        = $Insecure
                    FollowRedirects = $FollowRedirects
                }
                $jobs += Start-Job -ScriptBlock {
                    param($u, $m, $h, $b, $cf, $ik, $fr)
                    # We use a simplified inline curl call to avoid module-scope issues
                    $curl = "curl.exe"
                    $argsList = [System.Collections.Generic.List[string]]::new()
                    $argsList.Add("-sS")
                    $argsList.Add("-i")
                    $argsList.Add("-X"); $argsList.Add($m)
                    foreach ($kv in $h.GetEnumerator()) { $argsList.Add("-H"); $argsList.Add("$($kv.Key): $($kv.Value)") }
                    $argsList.Add("--connect-timeout"); $argsList.Add("10")
                    $argsList.Add("--max-time"); $argsList.Add("30")
                    if ($b) { $argsList.Add("--data"); $argsList.Add($b) }
                    if ($cf) { $argsList.Add("-b"); $argsList.Add($cf) }
                    if ($ik) { $argsList.Add("-k") }
                    if ($fr) { $argsList.Add("-L") }
                    $argsList.Add("-w"); $argsList.Add("`n---CURL-META---`n%{http_code}|%{time_total}|%{size_download}")
                    $argsList.Add($u)

                    $output = & $curl $argsList 2>&1
                    $exitCode = $LASTEXITCODE
                    $sc = $null
                    $time = 0.0
                    $size = 0
                    $fullOut = $output -join "`n"

                    if ($fullOut -match '---CURL-META---\s*(\d+)\|([\d.]+)\|(\d+)') {
                        $sc = [int]$Matches[1]
                        $time = [double]$Matches[2]
                        $size = [long]$Matches[3]
                    }

                    return @{ StatusCode = $sc; Timing = $time; Size = $size; Index = $jobIdx; ExitCode = $exitCode }
                } -ArgumentList $Url, $Method, $Headers, $Body, $CookieFile, $Insecure.IsPresent, $FollowRedirects.IsPresent
            }

            # wait all jobs
            $null = Wait-Job -Job $jobs -Timeout 60
            foreach ($jb in $jobs) {
                $data = Receive-Job -Job $jb
                Remove-Job -Job $jb -Force
                if ($data) {
                    $result = @{
                        StatusCode = $data.StatusCode
                        Timing     = @{ TotalSeconds = $data.Timing; SizeDownloadBytes = $data.Size }
                        Body       = $null
                        ExitCode   = $data.ExitCode
                        RequestUrl = $Url
                    }
                    $results.Add($result)
                    $idx = $data.Index
                    $sc = $data.StatusCode
                    $tl = $data.Timing
                    $sz = $data.Size

                    if (-not $Quiet) {
                        Write-Host ("  [{0,4}] HTTP {1,-4} | {2,6}s | {3,7}b" -f $idx, (Coalesce $sc "N/A"), [math]::Round($tl, 3), $sz) -ForegroundColor $(if ($sc -eq 429 -or $sc -eq 503) { "Red" } elseif ($sc -ge 400) { "Yellow" } else { "Gray" })
                    }

                    if ($sc -eq $ExpectedLimitCode -or $sc -eq 503) {
                        $rateLimited = $true
                        if (-not $normalCodes.ContainsKey($sc)) { $normalCodes[$sc] = 0 }
                        $normalCodes[$sc]++
                        $limitThreshold = $idx
                    }
                    elseif ($null -ne $sc) {
                        if (-not $normalCodes.ContainsKey($sc)) { $normalCodes[$sc] = 0 }
                        $normalCodes[$sc]++
                    }
                }
            }
            $remaining -= $currentBatch
            if ($rateLimited -and $StopOnLimit) { break }
            if ($remaining -gt 0) { Start-Sleep -Milliseconds $DelayMs }
            continue
        }

        $remaining -= $currentBatch
        $batchIndex++
    }

    # Helper function used in sequential loop
    function Process-RateResult {
        param($Result, $Index, [switch]$Quiet)
        $script:results.Add($Result)
        $sc = $Result.StatusCode
        $tl = if ($Result.Timing) { $Result.Timing.TotalSeconds } else { 0 }
        $sz = if ($Result.Timing) { $Result.Timing.SizeDownloadBytes } else { 0 }

        if (-not $Quiet) {
            Write-Host ("  [{0,4}] HTTP {1,-4} | {2,6}s | {3,7}b" -f $Index, (Coalesce $sc "N/A"), [math]::Round($tl, 3), $sz) -ForegroundColor $(if ($sc -eq $ExpectedLimitCode -or $sc -eq 503) { "Red" } elseif ($sc -ge 400) { "Yellow" } else { "Gray" })
        }

        if ($sc -eq $ExpectedLimitCode -or $sc -eq 503) {
            $script:rateLimited = $true
            if (-not $script:normalCodes.ContainsKey($sc)) { $script:normalCodes[$sc] = 0 }
            $script:normalCodes[$sc]++
            $script:limitThreshold = $Index
        }
        elseif ($null -ne $sc) {
            if (-not $script:normalCodes.ContainsKey($sc)) { $script:normalCodes[$sc] = 0 }
            $script:normalCodes[$sc]++
        }
    }

    # final summary
    Write-Host "`n-- Rate-Limit Test Summary --" -ForegroundColor DarkCyan
    Write-Host "  Total sent: $TotalRequests" -ForegroundColor DarkGray
    Write-Host "  Rate-limited detected: $(if ($rateLimited) { "YES at request #$limitThreshold" } else { "NO" })" -ForegroundColor $(if ($rateLimited) { "Red" } else { "Green" })

    $codeSummary = $normalCodes.GetEnumerator() | Sort-Object Name
    foreach ($entry in $codeSummary) {
        Write-Host "    HTTP $($entry.Key): $($entry.Value) times" -ForegroundColor Gray
    }
    Write-Host "  Responses: $($results.Count)" -ForegroundColor DarkGray

    if ($OutCsv) {
        $results | ForEach-Object {
            $idx = [array]::IndexOf($results, $_)
            [PSCustomObject]@{
                Index      = $idx
                StatusCode = $_.StatusCode
                Timing     = if ($_.Timing) { [math]::Round($_.Timing.TotalSeconds, 3) } else { 0 }
                Size       = if ($_.Timing) { $_.Timing.SizeDownloadBytes } else { 0 }
                ExitCode   = $_.ExitCode
            }
        } | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $OutCsv" -ForegroundColor DarkGray
    }

    return @{
        Results       = $results
        RateLimited   = $rateLimited
        LimitAt       = $limitThreshold
        StatusCodes   = $normalCodes
    }
}


# ===========================================================================
# FUNCTION 15 : Invoke-CurlHunterMenu
# ===========================================================================
<#
.SYNOPSIS
    Launch an interactive console menu for curl-hunter.

.DESCRIPTION
    Provides a console-based interactive menu that lets you select and
    configure curl-hunter functions without remembering parameter names.
    Useful for quick ad-hoc testing.

.PARAMETER NoExit
    If set, returns to the menu after each action instead of exiting.

.EXAMPLE
    Invoke-CurlHunterMenu
#>
function Invoke-CurlHunterMenu {
    [CmdletBinding()]
    param(
        [switch] $NoExit
    )

    $menuItems = @(
        @{ Key = "1"; Label = "Test a single endpoint"; Action = "endpoint" }
        @{ Key = "2"; Label = "Test JSON API endpoint"; Action = "json" }
        @{ Key = "3"; Label = "Auth bypass scan"; Action = "auth" }
        @{ Key = "4"; Label = "Parameter fuzzing"; Action = "paramfuzz" }
        @{ Key = "5"; Label = "IDOR enumeration"; Action = "idor" }
        @{ Key = "6"; Label = "Method bypass test"; Action = "method" }
        @{ Key = "7"; Label = "SSRF parameter scan"; Action = "ssrf" }
        @{ Key = "8"; Label = "CORS misconfiguration test"; Action = "cors" }
        @{ Key = "9"; Label = "Rate-limit stress test"; Action = "ratelimit" }
        @{ Key = "B"; Label = "Send batch requests"; Action = "batch" }
        @{ Key = "L"; Label = "List saved sessions"; Action = "listsessions" }
        @{ Key = "H"; Label = "Convert last response to HAR"; Action = "har" }
        @{ Key = "Q"; Label = "Quit"; Action = "quit" }
    )

    $lastResponse = $null

    do {
        Clear-Host
        Write-Host @"

+==========================================+
|        curl-hunter.ps1  Interactive      |
|        Bug Bounty curl Toolkit           |
+==========================================+

"@ -ForegroundColor Cyan

        foreach ($item in $menuItems) {
            Write-Host ("  [{0}] {1}" -f $item.Key, $item.Label) -ForegroundColor White
        }

        if ($lastResponse) {
            Write-Host ("`n  Last response: HTTP $($lastResponse.StatusCode) | $($lastResponse.RequestUrl)") -ForegroundColor DarkGray
        }

        Write-Host "`n  Enter choice: " -NoNewline -ForegroundColor Yellow
        $choice = (Read-Host).ToUpper()

        $item = $menuItems | Where-Object { $_.Key -eq $choice }
        if (-not $item) {
            Write-Host "  Invalid choice." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }

        switch ($item.Action) {
            "endpoint" {
                $url = Read-Host "URL"
                $method = Read-Host "Method (GET)"
                if (-not $method) { $method = "GET" }
                $lastResponse = Test-Endpoint -Url $url -Method $method -ShowHeaders
                if (-not $NoExit) { break }
            }
            "json" {
                $url = Read-Host "URL"
                $method = Read-Host "Method (POST)"
                if (-not $method) { $method = "POST" }
                $body = Read-Host "JSON body"
                $lastResponse = Test-JsonApi -Url $url -Method $method -Body $body -Pretty
                if (-not $NoExit) { break }
            }
            "auth" {
                $url = Read-Host "URL"
                $token = Read-Host "Bearer token (optional)"
                $splat = @{ Url = $url }
                if ($token) { $splat.OriginalToken = $token }
                $lastResponse = Test-AuthBypass @splat
                if (-not $NoExit) { break }
            }
            "paramfuzz" {
                $url = Read-Host "URL (use {fuzz} placeholder or -Parameter)"
                $param = Read-Host "Query parameter name (optional)"
                $splat = @{ Url = $url }
                if ($param) { $splat.Parameter = $param }
                $lastResponse = Test-ParameterFuzz @splat
                if (-not $NoExit) { break }
            }
            "idor" {
                $url = Read-Host "URL (with {id} placeholder)"
                $start = Read-Host "Start ID (1)"
                $end = Read-Host "End ID (50)"
                $splat = @{
                    Url     = $url
                    StartId = if ($start) { [int]$start } else { 1 }
                    EndId   = if ($end) { [int]$end } else { 50 }
                }
                $lastResponse = Test-IdorRange @splat
                if (-not $NoExit) { break }
            }
            "method" {
                $url = Read-Host "URL"
                $lastResponse = Test-MethodBypass -Url $url
                if (-not $NoExit) { break }
            }
            "ssrf" {
                $url = Read-Host "URL"
                $cb = Read-Host "Callback URL (optional)"
                $splat = @{ Url = $url }
                if ($cb) { $splat.CallbackUrl = $cb }
                $lastResponse = Test-SsrfParams @splat
                if (-not $NoExit) { break }
            }
            "cors" {
                $url = Read-Host "URL"
                $lastResponse = Test-Cors -Url $url
                if (-not $NoExit) { break }
            }
            "ratelimit" {
                $url = Read-Host "URL"
                $total = Read-Host "Total requests (30)"
                $concurrency = Read-Host "Concurrency (1)"
                $splat = @{
                    Url           = $url
                    TotalRequests = if ($total) { [int]$total } else { 30 }
                    Concurrency   = if ($concurrency) { [int]$concurrency } else { 1 }
                }
                $lastResponse = Invoke-RateLimitTest @splat
                if (-not $NoExit) { break }
            }
            "batch" {
                Write-Host "Enter requests (one URL per line, blank line to finish):" -ForegroundColor DarkGray
                $reqs = @()
                $lineNum = 1
                while ($true) {
                    $line = Read-Host "  $lineNum"
                    if (-not $line) { break }
                    $reqs += @{ Url = $line; Method = "GET"; Label = "Req#$lineNum" }
                    $lineNum++
                }
                if ($reqs.Count -gt 0) {
                    $lastResponse = Send-BatchRequests -Requests $reqs
                }
                if (-not $NoExit) { break }
            }
            "listsessions" {
                Save-CurlSession -Action List
                Write-Host "`nPress Enter to continue..." -NoNewline
                $null = Read-Host
            }
            "har" {
                if (-not $lastResponse) {
                    Write-Host "  No response to convert. Run a test first." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
                else {
                    $out = Read-Host "Output HAR file path"
                    if (-not $out) { $out = Join-Path -Path $Script:LogDir -ChildPath ("response_$(Get-Timestamp).har") }
                    ConvertTo-Har -Response $lastResponse -OutFile $out
                    Write-Host "Press Enter to continue..." -NoNewline
                    $null = Read-Host
                }
            }
            "quit" {
                Write-Host "Exiting." -ForegroundColor DarkGray
                return
            }
        }

        if (-not $NoExit -and $item.Action -ne "quit" -and $item.Action -ne "listsessions" -and $item.Action -ne "har") {
            Write-Host "`nPress Enter to continue..." -NoNewline
            $null = Read-Host
        }

    } while ($NoExit)

    if (-not $NoExit) {
        Write-Host "Exiting." -ForegroundColor DarkGray
    }
}


# ===========================================================================
# Module export
# ===========================================================================
$exportedFunctions = @(
    "Invoke-CurlRequest"
    "Save-CurlSession"
    "Test-Endpoint"
    "Test-JsonApi"
    "Test-AuthBypass"
    "Test-ParameterFuzz"
    "Test-IdorRange"
    "Test-MethodBypass"
    "Test-SsrfParams"
    "Test-Cors"
    "Compare-ResponseDiff"
    "ConvertTo-Har"
    "Send-BatchRequests"
    "Invoke-RateLimitTest"
    "Invoke-CurlHunterMenu"
)

Write-Host "[curl-hunter.ps1] Loaded $($exportedFunctions.Count) functions." -ForegroundColor DarkCyan
Write-Host "[curl-hunter.ps1] Log directory: $Script:LogDir" -ForegroundColor DarkGray
Write-Host "[curl-hunter.ps1] Use 'Invoke-CurlHunterMenu' for interactive mode." -ForegroundColor DarkGray
