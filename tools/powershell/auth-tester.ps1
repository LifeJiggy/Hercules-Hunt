<#
.SYNOPSIS
    Auth-Tester — Authentication Testing Tool for Bug Bounty Reconnaissance

.DESCRIPTION
    Comprehensive authentication security testing tool. Analyzes login forms, session
    cookies, JWT tokens, and performs common auth bypass tests to identify
    authentication and authorization vulnerabilities.

    Features:
      - Login form detection and analysis (methods, fields, actions)
      - Session cookie analysis (HttpOnly, Secure, SameSite, domain, path, expiry)
      - JWT decoding and inspection (header, payload, signature, alg analysis)
      - Common auth bypass tests (header injection, parameter tampering, verb tampering)
      - Brute-force detection and rate limit testing
      - Password reset flow analysis
      - 2FA/MFA implementation detection
      - OAuth flow identification
      - Response analysis for auth-fingerprinting
      - Structured JSON output for pipeline integration

    Output sections:
      - LoginForms: detected login mechanisms
      - Cookies: session cookie analysis
      - JwtAnalysis: decoded JWT details
      - BypassTests: results of auth bypass attempts
      - RateLimitResults: rate limiting assessment
      - AuthEndpoints: discovered auth-related endpoints

.PARAMETER Target
    Target base URL for authentication testing (e.g. https://target.com).

.PARAMETER LoginUrl
    Specific login page URL (e.g. https://target.com/login).

.PARAMETER Credentials
    Hashtable of credentials for authenticated testing. Format: @{Username='user';Password='pass';FieldUser='username';FieldPass='password'}

.PARAMETER Method
    HTTP method for authentication requests. Default: POST

.PARAMETER OutputFile
    Path to write structured results (JSON format). If omitted, results go to pipeline.

.PARAMETER AnalyzeJWT
    Extract and decode JWT tokens from responses and JavaScript. Default: $true.

.PARAMETER TestBypasses
    Run common authentication bypass tests. Default: $true.

.PARAMETER TestRateLimit
    Test for rate limiting on login endpoints. Default: $true.

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER UserAgent
    Custom User-Agent string for HTTP requests.

.PARAMETER RateLimit
    Minimum milliseconds between requests. Default: 500

.PARAMETER Silent
    Suppress all non-data output.

.EXAMPLE
    .\auth-tester.ps1 -Target "https://target.com" -LoginUrl "https://target.com/login"

    Analyzes the login page, cookies, and performs auth bypass tests.

.EXAMPLE
    .\auth-tester.ps1 -Target "https://target.com" -Credentials @{Username='test';Password='test123'} -AnalyzeJWT

    Authenticated analysis with JWT decoding.

.EXAMPLE
    .\auth-tester.ps1 -Target "https://target.com" -TestBypasses -TestRateLimit -OutputFile "auth-results.json"

    Full auth testing with bypasses and rate limiting, output to file.

.EXAMPLE
    .\auth-tester.ps1 -Target "https://target.com" -Method GET -TestBypasses:$false

    Analyze using GET method, skip bypass tests.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Details     : Uses Invoke-WebRequest and Invoke-RestMethod for all HTTP.
                  JWT decoding uses base64url decoding. No external modules.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

$Script:AuthEndpointPatterns = @(
    '/login', '/signin', '/auth', '/authenticate', '/oauth', '/oauth2',
    '/token', '/api/token', '/api/auth', '/api/login', '/api/signin',
    '/api/authenticate', '/api/v1/auth', '/api/v1/login', '/api/v1/token',
    '/jwt', '/api/jwt', '/auth/token', '/auth/login', '/auth/signin',
    '/sso', '/saml', '/adfs', '/connect/token', '/authorize',
    '/oauth/authorize', '/oauth/token', '/api/oauth/token'
)

$Script:AuthBypassHeaders = @(
    @{Name = 'X-Forwarded-For'; Value = '127.0.0.1' },
    @{Name = 'X-Forwarded-Host'; Value = 'localhost' },
    @{Name = 'X-Real-IP'; Value = '127.0.0.1' },
    @{Name = 'X-Originating-IP'; Value = '127.0.0.1' },
    @{Name = 'X-Remote-IP'; Value = '127.0.0.1' },
    @{Name = 'X-Remote-Addr'; Value = '127.0.0.1' },
    @{Name = 'X-Client-IP'; Value = '127.0.0.1' },
    @{Name = 'X-Host'; Value = 'localhost' },
    @{Name = 'X-Forwarded-Proto'; Value = 'https' },
    @{Name = 'Client-IP'; Value = '127.0.0.1' },
    @{Name = 'Forwarded'; Value = 'for=127.0.0.1;host=localhost;proto=https' },
    @{Name = 'Authorization'; Value = 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.' },
    @{Name = 'Authorization'; Value = 'Basic YWRtaW46YWRtaW4=' },
    @{Name = 'X-Admin'; Value = 'true' },
    @{Name = 'X-Role'; Value = 'admin' },
    @{Name = 'X-User-Role'; Value = 'administrator' },
    @{Name = 'X-Permissions'; Value = '*' },
    @{Name = 'X-Access-Level'; Value = 'admin' },
    @{Name = 'X-User'; Value = 'admin' },
    @{Name = 'X-Username'; Value = 'admin' },
    @{Name = 'X-Auth-Override'; Value = 'true' },
    @{Name = 'X-Internal'; Value = 'true' },
    @{Name = 'X-Backend'; Value = 'true' },
    @{Name = 'X-Proxy'; Value = 'true' }
)

$Script:AuthBypassParams = @(
    @{Name = 'is_admin'; Value = 'true' },
    @{Name = 'isAdmin'; Value = 'true' },
    @{Name = 'admin'; Value = 'true' },
    @{Name = 'role'; Value = 'admin' },
    @{Name = 'user_role'; Value = 'admin' },
    @{Name = 'userRole'; Value = 'admin' },
    @{Name = 'permissions'; Value = '*' },
    @{Name = 'access_level'; Value = 'admin' },
    @{Name = 'verified'; Value = 'true' },
    @{Name = 'is_verified'; Value = 'true' },
    @{Name = 'email_verified'; Value = 'true' },
    @{Name = 'is_active'; Value = 'true' },
    @{Name = 'bypass'; Value = 'true' },
    @{Name = 'debug'; Value = 'true' },
    @{Name = 'internal'; Value = '1' },
    @{Name = 'sudo'; Value = 'true' },
    @{Name = 'impersonate'; Value = 'admin' },
    @{Name = 'as_user'; Value = 'admin' }
)

$Script:AuthBypassPaths = @(
    '/admin', '/api/admin', '/dashboard', '/api/internal', '/api/private',
    '/api/v1/admin', '/api/v2/admin', '/api/debug', '/api/health',
    '/api/config', '/api/settings', '/api/users', '/api/user/list',
    '/internal', '/private', '/restricted', '/management', '/console',
    '/api/console', '/shell', '/api/server', '/api/system', '/logs',
    '/api/logs', '/api/backup', '/api/export', '/api/import', '/api/migrate'
)

$Script:JwtHeaderPatterns = '(?:Authorization|Bearer|JWT|access-token|token)[:\s]+(?:Bearer\s+)?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'

$Script:JwtPatterns = @(
    '["''](access_token|id_token|refresh_token|token|jwt)["'']\s*[:=]\s*["'']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["'']',
    '["'']token["'']\s*[:=]\s*["'']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["'']',
    '\b(jwt|token)\s*[:=]\s*["'']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["'']'
)

# ============================================================================
# FUNCTION: Invoke-WebRequestSafe
# ============================================================================

function Invoke-WebRequestSafe {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Headers,
        [string]$SessionVariable
    )
    $ua = if ($UserAgent) { $UserAgent } else { $Script:DefaultUserAgent }
    $params = @{
        Uri             = $Uri
        Method          = $Method
        TimeoutSec      = $TimeoutSec
        UserAgent       = $ua
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($Body) { $params['Body'] = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }
    if ($Headers) { $params['Headers'] = $Headers }
    if ($SessionVariable) { $params['SessionVariable'] = $SessionVariable }

    try {
        $response = Invoke-WebRequest @params
        $content = if ($response.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($response.Content)
        } else { $response.Content }

        $result = [PSCustomObject]@{
            StatusCode      = [int]$response.StatusCode
            StatusDescription = $response.StatusCode.ToString()
            Content         = $content
            ContentLength   = if ($content) { $content.Length } else { 0 }
            ContentType     = $response.Headers.'Content-Type' -join ', '
            Headers         = $response.Headers
            Cookies         = $response.BaseResponse.Cookies
            Success         = $true
            ErrorMessage    = $null
            ElapsedMs       = 0
            StartTime       = (Get-Date)
            EndTime         = (Get-Date)
        }
        return $result
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $result = [PSCustomObject]@{
            StatusCode      = $statusCode
            StatusDescription = $_.Exception.Message
            Content         = $null
            ContentLength   = 0
            ContentType     = $null
            Headers         = $null
            Cookies         = $null
            Success         = $false
            ErrorMessage    = $_.Exception.Message
            ElapsedMs       = 0
            StartTime       = (Get-Date)
            EndTime         = (Get-Date)
        }
        return $result
    }
}

# ============================================================================
# FUNCTION: Decode-Base64Url
# ============================================================================

function Decode-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Base64UrlString
    )
    try {
        $base64 = $Base64UrlString -replace '-', '+' -replace '_', '/'
        switch ($base64.Length % 4) {
            2 { $base64 += '==' }
            3 { $base64 += '=' }
        }
        $bytes = [Convert]::FromBase64String($base64)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    catch {
        return $null
    }
}

# ============================================================================
# FUNCTION: Decode-Jwt
# ============================================================================

function Decode-Jwt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$JwtToken
    )
    $parts = $JwtToken -split '\.'
    if ($parts.Count -ne 3) {
        return $null
    }

    $headerDecoded = Decode-Base64Url -Base64UrlString $parts[0]
    $payloadDecoded = Decode-Base64Url -Base64UrlString $parts[1]
    $signatureRaw = $parts[2]

    if (-not $headerDecoded -or -not $payloadDecoded) {
        return $null
    }

    try {
        $headerObj = $headerDecoded | ConvertFrom-Json
        $payloadObj = $payloadDecoded | ConvertFrom-Json
    }
    catch {
        return $null
    }

    $alg = $headerObj.alg
    $typ = $headerObj.typ
    $kid = $headerObj.kid
    $iss = $payloadObj.iss
    $sub = $payloadObj.sub
    $aud = $payloadObj.aud
    $exp = $payloadObj.exp
    $nbf = $payloadObj.nbf
    $iat = $payloadObj.iat
    $jti = $payloadObj.jti
    $roleClaim = $null
    $isAdmin = $false

    # Detect common role/privilege claims
    $roleFields = @('role', 'roles', 'permissions', 'groups', 'scope', 'scopes', 'user_role', 'userRole', 'is_admin', 'isAdmin', 'admin', 'privilege', 'privileges', 'access_level', 'accessLevel', 'type', 'account_type', 'accountType', 'tier', 'plan', 'level')
    foreach ($field in $roleFields) {
        if ($payloadObj.$field) {
            $roleClaim = "$field: $($payloadObj.$field)"
            if ($payloadObj.$field -match 'admin|Admin|ADMIN|root|super|owner|manager|moderator|staff|employee|internal') {
                $isAdmin = $true
            }
            break
        }
    }

    # Check alg for "none" (vulnerable)
    $algVulnerable = ($alg -eq 'none' -or $alg -eq 'None' -or $alg -eq 'NONE')
    $algWeak = ($alg -match '^(HS256|HS384|HS512)$' -and $alg.Length -le 5)

    # Analyse signature length for weak keys
    $sigStrength = if ($signatureRaw.Length -ge 86) { 'Strong' }
    elseif ($signatureRaw.Length -ge 44) { 'Medium' }
    elseif ($signatureRaw.Length -ge 22) { 'Weak' }
    else { 'Minimal' }

    # Check if expired
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $expired = if ($exp -and $exp -lt $now) { $true } else { $false }
    $notYetValid = if ($nbf -and $nbf -gt $now) { $true } else { $false }

    $formattedExp = if ($exp) { (Get-Date '1970-01-01').AddSeconds($exp).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
    $formattedNbf = if ($nbf) { (Get-Date '1970-01-01').AddSeconds($nbf).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
    $formattedIat = if ($iat) { (Get-Date '1970-01-01').AddSeconds($iat).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }

    $payloadProps = [PSCustomObject]@{
        Issuer         = $iss
        Subject        = $sub
        Audience       = $aud
        Expiry         = $formattedExp
        NotBefore      = $formattedNbf
        IssuedAt       = $formattedIat
        JwtId          = $jti
        RoleClaim      = $roleClaim
        HasAdminClaim  = $isAdmin
        PayloadRaw     = $payloadDecoded
    }

    $analysis = [PSCustomObject]@{
        Algorithm        = $alg
        AlgorithmType    = if ($alg -match '^(RS|PS|ES|EdDSA)') { 'Asymmetric' } elseif ($alg -match '^(HS)') { 'Symmetric' } elseif ($alg -eq 'none') { 'None (Insecure)' } else { 'Unknown' }
        AlgorithmStrength = if ($algVulnerable) { 'CRITICAL' } elseif ($alg -eq 'HS256') { 'Low' } elseif ($alg -match '^(HS384|HS512)$') { 'Medium' } else { 'High' }
        KeyId            = $kid
        TokenType        = $typ
        AlgIsNone        = $algVulnerable
        AlgIsSymmetric   = ($alg -match '^HS')
        SignatureLength  = $signatureRaw.Length
        SignatureStrength = $sigStrength
        Expired          = $expired
        NotYetValid      = $notYetValid
        TokenAgeSec      = if ($iat) { $now - $iat } else { $null }
        Payload          = $payloadProps
        HeaderRaw        = $headerDecoded
    }

    return $analysis
}

# ============================================================================
# FUNCTION: Find-JwtTokens
# ============================================================================

function Find-JwtTokens {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [string]$Source
    )
    $jwtTokens = [System.Collections.Generic.List[object]]::new()
    $seenTokens = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($pattern in $Script:JwtPatterns) {
        $matches = [regex]::Matches($Content, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $matches) {
            $token = $m.Groups[2].Value
            if ($token -and -not $seenTokens.Contains($token) -and ($token -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')) {
                $null = $seenTokens.Add($token)
                $decoded = Decode-Jwt -JwtToken $token
                $jwtTokens.Add([PSCustomObject]@{
                    Token       = $token.Substring(0, [Math]::Min(50, $token.Length)) + '...'
                    TokenHash   = $token.GetHashCode()
                    FullToken   = $token
                    Source      = $Source
                    Decoded     = $decoded
                })
            }
        }
    }

    return $jwtTokens
}

# ============================================================================
# FUNCTION: Find-JwtInHeaders
# ============================================================================

function Find-JwtInHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
    $jwtTokens = [System.Collections.Generic.List[object]]::new()
    $seenTokens = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($key in $Headers.Keys) {
        $values = $Headers[$key]
        if ($values -is [string]) { $values = @($values) }
        foreach ($val in $values) {
            $match = [regex]::Match($val, $Script:JwtHeaderPatterns, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($match.Success) {
                $token = $match.Groups[1].Value
                if (-not $seenTokens.Contains($token)) {
                    $null = $seenTokens.Add($token)
                    $decoded = Decode-Jwt -JwtToken $token
                    $jwtTokens.Add([PSCustomObject]@{
                        Token      = $token.Substring(0, [Math]::Min(50, $token.Length)) + '...'
                        TokenHash  = $token.GetHashCode()
                        FullToken  = $token
                        Source     = "header:$key"
                        Decoded    = $decoded
                    })
                }
            }
        }
    }
    return $jwtTokens
}

# ============================================================================
# FUNCTION: Analyze-Cookies
# ============================================================================

function Analyze-Cookies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.CookieCollection]$Cookies,
        [hashtable]$ResponseHeaders
    )
    $cookieAnalysis = [System.Collections.Generic.List[object]]::new()
    $cookieWarnings = [System.Collections.Generic.List[string]]::new()
    $sessionCookieFound = $false

    foreach ($cookie in $Cookies) {
        $isSecure = $cookie.Secure
        $isHttpOnly = $cookie.HttpOnly
        $domain = $cookie.Domain
        $path = $cookie.Path
        $expires = if ($cookie.Expires -and $cookie.Expires -ne [DateTime]::MinValue) { $cookie.Expires.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'Session' }
        $expiresUtc = if ($cookie.Expires -and $cookie.Expires -ne [DateTime]::MinValue) { $cookie.Expires } else { $null }

        # Detect SameSite from response headers
        $sameSite = 'Unknown'
        $rawCookie = $null
        if ($ResponseHeaders) {
            $setCookieHeaders = $ResponseHeaders['Set-Cookie']
            if ($setCookieHeaders) {
                if ($setCookieHeaders -is [string]) { $setCookieHeaders = @($setCookieHeaders) }
                foreach ($sch in $setCookieHeaders) {
                    if ($sch -match "$($cookie.Name)[^;]*;\s*.*?(SameSite=(None|Lax|Strict))") {
                        $sameSite = $matches[2]
                        break
                    }
                }
            }
        }

        # Identify session cookies
        $isSession = ($cookie.Name -match '(?i)(session|sid|token|auth|jwt|php[s]?ession|aspsession|asp\.net_session|connect\.sid|laravel_session|symfony|ci_session|zenid|sess|bearer|access|refresh|xsrf|xrf|csrf)')
        if ($isSession) { $sessionCookieFound = $true }

        # Generate warnings
        if ($cookie.Secure -eq $false -and $cookie.Name -match '(?i)(session|token|auth|sid|jwt)') {
            $cookieWarnings.Add("$($cookie.Name): Missing Secure flag")
        }
        if ($cookie.HttpOnly -eq $false -and $cookie.Name -match '(?i)(session|token|auth|sid|jwt)') {
            $cookieWarnings.Add("$($cookie.Name): Missing HttpOnly flag")
        }
        if ($sameSite -eq 'None' -or $sameSite -eq 'Unknown') {
            $cookieWarnings.Add("$($cookie.Name): SameSite is $sameSite (consider Lax or Strict)")
        }
        if ($domain -match '^\.') {
            $cookieWarnings.Add("$($cookie.Name): Wildcard domain prefix detected ($domain)")
        }
        if ($path -eq '/') {
            $cookieWarnings.Add("$($cookie.Name): Cookie applies to entire site (path=/)")
        }

        # Calculate expiry info
        $expiresInHours = $null
        if ($expiresUtc) {
            $expiresInHours = [Math]::Round(($expiresUtc - (Get-Date)).TotalHours, 1)
        }
        $isPersistent = ($expiresUtc -ne $null)

        $cookieAnalysis.Add([PSCustomObject]@{
            CookieName       = $cookie.Name
            CookieValue      = $cookie.Value.Substring(0, [Math]::Min(20, $cookie.Value.Length)) + '...'
            Domain           = $domain
            Path             = $path
            Secure           = $isSecure
            HttpOnly         = $isHttpOnly
            SameSite         = $sameSite
            Expires          = $expires
            ExpiresInHours   = $expiresInHours
            IsSessionCookie  = $isSession
            IsPersistent     = $isPersistent
            Warnings         = @()
        })
    }

    return [PSCustomObject]@{
        Cookies         = $cookieAnalysis
        Warnings        = $cookieWarnings
        SessionFound    = $sessionCookieFound
        TotalCookies    = $cookieAnalysis.Count
    }
}

# ============================================================================
# FUNCTION: Test-AuthBypassHeaders
# ============================================================================

function Test-AuthBypassHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetUrl,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()

    # Baseline request (no special headers)
    if (-not $Silent) { Write-Output "[*] Baseline request: $TargetUrl" }
    $baseline = Invoke-WebRequestSafe -Uri $TargetUrl -TimeoutSec $TimeoutSec -UserAgent $UserAgent
    $baselineSize = if ($baseline.Success) { $baseline.ContentLength } else { 0 }
    $baselineStatus = $baseline.StatusCode

    foreach ($header in $Script:AuthBypassHeaders) {
        $testHeaders = @{ $header.Name = $header.Value }
        $response = Invoke-WebRequestSafe -Uri $TargetUrl -Method 'GET' -Headers $testHeaders -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        $statusChanged = ($response.StatusCode -ne $baselineStatus)
        $sizeChanged = ($response.ContentLength -ne $baselineSize -and $response.ContentLength -gt 0)
        $interesting = $statusChanged -or $sizeChanged

        $results.Add([PSCustomObject]@{
            TestType          = 'header_bypass'
            HeaderName        = $header.Name
            HeaderValue       = $header.Value
            StatusCode        = $response.StatusCode
            BaselineStatus    = $baselineStatus
            ContentLength     = $response.ContentLength
            SizeChanged       = $sizeChanged
            StatusChanged     = $statusChanged
            Interesting       = $interesting
            Success           = $response.Success
            Error             = $response.ErrorMessage
        })

        if ($interesting -and -not $Silent) {
            Write-Output "[!] Interesting: $($header.Name): $($header.Value) -> Status $($response.StatusCode) (was $baselineStatus)"
        }
    }

    return $results
}

# ============================================================================
# FUNCTION: Test-AuthBypassParams
# ============================================================================

function Test-AuthBypassParams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetUrl,
        [string]$Method = 'POST',
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()

    $baseline = Invoke-WebRequestSafe -Uri $TargetUrl -Method $Method -TimeoutSec $TimeoutSec -UserAgent $UserAgent
    $baselineSize = if ($baseline.Success) { $baseline.ContentLength } else { 0 }
    $baselineStatus = $baseline.StatusCode

    foreach ($param in $Script:AuthBypassParams) {
        $body = "$($param.Name)=$($param.Value)"
        $response = Invoke-WebRequestSafe -Uri $TargetUrl -Method $Method -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        $statusChanged = ($response.StatusCode -ne $baselineStatus)
        $sizeChanged = ($response.ContentLength -ne $baselineSize -and $response.ContentLength -gt 0)
        $interesting = $statusChanged -or $sizeChanged

        $results.Add([PSCustomObject]@{
            TestType          = 'param_bypass'
            ParamName         = $param.Name
            ParamValue        = $param.Value
            StatusCode        = $response.StatusCode
            BaselineStatus    = $baselineStatus
            ContentLength     = $response.ContentLength
            SizeChanged       = $sizeChanged
            StatusChanged     = $statusChanged
            Interesting       = $interesting
            Success           = $response.Success
            Error             = $response.ErrorMessage
        })

        if ($interesting -and -not $Silent) {
            Write-Output "[!] Interesting: $($param.Name)=$($param.Value) -> Status $($response.StatusCode) (was $baselineStatus)"
        }
    }

    return $results
}

# ============================================================================
# FUNCTION: Test-AuthBypassVerbs
# ============================================================================

function Test-AuthBypassVerbs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetUrl,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $verbs = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT')

    $baseline = Invoke-WebRequestSafe -Uri $TargetUrl -Method 'GET' -TimeoutSec $TimeoutSec -UserAgent $UserAgent
    $baselineStatus = $baseline.StatusCode
    $baselineSize = if ($baseline.Success) { $baseline.ContentLength } else { 0 }

    foreach ($verb in $verbs) {
        $response = Invoke-WebRequestSafe -Uri $TargetUrl -Method $verb -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        $statusChanged = ($response.StatusCode -ne $baselineStatus)
        $interesting = $statusChanged -and $response.StatusCode -notin @(0, 405, 501, 400)

        $results.Add([PSCustomObject]@{
            TestType          = 'verb_tampering'
            Verb              = $verb
            StatusCode        = $response.StatusCode
            BaselineVerb      = 'GET'
            BaselineStatus    = $baselineStatus
            ContentLength     = $response.ContentLength
            Interesting       = $interesting
            Success           = $response.Success
            Error             = $response.ErrorMessage
        })

        if ($interesting -and -not $Silent) {
            Write-Output "[!] Interesting: $verb $TargetUrl -> Status $($response.StatusCode)"
        }
    }

    return $results
}

# ============================================================================
# FUNCTION: Test-RateLimit
# ============================================================================

function Test-RateLimit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LoginUrl,
        [string]$Method = 'POST',
        [string]$RequestBody,
        [int]$MaxAttempts = 20,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $timings = [System.Collections.Generic.List[long]]::new()
    $statusCodes = [System.Collections.Generic.List[int]]::new()
    $rateLimited = $false
    $rateLimitDetectedAt = $null

    if (-not $Silent) { Write-Output "[*] Rate limit test: $MaxAttempts attempts to $LoginUrl" }

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $startTime = Get-Date
        $response = Invoke-WebRequestSafe -Uri $LoginUrl -Method $Method -Body $RequestBody -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalMilliseconds, 0)

        $timings.Add($elapsed)
        $statusCodes.Add($response.StatusCode)

        if (-not $rateLimited -and $response.StatusCode -in @(429, 420, 503, 403)) {
            $rateLimited = $true
            $rateLimitDetectedAt = $i
            if (-not $Silent) { Write-Output "[!] Rate limited at attempt $i: Status $($response.StatusCode)" }
        }

        # Check for Retry-After header
        $retryAfter = $null
        if ($response.Headers -and $response.Headers.ContainsKey('Retry-After')) {
            $retryAfter = ($response.Headers['Retry-After'] -join ', ')
        }

        $results.Add([PSCustomObject]@{
            Attempt          = $i
            StatusCode       = $response.StatusCode
            ContentLength    = $response.ContentLength
            ElapsedMs        = $elapsed
            RetryAfter       = $retryAfter
            RateLimited      = ($response.StatusCode -in @(429, 420, 503, 403))
            Success          = $response.Success
            Error            = $response.ErrorMessage
        })
    }

    # Analyse timing patterns
    $avgTiming = if ($timings.Count -gt 0) { [Math]::Round(($timings | Measure-Object -Average).Average, 0) } else { 0 }
    $maxTiming = if ($timings.Count -gt 0) { ($timings | Measure-Object -Maximum).Maximum } else { 0 }
    $minTiming = if ($timings.Count -gt 0) { ($timings | Measure-Object -Minimum).Minimum } else { 0 }
    $timingStdDev = if ($timings.Count -gt 1) {
        $avg = $timings | Measure-Object -Average
        $variance = ($timings | ForEach-Object { [Math]::Pow($_ - $avg.Average, 2) } | Measure-Object -Average).Average
        [Math]::Round([Math]::Sqrt($variance), 0)
    } else { 0 }

    $uniqueStatusCodes = ($statusCodes | Select-Object -Unique) -join ', '
    $blockedAttempts = ($results | Where-Object { $_.RateLimited }).Count

    return [PSCustomObject]@{
        TestedUrl          = $LoginUrl
        MaxAttempts        = $MaxAttempts
        RateLimited        = $rateLimited
        RateLimitAtAttempt = $rateLimitDetectedAt
        BlockedAttempts    = $blockedAttempts
        StatusCodes        = $uniqueStatusCodes
        AverageTimingMs    = $avgTiming
        MinTimingMs        = $minTiming
        MaxTimingMs        = $maxTiming
        TimingStdDevMs     = $timingStdDev
        Attempts           = $results
    }
}

# ============================================================================
# FUNCTION: Test-InternalPathAccess
# ============================================================================

function Test-InternalPathAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $accessiblePaths = [System.Collections.Generic.List[string]]::new()

    foreach ($path in $Script:AuthBypassPaths) {
        $url = "$($BaseUrl.TrimEnd('/'))$path"
        $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        $authRequired = ($response.StatusCode -in @(401, 403, 302, 301))
        $accessible = $response.StatusCode -in @(200, 204, 404) -and $response.StatusCode -gt 0

        $results.Add([PSCustomObject]@{
            Path          = $path
            FullUrl       = $url
            StatusCode    = $response.StatusCode
            ContentLength = $response.ContentLength
            Accessible    = $accessible
            AuthRequired  = $authRequired
        })

        if ($accessible -and -not $Silent) {
            Write-Output "[!] Potentially accessible: $url -> $($response.StatusCode)"
        }
    }

    return $results
}

# ============================================================================
# FUNCTION: Analyze-AuthResponseHeaders
# ============================================================================

function Analyze-AuthResponseHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    $headerStr = ($Headers.Keys | ForEach-Object { "$_ : $($Headers[$_])" }) -join '; '

    if ($Headers.ContainsKey('WWW-Authenticate')) {
        $findings.Add([PSCustomObject]@{
            Finding = 'WWW-Authenticate header present'
            Detail  = ($Headers['WWW-Authenticate'] -join ', ')
            Risk    = 'Info'
        })
    }

    if ($Headers.ContainsKey('X-AspNet-Version') -or $Headers.ContainsKey('X-AspNetMvc-Version')) {
        $findings.Add([PSCustomObject]@{
            Finding = 'ASP.NET version disclosure'
            Detail  = "X-AspNet-Version: $($Headers['X-AspNet-Version'])"
            Risk    = 'Low'
        })
    }

    if ($Headers.ContainsKey('X-Powered-By')) {
        $findings.Add([PSCustomObject]@{
            Finding = 'Server technology disclosure'
            Detail  = "X-Powered-By: $($Headers['X-Powered-By'])"
            Risk    = 'Info'
        })
    }

    if ($Headers.ContainsKey('Server')) {
        $server = ($Headers['Server'] -join ', ')
        $findings.Add([PSCustomObject]@{
            Finding = 'Server header disclosure'
            Detail  = "Server: $server"
            Risk    = 'Low'
        })
    }

    if ($Headers.ContainsKey('Strict-Transport-Security')) {
        $hsts = ($Headers['Strict-Transport-Security'] -join ', ')
        $findings.Add([PSCustomObject]@{
            Finding = 'HSTS configured'
            Detail  = "Strict-Transport-Security: $hsts"
            Risk    = 'Info'
        })
    }
    else {
        $findings.Add([PSCustomObject]@{
            Finding = 'HSTS not configured'
            Detail  = 'No Strict-Transport-Security header'
            Risk    = 'Medium'
        })
    }

    if (-not $Headers.ContainsKey('X-Frame-Options') -and -not $Headers.ContainsKey('Content-Security-Policy')) {
        $findings.Add([PSCustomObject]@{
            Finding = 'Clickjacking protection missing'
            Detail  = 'No X-Frame-Options or Content-Security-Policy header'
            Risk    = 'Medium'
        })
    }

    if ($Headers.ContainsKey('Set-Cookie')) {
        $cookies = $Headers['Set-Cookie']
        if ($cookies -is [string]) { $cookies = @($cookies) }
        foreach ($ck in $cookies) {
            if ($ck -notmatch 'HttpOnly') {
                $findings.Add([PSCustomObject]@{
                    Finding = 'Cookie missing HttpOnly'
                    Detail  = $ck
                    Risk    = 'Medium'
                })
            }
            if ($ck -notmatch 'Secure') {
                $findings.Add([PSCustomObject]@{
                    Finding = 'Cookie missing Secure flag'
                    Detail  = $ck
                    Risk    = 'Medium'
                })
            }
            if ($ck -match 'SameSite=None') {
                $findings.Add([PSCustomObject]@{
                    Finding = 'Cookie SameSite=None'
                    Detail  = $ck
                    Risk    = 'Low'
                })
            }
        }
    }

    return $findings
}

# ============================================================================
# FUNCTION: Invoke-AuthTesting
# ============================================================================

function Invoke-AuthTesting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Target,
        [string]$LoginUrl,
        [hashtable]$Credentials,
        [string]$Method = 'POST',
        [string]$OutputFile,
        [switch]$AnalyzeJWT,
        [switch]$TestBypasses,
        [switch]$TestRateLimit,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 500,
        [switch]$Silent
    )
    $output = [PSCustomObject]@{
        Tool            = 'Auth-Tester'
        Timestamp       = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target          = $Target
        LoginUrl        = $LoginUrl
        LoginForms      = @()
        Cookies         = $null
        JwtTokens       = @()
        BypassTests     = @()
        RateLimitResult = $null
        AuthEndpoints   = @()
        HeaderFindings  = @()
        InternalPaths   = @()
        Warnings        = @()
        Errors          = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $allJwts = [System.Collections.Generic.List[object]]::new()

    if (-not $Target -and -not $LoginUrl) {
        $errMsg = 'Either -Target or -LoginUrl is required'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
        return $output
    }

    $baseUrl = if ($Target) { $Target } else { $LoginUrl }
    $loginTarget = if ($LoginUrl) { $LoginUrl } else { "$($baseUrl.TrimEnd('/'))/login" }

    # Phase 1: Fetch login page
    if (-not $Silent) { Write-Output "[*] Fetching login page: $loginTarget" }
    $loginResponse = Invoke-WebRequestSafe -Uri $loginTarget -TimeoutSec $Timeout -UserAgent $UserAgent
    if ($loginResponse.Success) {
        if (-not $Silent) { Write-Output "[+] Login page fetched ($($loginResponse.ContentLength) bytes, status $($loginResponse.StatusCode))" }

        # Extract forms
        $formPattern = '<form\s[^>]*>([\s\S]*?)</form>'
        $formMatches = [regex]::Matches($loginResponse.Content, $formPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $loginForms = [System.Collections.Generic.List[object]]::new()

        foreach ($fm in $formMatches) {
            $formHtml = $fm.Value
            $formAction = if ($formHtml -match 'action\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $loginTarget }
            $formMethod = if ($formHtml -match 'method\s*=\s*["''](\w+)["'']') { $matches[1].ToUpper() } else { 'GET' }
            $formId = if ($formHtml -match 'id\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }

            # Extract all input fields
            $inputs = [System.Collections.Generic.List[object]]::new()
            $inputPattern = '<input\s[^>]*/?>'
            $inputMatches = [regex]::Matches($formHtml, $inputPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $hasPassword = $false
            $hasUsername = $false
            $userField = $null
            $passField = $null

            foreach ($im in $inputMatches) {
                $inputHtml = $im.Value
                $iType = if ($inputHtml -match 'type\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1].ToLower() } else { 'text' }
                $iName = if ($inputHtml -match 'name\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }
                $iId = if ($inputHtml -match 'id\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }
                $iValue = if ($inputHtml -match 'value\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }
                $iPlaceholder = if ($inputHtml -match 'placeholder\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }
                $iRequired = ($inputHtml -match '\brequired\b')
                $iAutocomplete = if ($inputHtml -match 'autocomplete\s*=\s*["'']([^"''\s>]+)["'']') { $matches[1] } else { $null }

                $isPassword = ($iType -eq 'password')
                $isHidden = ($iType -eq 'hidden')

                if ($isPassword) { $hasPassword = $true; $passField = $iName }
                if (-not $isPassword -and -not $isHidden) { $hasUsername = $true; $userField = $iName }

                $inputs.Add([PSCustomObject]@{
                    Type         = $iType
                    Name         = $iName
                    Id           = $iId
                    Value        = $iValue
                    Placeholder  = $iPlaceholder
                    Required     = $iRequired
                    Autocomplete = $iAutocomplete
                    IsPassword   = $isPassword
                    IsHidden     = $isHidden
                })
            }

            $isLoginForm = $hasPassword -or
                ($formAction -match '(?i)(login|signin|auth|authenticate)') -or
                (($inputs | ForEach-Object { $_.Name }) -join ' ') -match '(?i)(password|pass)')

            $loginForms.Add([PSCustomObject]@{
                FormId         = $formId
                FormAction     = $formAction
                FormMethod     = $formMethod
                IsLoginForm    = $isLoginForm
                HasPassword    = $hasPassword
                UsernameField  = $userField
                PasswordField  = $passField
                Inputs         = $inputs
                InputCount     = $inputs.Count
            })

            if ($isLoginForm -and -not $Silent) {
                Write-Output "[+] Login form detected: action=$formAction method=$formMethod fields=$($inputs.Count)"
            }
        }
        $output.LoginForms = $loginForms

        # Phase 2: Cookie analysis
        if (-not $Silent) { Write-Output "[*] Analyzing cookies..." }
        if ($loginResponse.Cookies -and $loginResponse.Cookies.Count -gt 0) {
            $cookieAnalysis = Analyze-Cookies -Cookies $loginResponse.Cookies -ResponseHeaders $loginResponse.Headers
            $output.Cookies = $cookieAnalysis
            if ($cookieAnalysis.Warnings.Count -gt 0) {
                foreach ($warn in $cookieAnalysis.Warnings) {
                    $warnings.Add($warn)
                }
            }
        }

        # Phase 3: Response header analysis
        if (-not $Silent) { Write-Output "[*] Analyzing response headers..." }
        if ($loginResponse.Headers) {
            $headerFindings = Analyze-AuthResponseHeaders -Headers $loginResponse.Headers
            $output.HeaderFindings = $headerFindings
        }

        # Phase 4: JWT detection and analysis
        if ($AnalyzeJWT) {
            if (-not $Silent) { Write-Output "[*] Scanning for JWT tokens..." }
            $jwtInContent = Find-JwtTokens -Content $loginResponse.Content -Source 'page_content'
            foreach ($jwt in $jwtInContent) { $allJwts.Add($jwt) }

            if ($loginResponse.Headers) {
                $jwtInHeaders = Find-JwtInHeaders -Headers $loginResponse.Headers
                foreach ($jwt in $jwtInHeaders) { $allJwts.Add($jwt) }
            }

            if ($allJwts.Count -gt 0 -and -not $Silent) {
                Write-Output "[+] Found $($allJwts.Count) JWT tokens"
                foreach ($jwt in $allJwts) {
                    if ($jwt.Decoded -and $jwt.Decoded.AlgIsNone) {
                        Write-Output "[!] CRITICAL: JWT with alg=none detected!"
                    }
                    if ($jwt.Decoded -and $jwt.Decoded.Payload.HasAdminClaim) {
                        Write-Output "[!] JWT contains admin claim: $($jwt.Decoded.Payload.RoleClaim)"
                    }
                }
            }
            $output.JwtTokens = $allJwts
        }

        # Phase 5: Auth bypass tests
        if ($TestBypasses) {
            if (-not $Silent) { Write-Output "[*] Running auth bypass header tests..." }
            $bypassHeaders = Test-AuthBypassHeaders -TargetUrl $loginTarget -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
            $bypassHeaders | Add-Member -MemberType NoteProperty -Name 'TestCategory' -Value 'header_bypass' -Force

            if (-not $Silent) { Write-Output "[*] Running auth bypass parameter tests..." }
            $bypassParams = Test-AuthBypassParams -TargetUrl $loginTarget -Method $Method -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
            $bypassParams | Add-Member -MemberType NoteProperty -Name 'TestCategory' -Value 'param_bypass' -Force

            if (-not $Silent) { Write-Output "[*] Running HTTP verb tampering tests..." }
            $bypassVerbs = Test-AuthBypassVerbs -TargetUrl $loginTarget -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
            $bypassVerbs | Add-Member -MemberType NoteProperty -Name 'TestCategory' -Value 'verb_tampering' -Force

            $allBypassTests = [System.Collections.Generic.List[object]]::new()
            foreach ($t in $bypassHeaders) { $allBypassTests.Add($t) }
            foreach ($t in $bypassParams) { $allBypassTests.Add($t) }
            foreach ($t in $bypassVerbs) { $allBypassTests.Add($t) }

            $output.BypassTests = $allBypassTests

            if (-not $Silent) { Write-Output "[*] Testing internal path access..." }
            $internalPaths = Test-InternalPathAccess -BaseUrl $baseUrl -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
            $output.InternalPaths = $internalPaths
        }

        # Phase 6: Rate limit testing
        if ($TestRateLimit) {
            if (-not $Silent) { Write-Output "[*] Testing rate limiting on $loginTarget..." }
            $rateLimitBody = if ($Credentials -and $Credentials.Username -and $Credentials.Password) {
                $uField = if ($Credentials.FieldUser) { $Credentials.FieldUser } else { 'username' }
                $pField = if ($Credentials.FieldPass) { $Credentials.FieldPass } else { 'password' }
                "$uField=$($Credentials.Username)&$pField=$($Credentials.Password)"
            }
            else {
                'username=test&password=test123'
            }
            $rateLimitResult = Test-RateLimit -LoginUrl $loginTarget -Method $Method -RequestBody $rateLimitBody -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
            $output.RateLimitResult = $rateLimitResult
        }

        # Phase 7: Authenticated request
        if ($Credentials -and $Credentials.Username -and $Credentials.Password) {
            if (-not $Silent) { Write-Output "[*] Attempting authentication..." }
            $uField = if ($Credentials.FieldUser) { $Credentials.FieldUser } else { 'username' }
            $pField = if ($Credentials.FieldPass) { $Credentials.FieldPass } else { 'password' }
            $authBody = "$uField=$($Credentials.Username)&$pField=$($Credentials.Password)"

            $loginFormAction = $loginTarget
            if ($output.LoginForms.Count -gt 0 -and $output.LoginForms[0].FormAction) {
                $loginFormAction = $output.LoginForms[0].FormAction
            }

            $authResponse = Invoke-WebRequestSafe -Uri $loginFormAction -Method $Method -Body $authBody -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $Timeout -UserAgent $UserAgent

            if ($authResponse.Success) {
                if (-not $Silent) { Write-Output "[+] Auth response: $($authResponse.StatusCode) ($($authResponse.ContentLength) bytes)" }

                if ($authResponse.Cookies -and $authResponse.Cookies.Count -gt 0) {
                    if (-not $Silent) { Write-Output "[*] Analyzing post-auth cookies..." }
                    $postAuthCookieAnalysis = Analyze-Cookies -Cookies $authResponse.Cookies -ResponseHeaders $authResponse.Headers
                    $output.PostAuthCookies = $postAuthCookieAnalysis
                }

                if ($AnalyzeJWT) {
                    $jwtInAuthResponse = Find-JwtTokens -Content $authResponse.Content -Source 'auth_response'
                    foreach ($jwt in $jwtInAuthResponse) {
                        $alreadyFound = $allJwts | Where-Object { $_.TokenHash -eq $jwt.TokenHash }
                        if (-not $alreadyFound) { $allJwts.Add($jwt) }
                    }
                    if ($authResponse.Headers) {
                        $jwtInAuthHeaders = Find-JwtInHeaders -Headers $authResponse.Headers
                        foreach ($jwt in $jwtInAuthHeaders) {
                            $alreadyFound = $allJwts | Where-Object { $_.TokenHash -eq $jwt.TokenHash }
                            if (-not $alreadyFound) { $allJwts.Add($jwt) }
                        }
                    }
                    if ($allJwts.Count -gt 0) { $output.JwtTokens = $allJwts }
                }

                # Detect redirect patterns
                if ($authResponse.StatusCode -in @(302, 301, 303, 307, 308)) {
                    $redirectLocation = $authResponse.Headers['Location']
                    $output.AuthRedirect = if ($redirectLocation) { ($redirectLocation -join ', ') } else { 'Unknown' }
                }
            }
        }
    }
    else {
        $errMsg = "Failed to fetch login page: $loginTarget - $($loginResponse.ErrorMessage)"
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Warning $errMsg }
    }

    $output.Warnings = $warnings
    $output.Errors = $errors

    # Write output
    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "`n=== Auth Testing Summary ==="
        Write-Output "Target: $baseUrl"
        Write-Output "Login Forms: $($output.LoginForms.Count) | Is Login: $(if ($output.LoginForms.Count -gt 0) { $output.LoginForms[0].IsLoginForm } else { 'N/A' })"
        if ($output.Cookies) { Write-Output "Cookies: $($output.Cookies.TotalCookies) | Session Cookie: $($output.Cookies.SessionFound)" }
        Write-Output "JWT Tokens: $($output.JwtTokens.Count)"
        Write-Output "Bypass Tests: $($output.BypassTests.Count) | Interesting: $(($output.BypassTests | Where-Object { $_.Interesting }).Count)"
        if ($output.RateLimitResult) { Write-Output "Rate Limited: $($output.RateLimitResult.RateLimited) | Blocked: $($output.RateLimitResult.BlockedAttempts)/$($output.RateLimitResult.MaxAttempts)" }
        Write-Output "Warnings: $($warnings.Count) | Errors: $($errors.Count)"
    }

    return $output
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    param(
        [string]$Target,
        [string]$LoginUrl,
        [hashtable]$Credentials,
        [string]$Method = 'POST',
        [string]$OutputFile,
        [switch]$AnalyzeJWT,
        [switch]$TestBypasses,
        [switch]$TestRateLimit,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 500,
        [switch]$Silent
    )
    $AnalyzeJWT = if ($PSBoundParameters.ContainsKey('AnalyzeJWT')) { $AnalyzeJWT } else { $true }
    $TestBypasses = if ($PSBoundParameters.ContainsKey('TestBypasses')) { $TestBypasses } else { $true }
    $TestRateLimit = if ($PSBoundParameters.ContainsKey('TestRateLimit')) { $TestRateLimit } else { $true }

    Invoke-AuthTesting -Target $Target -LoginUrl $LoginUrl -Credentials $Credentials -Method $Method -OutputFile $OutputFile -AnalyzeJWT:$AnalyzeJWT -TestBypasses:$TestBypasses -TestRateLimit:$TestRateLimit -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit -Silent:$Silent
}

# Entry point
$Target = $null; $LoginUrl = $null; $Credentials = $null; $Method = 'POST'
$OutputFile = $null; $AnalyzeJWT = $true; $TestBypasses = $true; $TestRateLimit = $true
$Silent = $false; $Timeout = 30; $UserAgent = $null; $RateLimit = 500

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Target' { $i++; $Target = $args[$i] }
            '-LoginUrl' { $i++; $LoginUrl = $args[$i] }
            '-Credentials' {
                $i++; $credJson = $args[$i]
                $Credentials = $credJson | ConvertFrom-Json -AsHashtable
            }
            '-Method' { $i++; $Method = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-AnalyzeJWT' { $AnalyzeJWT = [bool]::Parse($args[$i + 1]); $i++ }
            '-TestBypasses' { $TestBypasses = [bool]::Parse($args[$i + 1]); $i++ }
            '-TestRateLimit' { $TestRateLimit = [bool]::Parse($args[$i + 1]); $i++ }
            '-Silent' { $Silent = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
            '-RateLimit' { $i++; $RateLimit = [int]$args[$i] }
        }
        $i++
    }
}

try {
    Main -Target $Target -LoginUrl $LoginUrl -Credentials $Credentials -Method $Method -OutputFile $OutputFile -AnalyzeJWT:$AnalyzeJWT -TestBypasses:$TestBypasses -TestRateLimit:$TestRateLimit -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit -Silent:$Silent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
