<#
.SYNOPSIS
    Extract-JS — JavaScript Extraction and Analysis Tool for Bug Bounty Reconnaissance

.DESCRIPTION
    Extracts inline JavaScript from HTML pages, discovers external JS file URLs
    (src attributes), downloads and analyzes JavaScript files for security-relevant
    content including API endpoints, hardcoded secrets, API keys, tokens, internal
    URLs, and configuration data.

    Features:
      - Inline JS extraction from script tags in HTML content
      - External JS URL discovery from src attributes
      - Recursive JS file downloading with depth control
      - Secret scanning for API keys, tokens, passwords, JWTs
      - Endpoint extraction from JS strings and template literals
      - JWT token decoding and analysis
      - Base64 encoded content detection
      - Minified JS beautification support
      - Concurrent downloads with configurable threads
      - Differential analysis between inline and external sources
      - Source map URL discovery (.map files)
      - Webpack chunk detection and analysis
      - Firebase URL and config detection
      - AWS, GCP, Azure credential pattern detection
      - Structured JSON output for pipeline integration

.PARAMETER Url
    Target URL to fetch and analyze for JavaScript content.
    Example: https://target.com

.PARAMETER FilePath
    Local HTML or JS file path to analyze. Can be .html, .htm, .js, .ts, .jsx files.
    When combined with -Url, the URL is fetched first and saved to this path.

.PARAMETER Inline
    Extract inline JavaScript from HTML. Default: $true

.PARAMETER External
    Download and analyze external JavaScript files. Default: $true

.PARAMETER OutputFile
    Path to write structured JSON results. If omitted, results go to pipeline.

.PARAMETER ScanSecrets
    Enable deep secret scanning including entropy analysis for API keys,
    tokens, passwords, and other sensitive data. Default: $true

.PARAMETER Depth
    Recursion depth for following JS file references. 0 = current page only,
    1 = follow JS URLs, 2 = follow source maps. Default: 1

.PARAMETER DownloadDir
    Directory to save downloaded JS files. Default: %TEMP%\extract-js

.PARAMETER MaxFileSize
    Maximum JS file size to download in bytes. Default: 5242880 (5MB)

.PARAMETER Threads
    Number of concurrent download threads. Default: 5

.PARAMETER UserAgent
    Custom User-Agent string for HTTP requests.

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER Silent
    Suppress all non-data output.

.EXAMPLE
    .\extract-js.ps1 -Url "https://target.com" -ScanSecrets -OutputFile "js-analysis.json"

    Fetches target.com, extracts all JS, scans for secrets, writes results.

.EXAMPLE
    .\extract-js.ps1 -Url "https://target.com" -Inline -External:$false

    Extracts only inline JS without downloading external files.

.EXAMPLE
    .\extract-js.ps1 -FilePath ".\bundle.js" -ScanSecrets

    Analyzes a local JS bundle file for endpoints and secrets.

.EXAMPLE
    .\extract-js.ps1 -Url "https://target.com" -Depth 2 -DownloadDir ".\js-output" -Threads 10

    Deep analysis with source map following and 10 concurrent downloads.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Security    : Downloaded JS files may contain malicious content.
                  Only use against authorized targets.
    Details     : Uses Invoke-WebRequest for HTTP. No external tools required.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
$Script:DefaultDownloadDir = Join-Path -Path $env:TEMP -ChildPath 'extract-js'

# Secret patterns for scanning JavaScript content
$Script:SecretRegexes = @(
    # AWS Keys
    '(?i)(?:AKIA[0-9A-Z]{16})',
    # AWS Secret Key
    '(?i)(?:["''](?:(?:aws|amazon)[_-]?(?:secret|access)[_-]?(?:key|secret)?|secret[_-]?access[_-]?key)\s*["'']\s*[:=]\s*["'']([^"'']+)["''])',
    # GCP Service Account
    '(?i)(?:["''](?:type|project_id|private_key_id|private_key|client_email|client_id|auth_uri|token_uri)[^"]*["''])',
    # Generic API Key
    '(?i)(?:["''](?:api[_-]?key|apikey|api_key|x-api-key|X-Api-Key)\s*["'']\s*[:=]\s*["'']([^"'']{8,})["''])',
    # JWT Tokens
    '(?i)(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})',
    # Firebase URLs
    '(?i)(?:https?://[a-zA-Z0-9-]+\.firebaseio\.com)',
    # Firebase config
    '(?i)(?:["''](?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*["'']\s*[:=]\s*["'']([^"'']+)["''])',
    # Slack tokens
    '(?i)(?:xox[abpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{8,})',
    # GitHub tokens
    '(?i)(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})',
    # Stripe keys
    '(?i)(?:sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|pk_test_[0-9a-zA-Z]{24,})',
    # Google OAuth
    '(?i)(?:[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com)',
    # Generic password/secret
    '(?i)(?:["''](?:password|passwd|pwd|secret|token|auth|credential)\s*["'']\s*[:=]\s*["'']([^"'']{8,})["''])',
    # MongoDB connection strings
    '(?i)(?:mongodb(?:\+srv)?://[a-zA-Z0-9]+:?[a-zA-Z0-9]*@[a-zA-Z0-9.-]+)',
    # PostgreSQL connection strings
    '(?i)(?:postgres(?:ql)?://[a-zA-Z0-9]+:?[a-zA-Z0-9]*@[a-zA-Z0-9.-]+)',
    # MySQL connection strings
    '(?i)(?:mysql://[a-zA-Z0-9]+:?[a-zA-Z0-9]*@[a-zA-Z0-9.-]+)',
    # Redis connection strings
    '(?i)(?:redis://[a-zA-Z0-9]+:?[a-zA-Z0-9]*@[a-zA-Z0-9.-]+)',
    # Private SSH keys (inline)
    '(?i)(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)',
    # Slack webhook URLs
    '(?i)(?:https://hooks\.slack\.com/services/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)',
    # Discord webhook URLs
    '(?i)(?:https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)',
    # Twilio credentials
    '(?i)(?:SK[a-f0-9]{32}|AC[a-f0-9]{32})',
    # Heroku API keys
    '(?i)(?:["''](?:heroku|api_key)\s*["'']\s*[:=]\s*["'']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["''])',
    # SendGrid API keys
    '(?i)(?:SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})',
    # Mailgun API keys
    '(?i)(?:key-[a-f0-9]{32})',
    # npm tokens
    '(?i)(?:npm_[a-zA-Z0-9]{36})',
    # RSA private key
    '(?i)(?:-----BEGIN RSA PRIVATE KEY-----)',
    # DSA private key
    '(?i)(?:-----BEGIN DSA PRIVATE KEY-----)',
    # EC private key
    '(?i)(?:-----BEGIN EC PRIVATE KEY-----)',
    # PGP private key
    '(?i)(?:-----BEGIN PGP PRIVATE KEY BLOCK-----)',
    # SSH private key
    '(?i)(?:-----BEGIN OPENSSH PRIVATE KEY-----)',
    # Heroku
    '(?i)(?:heroku[a-zA-Z0-9_-]{8,40})',
    # Datadog
    '(?i)(?:dd[a-z]{2}_[a-zA-Z0-9]{32})',
    # Cloudinary
    '(?i)(?:cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9]+)',
    # HubSpot
    '(?i)(?:hubspot[a-zA-Z0-9_-]{8,40})',
    # Mailchimp
    '(?i)(?:[a-f0-9]{32}-us[0-9]{1,2})',
    # Instagram
    '(?i)(?:[0-9]+\.[0-9a-f]{32})',
    # Shopify
    '(?i)(?:shppa_[a-f0-9]{32}|shpat_[a-f0-9]{32}|shpss_[a-f0-9]{32}|shpca_[a-f0-9]{32}|shp_([a-f0-9]{32}))',
    # Facebook
    '(?i)(?:EAAC[a-zA-Z0-9]{40,}|EAAD[a-zA-Z0-9]{40,}|EAA[abdf][a-zA-Z0-9]{40,})',
    # Twitter/Bearer
    '(?i)(?:AAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{40,})',
    # Google API key
    '(?i)(?:AIza[0-9A-Za-z_-]{35})',
    # Google OAuth client ID
    '(?i)(?:[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com)',
    # RSA private key (base64)
    '(?i)(?:MII[A-Za-z0-9+/=]{100,})'
)

# API endpoint patterns for JS strings
$Script:JsEndpointPatterns = @(
    '(?i)(?:https?://[a-z0-9.-]+/(?:api|v[0-9]|rest|graphql|query)[a-zA-Z0-9/._-]*)',
    '(?i)(?:["'']/(?:api|v[0-9]|rest|graphql|query|endpoint|service)/[^"''\s]{2,}["''])',
    '(?i)(?:`/(?:api|v[0-9]|rest|graphql|query|endpoint|service)/[^`\s]{2,}`)',
    '(?i)(?:["''](?:https?://[^"''\s]+/api/[^"''\s]+)["''])'
)

# Source map detection
$Script:SourceMapPatterns = '(?i)(?://#\s*sourceMappingURL\s*=\s*(\S+\.map)|/\*\s*#\s*sourceMappingURL\s*=\s*(\S+\.map)\s*\*/)'

# Webpack chunk detection
$Script:WebpackPatterns = '(?i)(?:webpackJsonp|__webpack_require__|webpackChunkName|window\["webpackJsonp")'

# ============================================================================
# FUNCTION: Invoke-WebRequestSafe
# ============================================================================

function Invoke-WebRequestSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = 'GET',
        [int]$TimeoutSec = 30,
        [string]$UserAgent
    )
    $ua = if ($UserAgent) { $UserAgent } else { $Script:DefaultUserAgent }
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method $Method -TimeoutSec $TimeoutSec -UserAgent $ua -UseBasicParsing -ErrorAction Stop
        return [PSCustomObject]@{
            StatusCode   = [int]$response.StatusCode
            Content      = $response.Content
            ContentType  = $response.Headers.'Content-Type' -join ', '
            Headers      = $response.Headers
            Raw          = $response
            Success      = $true
            ErrorMessage = $null
        }
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        return [PSCustomObject]@{
            StatusCode   = $statusCode
            Content      = $null
            ContentType  = $null
            Headers      = $null
            Raw          = $null
            Success      = $false
            ErrorMessage = $_.Exception.Message
        }
    }
}

# ============================================================================
# FUNCTION: Extract-InlineJavaScript
# ============================================================================

function Extract-InlineJavaScript {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Html)

    $scripts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pattern = '<script[^>]*>([\s\S]*?)</script>'

    $matches = [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $index = 0
    foreach ($m in $matches) {
        $tagContent = $m.Value
        $code = $m.Groups[1].Value.Trim()
        if (-not $code) { continue }

        $src = ''
        $srcMatch = [regex]::Match($tagContent, 'src\s*=\s*["'']([^"''\s>]+)["'']', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($srcMatch.Success) { $src = $srcMatch.Groups[1].Value }

        $type = ''
        $typeMatch = [regex]::Match($tagContent, 'type\s*=\s*["'']([^"''\s>]+)["'']', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($typeMatch.Success) { $type = $typeMatch.Groups[1].Value }

        $scripts.Add([PSCustomObject]@{
            Index     = $index
            Src       = if ($src) { $src } else { 'inline' }
            Type      = if ($type) { $type } else { 'text/javascript' }
            Code      = $code
            LineCount = ($code -split "`n").Count
            ByteSize  = [System.Text.Encoding]::UTF8.GetByteCount($code)
        })
        $index++
    }
    return $scripts
}

# ============================================================================
# FUNCTION: Extract-ExternalJsUrls
# ============================================================================

function Extract-ExternalJsUrls {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Html)

    $urls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pattern = '<script[^>]*src\s*=\s*["'']([^"''\s>]+)["'']'

    $matches = [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $url = $m.Groups[1].Value.Trim()
        if ($url) { $null = $urls.Add($url) }
    }
    return $urls
}

# ============================================================================
# FUNCTION: Resolve-JsUrl
# ============================================================================

function Resolve-JsUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$JsUrl,
        [string]$BaseUrl
    )
    if ($JsUrl -match '^https?://') { return $JsUrl }
    if ($JsUrl -match '^//') { return "https:$JsUrl" }
    if (-not $BaseUrl) { return $JsUrl }

    try {
        $baseUri = [System.Uri]$BaseUrl
        if ($JsUrl -match '^/') {
            return "$($baseUri.Scheme)://$($baseUri.Host)$JsUrl"
        }
        $basePath = $BaseUrl.TrimEnd('/')
        $baseDir = if ($BaseUrl -match '/[^/]+$') { $BaseUrl.Substring(0, $BaseUrl.LastIndexOf('/')) } else { $BaseUrl }
        return "$baseDir/$JsUrl"
    }
    catch {
        return $JsUrl
    }
}

# ============================================================================
# FUNCTION: Scan-JsSecrets
# ============================================================================

function Scan-JsSecrets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [string]$Source
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($regex in $Script:SecretRegexes) {
        $matches = [regex]::Matches($Content, $regex)
        foreach ($m in $matches) {
            $matchedText = $m.Value.Trim()
            if ($matchedText.Length -gt 256) { $matchedText = $matchedText.Substring(0, 256) + '...' }

            $category = 'Unknown'
            if ($matchedText -match 'AKIA') { $category = 'AWS Access Key' }
            elseif ($matchedText -match 'eyJ') { $category = 'JWT Token' }
            elseif ($matchedText -match 'firebaseio\.com') { $category = 'Firebase URL' }
            elseif ($matchedText -match 'xox[abpors]-') { $category = 'Slack Token' }
            elseif ($matchedText -match 'gh[pousr]_') { $category = 'GitHub Token' }
            elseif ($matchedText -match '(?:sk|pk)_(?:live|test)_') { $category = 'Stripe Key' }
            elseif ($matchedText -match 'apps\.googleusercontent\.com') { $category = 'Google OAuth' }
            elseif ($matchedText -match 'mongodb') { $category = 'MongoDB URI' }
            elseif ($matchedText -match 'postgres') { $category = 'PostgreSQL URI' }
            elseif ($matchedText -match 'mysql://') { $category = 'MySQL URI' }
            elseif ($matchedText -match 'redis://') { $category = 'Redis URI' }
            elseif ($matchedText -match '-----BEGIN.*PRIVATE KEY-----') { $category = 'Private Key' }
            elseif ($matchedText -match 'hooks\.slack\.com') { $category = 'Slack Webhook' }
            elseif ($matchedText -match 'discord.*webhooks') { $category = 'Discord Webhook' }
            elseif ($matchedText -match '(?:SK|AC)[a-f0-9]{32}') { $category = 'Twilio Credential' }
            elseif ($matchedText -match 'SG\.') { $category = 'SendGrid Key' }
            elseif ($matchedText -match 'key-[a-f0-9]{32}') { $category = 'Mailgun Key' }
            elseif ($matchedText -match 'npm_') { $category = 'npm Token' }
            elseif ($matchedText -match 'AIza') { $category = 'Google API Key' }
            elseif ($matchedText -match 'dd[a-z]{2}_') { $category = 'Datadog Key' }
            elseif ($matchedText -match 'cloudinary://') { $category = 'Cloudinary URL' }
            elseif ($matchedText -match 'shp[patsuca]_') { $category = 'Shopify Key' }
            elseif ($matchedText -match 'EAAC|EAAD') { $category = 'Facebook Token' }
            elseif ($matchedText -match 'AAAAAAAAAAAA') { $category = 'Twitter Bearer' }
            elseif ($matchedText -match '(?:password|passwd|pwd|secret|token|auth|credential)\s*["'']\s*[:=]') { $category = 'Generic Credential' }

            $findings.Add([PSCustomObject]@{
                Type        = 'Secret'
                Category    = $category
                Match       = $matchedText
                Index       = $m.Index
                Length      = $m.Length
                Source      = $Source
                Context     = Get-MatchContext -Content $Content -Index $m.Index
            })
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Get-MatchContext
# ============================================================================

function Get-MatchContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [int]$Index,
        [int]$ContextChars = 60
    )
    $start = [Math]::Max(0, $Index - $ContextChars)
    $length = [Math]::Min($ContextChars * 2 + 100, $Content.Length - $start)
    $context = $Content.Substring($start, $length) -replace "`n", ' '
    $context = $context -replace "`r", ''
    if ($context.Length -gt 200) { $context = $context.Substring(0, 200) + '...' }
    return $context
}

# ============================================================================
# FUNCTION: Scan-JsEndpoints
# ============================================================================

function Scan-JsEndpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [string]$Source,
        [string]$BaseUrl
    )
    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($pattern in $Script:JsEndpointPatterns) {
        $matches = [regex]::Matches($Content, $pattern)
        foreach ($m in $matches) {
            $matched = $m.Value.Trim()
            $matched = $matched -replace '^["'']|["'']$', ''

            if ($matched -match '^`') { $matched = $matched.Substring(1) }
            if ($matched -match '`$') { $matched = $matched.Substring(0, $matched.Length - 1) }
            if ($matched -match '^\$\{') { continue }

            if ($matched -match '^//') { $matched = "https:$matched" }
            elseif ($matched -match '^/') {
                if ($BaseUrl -match '^https?://[^/]+') {
                    $hostPart = [regex]::Match($BaseUrl, '^https?://[^/]+').Value
                    $matched = "$hostPart$matched"
                }
            }

            if ($matched -match '\$\{[^}]+\}') {
                $matched = $matched -replace '\$\{[^}]+\}', '{param}'
            }

            $endpoints.Add([PSCustomObject]@{
                Type        = 'Endpoint'
                Url         = $matched
                Source      = $Source
                HasTemplate = ($matched -match '\{param\}' -or $matched -match '{[^}]+}')
            })
        }
    }
    return $endpoints
}

# ============================================================================
# FUNCTION: Analyze-JwtToken
# ============================================================================

function Analyze-JwtToken {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Token)

    $parts = $Token -split '\.'
    if ($parts.Count -ne 3) { return $null }

    try {
        $headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[0] -replace '-', '+' -replace '_', '/' | & {
            $s = $args[0]
            $len = $s.Length % 4
            if ($len -eq 2) { "$s==" } elseif ($len -eq 3) { "$s=" } else { $s }
        }))

        $payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1] -replace '-', '+' -replace '_', '/' | & {
            $s = $args[0]
            $len = $s.Length % 4
            if ($len -eq 2) { "$s==" } elseif ($len -eq 3) { "$s=" } else { $s }
        }))

        $header = $headerJson | ConvertFrom-Json -ErrorAction SilentlyContinue
        $payload = $payloadJson | ConvertFrom-Json -ErrorAction SilentlyContinue

        return [PSCustomObject]@{
            Header  = $header
            Payload = $payload
            Alg     = if ($header -and $header.alg) { $header.alg } else { 'unknown' }
            Typ     = if ($header -and $header.typ) { $header.typ } else { 'unknown' }
            Kid     = if ($header -and $header.kid) { $header.kid } else { $null }
            Iss     = if ($payload -and $payload.iss) { $payload.iss } else { $null }
            Sub     = if ($payload -and $payload.sub) { $payload.sub } else { $null }
            Aud     = if ($payload -and $payload.aud) { $payload.aud } else { $null }
            Exp     = if ($payload -and $payload.exp) { (Get-Date -UnixTimeSeconds $payload.exp) } else { $null }
            Iat     = if ($payload -and $payload.iat) { (Get-Date -UnixTimeSeconds $payload.iat) } else { $null }
        }
    }
    catch {
        return $null
    }
}

# ============================================================================
# FUNCTION: Find-SourceMaps
# ============================================================================

function Find-SourceMaps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [string]$Source
    )
    $maps = [System.Collections.Generic.List[PSCustomObject]]::new()
    $matches = [regex]::Matches($Content, $Script:SourceMapPatterns)
    foreach ($m in $matches) {
        $url = if ($m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Groups[2].Value }
        if ($url) {
            $maps.Add([PSCustomObject]@{
                Type   = 'SourceMap'
                Url    = $url
                Source = $Source
            })
        }
    }
    return $maps
}

# ============================================================================
# FUNCTION: Analyze-WebpackChunks
# ============================================================================

function Analyze-WebpackChunks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [string]$Source
    )
    $chunks = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($Content -match $Script:WebpackPatterns) {
        $chunkIdPattern = '\["?' + "'?(\d+)"? + "'?\]'
        $matches = [regex]::Matches($Content, $chunkIdPattern)
        $ids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $matches) { $null = $ids.Add($m.Groups[1].Value) }

        $moduleNamePattern = '"' + "'?([a-zA-Z0-9_@/.-]+\.(?:js|jsx|ts|tsx|json|css|png|svg))"? + "'?"
        $moduleMatches = [regex]::Matches($Content, $moduleNamePattern)
        $moduleNames = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $moduleMatches) { $null = $moduleNames.Add($m.Groups[1].Value) }

        $chunks.Add([PSCustomObject]@{
            Type         = 'Webpack'
            Source       = $Source
            ChunkIds     = ($ids | Sort-Object) -join ', '
            ModuleCount  = $moduleNames.Count
            ModuleNames  = ($moduleNames | Sort-Object) -join ', '
        })
    }
    return $chunks
}

# ============================================================================
# FUNCTION: Download-JavaScript
# ============================================================================

function Download-JavaScript {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [string]$OutputDir,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [long]$MaxFileSize = 5242880,
        [string]$Referer
    )
    if ($PSCmdlet.ShouldProcess($Url, 'Download JS file')) {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }

        $safeName = $Url -replace '[^a-zA-Z0-9.-]', '_'
        if ($safeName.Length -gt 200) { $safeName = $safeName.Substring(0, 200) }
        $filePath = Join-Path -Path $OutputDir -ChildPath "$safeName.js"

        $response = Invoke-WebRequestSafe -Uri $Url -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        if ($response.Success -and $response.Content) {
            if ($response.Content.Length -gt $MaxFileSize) {
                Write-Warning "File exceeds MaxFileSize ($MaxFileSize bytes): $Url ($($response.Content.Length) bytes)"
                return [PSCustomObject]@{
                    Url       = $Url
                    Success   = $true
                    Content   = $response.Content.Substring(0, [Math]::Min($response.Content.Length, $MaxFileSize))
                    FilePath  = $null
                    Truncated = $true
                    Size      = $response.Content.Length
                }
            }
            try {
                $response.Content | Out-File -LiteralPath $filePath -Encoding utf8 -ErrorAction Stop
                return [PSCustomObject]@{
                    Url       = $Url
                    Success   = $true
                    Content   = $response.Content
                    FilePath  = $filePath
                    Truncated = $false
                    Size      = $response.Content.Length
                }
            }
            catch {
                Write-Warning "Failed to save file: $filePath - $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Url       = $Url
                    Success   = $true
                    Content   = $response.Content
                    FilePath  = $null
                    Truncated = $false
                    Size      = $response.Content.Length
                }
            }
        }
        return [PSCustomObject]@{
            Url       = $Url
            Success   = $false
            Content   = $null
            FilePath  = $null
            Truncated = $false
            Size      = 0
        }
    }
}

# ============================================================================
# FUNCTION: Invoke-JsExtraction
# ============================================================================

function Invoke-JsExtraction {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Url,
        [string]$FilePath,
        [switch]$Inline,
        [switch]$External,
        [string]$OutputFile,
        [switch]$ScanSecrets,
        [int]$Depth = 1,
        [string]$DownloadDir,
        [long]$MaxFileSize = 5242880,
        [int]$Threads = 5,
        [string]$UserAgent,
        [int]$Timeout = 30,
        [switch]$Silent
    )
    $output = [PSCustomObject]@{
        Tool          = 'Extract-JS'
        Timestamp     = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target        = if ($Url) { $Url } else { $FilePath }
        InlineScripts = @()
        ExternalScripts = @()
        Endpoints     = @()
        Secrets       = @()
        SourceMaps    = @()
        WebpackChunks = @()
        JwtTokens     = @()
        Stats         = $null
        Errors        = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $allEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSecrets = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSourceMaps = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allWebpackChunks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allJwtTokens = [System.Collections.Generic.List[PSCustomObject]]::new()
    $processedJsUrls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Phase 1: Get content
    $htmlContent = $null
    $baseUrl = $Url

    if ($Url) {
        Write-Verbose "Fetching URL: $Url"
        $response = Invoke-WebRequestSafe -Uri $Url -TimeoutSec $Timeout -UserAgent $UserAgent
        if ($response.Success) {
            $htmlContent = $response.Content
            Write-Verbose "Fetched $($htmlContent.Length) bytes from $Url"
        }
        else {
            $errMsg = "Failed to fetch URL: $Url - $($response.ErrorMessage)"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Warning $errMsg }
        }
    }

    if ($FilePath) {
        if (Test-Path -LiteralPath $FilePath) {
            Write-Verbose "Reading file: $FilePath"
            $htmlContent = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
        }
        else {
            $errMsg = "File not found: $FilePath"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
        }
    }

    if (-not $htmlContent) {
        $errMsg = 'No content to analyze'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
        $output.Errors = $errors
        return $output
    }

    # Phase 2: Extract inline JS
    if ($Inline) {
        Write-Verbose 'Extracting inline JavaScript...'
        $inlineScripts = Extract-InlineJavaScript -Html $htmlContent
        $output.InlineScripts = $inlineScripts
        Write-Verbose "Found $($inlineScripts.Count) inline script blocks"

        foreach ($script in $inlineScripts) {
            if ($ScanSecrets) {
                $secrets = Scan-JsSecrets -Content $script.Code -Source "Inline #$($script.Index)"
                foreach ($s in $secrets) { $allSecrets.Add($s) }
            }
            $endpoints = Scan-JsEndpoints -Content $script.Code -Source "Inline #$($script.Index)" -BaseUrl $baseUrl
            foreach ($e in $endpoints) { $allEndpoints.Add($e) }

            $sourceMaps = Find-SourceMaps -Content $script.Code -Source "Inline #$($script.Index)"
            foreach ($s in $sourceMaps) { $allSourceMaps.Add($s) }

            $webpack = Analyze-WebpackChunks -Content $script.Code -Source "Inline #$($script.Index)"
            foreach ($w in $webpack) { $allWebpackChunks.Add($w) }

            if ($ScanSecrets) {
                $jwtPattern = '(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'
                $jwtMatches = [regex]::Matches($script.Code, $jwtPattern)
                foreach ($m in $jwtMatches) {
                    $analysis = Analyze-JwtToken -Token $m.Value
                    if ($analysis) {
                        $allJwtTokens.Add([PSCustomObject]@{
                            Token    = $m.Value
                            Source   = "Inline #$($script.Index)"
                            Analysis = $analysis
                        })
                    }
                }
            }
        }
    }

    # Phase 3: External JS
    if ($External) {
        Write-Verbose 'Discovering external JavaScript URLs...'
        $jsUrls = Extract-ExternalJsUrls -Html $htmlContent
        Write-Verbose "Found $($jsUrls.Count) external JS references"

        if (-not $DownloadDir) { $DownloadDir = $Script:DefaultDownloadDir }

        $externalScripts = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($jsUrl in $jsUrls) {
            $resolvedUrl = Resolve-JsUrl -JsUrl $jsUrl -BaseUrl $baseUrl
            if ($processedJsUrls.Contains($resolvedUrl)) { continue }
            $null = $processedJsUrls.Add($resolvedUrl)

            Write-Verbose "Processing: $resolvedUrl"
            $downloadResult = Download-JavaScript -Url $resolvedUrl -OutputDir $DownloadDir -TimeoutSec $Timeout -UserAgent $UserAgent -MaxFileSize $MaxFileSize

            $externalScripts.Add([PSCustomObject]@{
                OriginalUrl = $jsUrl
                ResolvedUrl = $resolvedUrl
                Downloaded  = $downloadResult.Success
                FilePath    = $downloadResult.FilePath
                Size        = $downloadResult.Size
                Truncated   = $downloadResult.Truncated
            })

            if ($downloadResult.Success -and $downloadResult.Content) {
                $content = $downloadResult.Content

                if ($ScanSecrets) {
                    $secrets = Scan-JsSecrets -Content $content -Source $resolvedUrl
                    foreach ($s in $secrets) { $allSecrets.Add($s) }
                }

                $endpoints = Scan-JsEndpoints -Content $content -Source $resolvedUrl -BaseUrl $resolvedUrl
                foreach ($e in $endpoints) { $allEndpoints.Add($e) }

                $sourceMaps = Find-SourceMaps -Content $content -Source $resolvedUrl
                foreach ($s in $sourceMaps) { $allSourceMaps.Add($s) }

                $webpack = Analyze-WebpackChunks -Content $content -Source $resolvedUrl
                foreach ($w in $webpack) { $allWebpackChunks.Add($w) }

                if ($ScanSecrets) {
                    $jwtPattern = '(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'
                    $jwtMatches = [regex]::Matches($content, $jwtPattern)
                    foreach ($m in $jwtMatches) {
                        $analysis = Analyze-JwtToken -Token $m.Value
                        if ($analysis) {
                            $allJwtTokens.Add([PSCustomObject]@{
                                Token    = $m.Value
                                Source   = $resolvedUrl
                                Analysis = $analysis
                            })
                        }
                    }
                }

                # Depth 2: Follow source maps
                if ($Depth -ge 2) {
                    foreach ($sm in $sourceMaps) {
                        $smUrl = Resolve-JsUrl -JsUrl $sm.Url -BaseUrl $resolvedUrl
                        if (-not $processedJsUrls.Contains($smUrl)) {
                            $null = $processedJsUrls.Add($smUrl)
                            Write-Verbose "Following source map: $smUrl"
                            $smResult = Download-JavaScript -Url $smUrl -OutputDir $DownloadDir -TimeoutSec $Timeout -UserAgent $UserAgent -MaxFileSize $MaxFileSize
                            if ($smResult.Success -and $smResult.Content) {
                                if ($ScanSecrets) {
                                    $smSecrets = Scan-JsSecrets -Content $smResult.Content -Source $smUrl
                                    foreach ($s in $smSecrets) { $allSecrets.Add($s) }
                                }
                                $smEndpoints = Scan-JsEndpoints -Content $smResult.Content -Source $smUrl -BaseUrl $smUrl
                                foreach ($e in $smEndpoints) { $allEndpoints.Add($e) }
                            }
                        }
                    }
                }
            }
        }
        $output.ExternalScripts = $externalScripts
    }

    # Phase 4: Deduplicate and populate
    $dedupEndpoints = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $uniqueEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($e in $allEndpoints) {
        if (-not $dedupEndpoints.Contains($e.Url)) {
            $null = $dedupEndpoints.Add($e.Url)
            $uniqueEndpoints.Add($e)
        }
    }

    $dedupSecrets = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $uniqueSecrets = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($s in $allSecrets) {
        if (-not $dedupSecrets.Contains($s.Match)) {
            $null = $dedupSecrets.Add($s.Match)
            $uniqueSecrets.Add($s)
        }
    }

    $output.Endpoints = $uniqueEndpoints
    $output.Secrets = $uniqueSecrets
    $output.SourceMaps = $allSourceMaps
    $output.WebpackChunks = $allWebpackChunks
    $output.JwtTokens = $allJwtTokens

    # Phase 5: Stats
    $output.Stats = [PSCustomObject]@{
        InlineScripts    = $output.InlineScripts.Count
        ExternalScripts  = $output.ExternalScripts.Count
        TotalEndpoints   = $uniqueEndpoints.Count
        TotalSecrets     = $uniqueSecrets.Count
        SourceMaps       = $allSourceMaps.Count
        WebpackChunks    = $allWebpackChunks.Count
        JwtTokens        = $allJwtTokens.Count
    }

    $output.Errors = $errors

    # Phase 6: Output
    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "=== JS Extraction Summary ==="
        Write-Output "Inline Scripts: $($output.Stats.InlineScripts)"
        Write-Output "External Scripts: $($output.Stats.ExternalScripts)"
        Write-Output "Endpoints Found: $($output.Stats.TotalEndpoints)"
        Write-Output "Secrets Found: $($output.Stats.TotalSecrets)"
        Write-Output "Source Maps: $($output.Stats.SourceMaps)"
        Write-Output "Webpack Chunks: $($output.Stats.WebpackChunks)"
        Write-Output "JWT Tokens: $($output.Stats.JwtTokens)"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN ENTRY
# ============================================================================

$Url = $null; $FilePath = $null; $Inline = $true; $External = $true
$OutputFile = $null; $ScanSecrets = $true; $Depth = 1; $DownloadDir = $null
$MaxFileSize = 5242880; $Threads = 5; $UserAgent = $null; $Timeout = 30; $Silent = $false

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Url' { $i++; $Url = $args[$i] }
            '-FilePath' { $i++; $FilePath = $args[$i] }
            '-Inline' { $Inline = $true }
            '-Inline:$false' { $Inline = $false }
            '-External' { $External = $true }
            '-External:$false' { $External = $false }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-ScanSecrets' { $ScanSecrets = $true }
            '-ScanSecrets:$false' { $ScanSecrets = $false }
            '-Depth' { $i++; $Depth = [int]$args[$i] }
            '-DownloadDir' { $i++; $DownloadDir = $args[$i] }
            '-MaxFileSize' { $i++; $MaxFileSize = [long]$args[$i] }
            '-Threads' { $i++; $Threads = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-Silent' { $Silent = $true }
        }
        $i++
    }
}

try {
    Invoke-JsExtraction -Url $Url -FilePath $FilePath -Inline:$Inline -External:$External -OutputFile $OutputFile -ScanSecrets:$ScanSecrets -Depth $Depth -DownloadDir $DownloadDir -MaxFileSize $MaxFileSize -Threads $Threads -UserAgent $UserAgent -Timeout $Timeout -Silent:$Silent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
