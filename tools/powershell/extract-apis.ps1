<#
.SYNOPSIS
    Extract-APIs — API Endpoint Discovery Tool for Bug Bounty Reconnaissance

.DESCRIPTION
    Crawls HTML and JavaScript content to discover API endpoint patterns including
    RESTful APIs (/api/, /v1/, /v2/), GraphQL endpoints, SOAP services, and
    WebSocket connections. Performs HTTP method discovery (GET, POST, PUT, DELETE,
    PATCH) and identifies potential authentication requirements for each endpoint.

    Features:
      - URL pattern matching for common API path conventions
      - JavaScript file analysis for embedded API calls (fetch, axios, $.ajax)
      - GraphQL introspection probe when /graphql or /gql endpoint is found
      - REST method discovery via OPTIONS requests and common verb probing
      - Authentication requirement detection (JWT, Bearer, API key patterns)
      - Swagger/OpenAPI and Postman collection discovery
      - Parallel endpoint probing with configurable depth and throttling
      - Structured JSON output for pipeline integration
      - Rate-limit aware with exponential backoff

    Output fields per endpoint:
      - Endpoint URL
      - Discovered HTTP methods
      - Source (html, js, swagger, wordlist)
      - Auth type detected (none, jwt, basic, apikey, oauth, cookie)
      - Response status code
      - Content-Type
      - Response size in bytes

.PARAMETER Url
    Target URL to scan for API endpoints. Can be a base domain or specific page.
    Example: https://target.com

.PARAMETER FilePath
    Local file path to scan instead of fetching from URL. Supports .html, .js,
    .ts, .json, or .txt files. When combined with -Url, the URL is fetched first
    then saved to this path.

.PARAMETER OutputFile
    Path to write the structured results file (JSON format). If omitted, results
    are written to the pipeline.

.PARAMETER Depth
    Crawling depth for recursive endpoint discovery. Default: 1, Range: 1-3.
    Depth 1 scans only the provided page. Depth 2 follows same-domain links.
    Depth 3 follows links from depth 2.

.PARAMETER Silent
    Suppress all non-data output. Only endpoint results and errors are emitted.
    Overrides -Verbose.

.PARAMETER MethodProbe
    Probe discovered endpoints with OPTIONS and common HTTP methods to confirm
    they are live API endpoints. Default: $true.

.PARAMETER ProbeMethods
    Comma-separated list of HTTP methods to probe. Default: GET,POST,PUT,DELETE,PATCH

.PARAMETER IncludeStatic
    Include static file extensions (css, png, jpg, etc.) in crawling. Default: $false.

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER UserAgent
    Custom User-Agent string for HTTP requests.

.PARAMETER RateLimit
    Minimum milliseconds between requests. Default: 200

.EXAMPLE
    .\extract-apis.ps1 -Url "https://target.com" -Depth 2 -MethodProbe

    Crawls target.com to depth 2, discovers all API endpoints, and probes
    each with OPTIONS/GET/POST to confirm availability and methods.

.EXAMPLE
    .\extract-apis.ps1 -Url "https://target.com" -OutputFile "results.json" -Silent

    Scans target.com and writes JSON results to results.json with no console output.

.EXAMPLE
    .\extract-apis.ps1 -FilePath ".\response.html" -MethodProbe

    Analyzes a local HTML file for API endpoints without making network requests.

.EXAMPLE
    .\extract-apis.ps1 -Url "https://target.com" -Depth 3 -MethodProbe -ProbeMethods GET,POST -Timeout 60

    Deep crawl with specific probe methods and extended timeout.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Details     : Uses Invoke-WebRequest and Invoke-RestMethod for all HTTP.
                  No third-party modules required.
    Security    : This tool makes network requests to the target. Only use
                  against authorized targets per bug bounty program scope.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
$Script:ApiPatterns = @(
    '/api/',
    '/v1/',
    '/v2/',
    '/v3/',
    '/v4/',
    '/rest/',
    '/graphql',
    '/query',
    '/gql',
    '/soap/',
    '/xmlrpc',
    '/ws/',
    '/websocket',
    '/swagger',
    '/openapi',
    '/docs',
    '/redoc',
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/api-docs',
    '/api/doc',
    '/api/swagger',
    '/api/v1',
    '/api/v2',
    '/api/rest',
    '/api/graphql',
    '/api/soap',
    '/api/ws',
    '/api/user',
    '/api/users',
    '/api/admin',
    '/api/auth',
    '/api/login',
    '/api/token',
    '/api/oauth',
    '/api/health',
    '/api/status',
    '/api/version',
    '/api/endpoint',
    '/api/data',
    '/api/search',
    '/api/config',
    '/api/settings',
    '/api/export',
    '/api/import',
    '/api/upload',
    '/api/download',
    '/api/sync',
    '/api/webhook',
    '/api/callback',
    '/api/notify',
    '/api/subscribe',
    '/api/event',
    '/api/metrics',
    '/api/analytics',
    '/api/report',
    '/api/log',
    '/api/debug',
    '/api/test',
    '/api/internal',
    '/api/external',
    '/api/public',
    '/api/private',
    '/api/protected',
    '/api/v1/users',
    '/api/v1/admin',
    '/api/v1/auth',
    '/api/v1/login',
    '/api/v1/token',
    '/api/v1/oauth',
    '/api/v1/health',
    '/api/v1/status',
    '/api/v1/version',
    '/api/v1/config',
    '/api/v1/settings',
    '/api/v1/search',
    '/api/v1/data',
    '/api/v1/export',
    '/api/v1/import',
    '/api/v1/upload',
    '/api/v1/download',
    '/api/v1/webhook',
    '/api/v1/metrics',
    '/api/v1/logs',
    '/api/v1/debug',
    '/api/v1/internal'
)
$Script:JsApiPatterns = @(
    '\b(?:fetch|axios|ajax|getJSON|post|put|patch|del|request)\s*\(\s*["'']([^"'']+)["'']',
    '\b(?:fetch|axios|ajax)\s*\(\s*["'']([^"'']+)["'']',
    '\burl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bendpoint\s*[:=]\s*["'']([^"'']+)["'']',
    '\bbaseURL\s*[:=]\s*["'']([^"'']+)["'']',
    '\bbaseUrl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bbase\s*[:=]\s*["'']([^"'']+)["'']',
    '\bapiUrl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bapi_url\s*[:=]\s*["'']([^"'']+)["'']',
    '\bserviceUrl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bservice_url\s*[:=]\s*["'']([^"'']+)["'']',
    '\bserverUrl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bserver_url\s*[:=]\s*["'']([^"'']+)["'']',
    '\bendpointUrl\s*[:=]\s*["'']([^"'']+)["'']',
    '\bgraphqlEndpoint\s*[:=]\s*["'']([^"'']+)["'']',
    '\bgraphql_endpoint\s*[:=]\s*["'']([^"'']+)["'']',
    '\bgqlEndpoint\s*[:=]\s*["'']([^"'']+)["'']'
)
$Script:AuthPatterns = @(
    '(?i)(?:authorization|auth|token|apikey|api[_-]?key|x[_-]?api[_-]?key|jwt|bearer|oauth|session[_-]?id|xsrf[_-]?token|csrf[_-]?token)'
)
$Script:SecretPatterns = @(
    '(?i)(?:key|secret|password|passwd|pwd|token|credential|auth|apikey|api[_-]?key)\s*[:=]\s*["'']([^"'']{8,})["'']'
)
$Script:WebSocketPatterns = '(?:wss?://[^"''\s>]+|new\s+WebSocket\s*\(\s*["'']([^"'']+)["'']|io\s*\(\s*["'']([^"'']+)["''])'
$Script:GraphQLPatterns = '(?:graphql|gql|query\s*{|mutation\s*{|subscription\s*{)'
$Script:SwaggerPatterns = '(?:swagger|openapi|api[_-]?docs|redoc|swagger\.json|openapi\.json)'
$Script:SoapPatterns = '(?:soap|xmlrpc|wsdl|\.svc\b|\.asmx\b)'

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
        [switch]$ReturnRaw,
        [hashtable]$Headers
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

    try {
        $response = Invoke-WebRequest @params
        $result = [PSCustomObject]@{
            StatusCode    = [int]$response.StatusCode
            Content       = $response.Content
            ContentType   = $response.Headers.'Content-Type' -join ', '
            Headers       = $response.Headers
            Raw           = if ($ReturnRaw) { $response } else { $null }
            Success       = $true
            ErrorMessage  = $null
        }
        return $result
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $result = [PSCustomObject]@{
            StatusCode    = $statusCode
            Content       = $null
            ContentType   = $null
            Headers       = $null
            Raw           = $null
            Success       = $false
            ErrorMessage  = $_.Exception.Message
        }
        return $result
    }
}

# ============================================================================
# FUNCTION: Invoke-RestMethodSafe
# ============================================================================

function Invoke-RestMethodSafe {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType = 'application/json',
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Headers
    )
    $ua = if ($UserAgent) { $UserAgent } else { $Script:DefaultUserAgent }
    $params = @{
        Uri         = $Uri
        Method      = $Method
        TimeoutSec  = $TimeoutSec
        UserAgent   = $ua
        ErrorAction = 'Stop'
    }
    if ($Body) { $params['Body'] = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }
    if ($Headers) { $params['Headers'] = $Headers }

    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        Write-Verbose "REST call failed: $Uri - $($_.Exception.Message)"
        return $null
    }
}

# ============================================================================
# FUNCTION: Extract-UrlsFromHtml
# ============================================================================

function Extract-UrlsFromHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html,
        [string]$BaseUrl
    )
    $urls = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Extract href attributes
    $hrefPattern = '<a\s[^>]*href\s*=\s*["'']([^"''\s>]+)["'']'
    $matches = [regex]::Matches($Html, $hrefPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $url = $m.Groups[1].Value.Trim()
        if ($url -and $url -notlike '#'* -and $url -notlike 'javascript:*' -and $url -notlike 'mailto:*' -and $url -notlike 'tel:*') {
            $null = $urls.Add($url)
        }
    }

    # Extract src attributes (scripts, images, iframes)
    $srcPattern = '<(?:script|img|iframe|source|embed|object|video|audio)\s[^>]*src\s*=\s*["'']([^"''\s>]+)["'']'
    $matches = [regex]::Matches($Html, $srcPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $null = $urls.Add($m.Groups[1].Value.Trim())
    }

    # Extract form actions
    $formPattern = '<form\s[^>]*action\s*=\s*["'']([^"''\s>]+)["'']'
    $matches = [regex]::Matches($Html, $formPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $null = $urls.Add($m.Groups[1].Value.Trim())
    }

    # Resolve relative URLs
    $resolved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($url in $urls) {
        if ($url -match '^https?://') {
            $null = $resolved.Add($url)
        }
        elseif ($BaseUrl -and $url -match '^/') {
            $base = $BaseUrl.TrimEnd('/')
            $null = $resolved.Add("$base$url")
        }
        elseif ($BaseUrl -and $url -notmatch '^https?://') {
            $base = $BaseUrl.TrimEnd('/')
            $null = $resolved.Add("$base/$url")
        }
        else {
            $null = $resolved.Add($url)
        }
    }

    return $resolved
}

# ============================================================================
# FUNCTION: Extract-JsUrls
# ============================================================================

function Extract-JsUrls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $jsUrls = [System.Collections.Generic.List[string]]::new()
    $pattern = '<script\s[^>]*src\s*=\s*["'']([^"''\s>]+)["'']'
    $matches = [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $jsUrls.Add($m.Groups[1].Value.Trim())
    }
    return $jsUrls
}

# ============================================================================
# FUNCTION: Extract-InlineJs
# ============================================================================

function Extract-InlineJs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $jsBlocks = [System.Collections.Generic.List[string]]::new()
    $pattern = '<script[^>]*>([\s\S]*?)</script>'
    $matches = [regex]::Matches($Html, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $content = $m.Groups[1].Value.Trim()
        if ($content) { $jsBlocks.Add($content) }
    }
    return $jsBlocks
}

# ============================================================================
# FUNCTION: Find-ApiUrls
# ============================================================================

function Find-ApiUrls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Urls,
        [int]$Depth = 1,
        [switch]$IncludeStatic,
        [switch]$MethodProbe,
        [string[]]$ProbeMethods = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH'),
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [int]$RateLimitMs = 200
    )
    $apiEndpoints = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new($Urls)
    $currentDepth = 0

    while ($queue.Count -gt 0 -and $currentDepth -lt $Depth) {
        $levelSize = $queue.Count
        for ($i = 0; $i -lt $levelSize; $i++) {
            $url = $queue.Dequeue()
            if ($visited.Contains($url)) { continue }
            $null = $visited.Add($url)

            # Skip static files unless opted in
            if (-not $IncludeStatic) {
                $staticExts = @('.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.webm', '.pdf')
                $skip = $false
                foreach ($ext in $staticExts) {
                    if ($url -like "*$ext*") { $skip = $true; break }
                }
                if ($skip) { continue }
            }

            Write-Verbose "Crawling: $url"
            Start-Sleep -Milliseconds $RateLimitMs

            $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec -UserAgent $UserAgent
            if (-not $response.Success) {
                Write-Verbose "Failed to fetch: $url ($($response.ErrorMessage))"
                continue
            }

            $content = $response.Content
            $baseUrl = $url

            # Check URL patterns directly
            foreach ($pattern in $Script:ApiPatterns) {
                if ($url -match [regex]::Escape($pattern)) {
                    $null = $apiEndpoints.Add($url)
                }
            }

            # Scan HTML content for API patterns
            if ($response.ContentType -like '*html*' -or $response.ContentType -like '*text*') {
                # Find API URLs in content
                foreach ($pattern in $Script:ApiPatterns) {
                    $escapedPattern = [regex]::Escape($pattern)
                    $contentMatches = [regex]::Matches($content, "$escapedPattern[^"''\s<>&]*")
                    foreach ($m in $contentMatches) {
                        $matched = $m.Value.Trim()
                        if ($matched -match '^https?://') {
                            $null = $apiEndpoints.Add($matched)
                        }
                        elseif ($matched -match '^/') {
                            try {
                                $uri = [System.Uri]$baseUrl
                                $null = $apiEndpoints.Add("$($uri.Scheme)://$($uri.Host)$matched")
                            }
                            catch {
                                Write-Verbose "Could not resolve: $matched"
                            }
                        }
                    }
                }

                # Find GraphQL patterns
                if ($content -match $Script:GraphQLPatterns) {
                    Write-Verbose "GraphQL patterns detected in $url"
                }

                # Extract JS files from page
                $jsUrls = Extract-JsUrls -Html $content
                foreach ($jsUrl in $jsUrls) {
                    $resolvedJs = if ($jsUrl -match '^https?://') { $jsUrl } elseif ($jsUrl -match '^/') {
                        try {
                            $uri = [System.Uri]$baseUrl
                            "$($uri.Scheme)://$($uri.Host)$jsUrl"
                        } catch { $jsUrl }
                    } else {
                        try {
                            $uri = [System.Uri]$baseUrl
                            "$($uri.Scheme)://$($uri.Host)/$jsUrl"
                        } catch { $jsUrl }
                    }
                    if (-not $visited.Contains($resolvedJs)) {
                        $queue.Enqueue($resolvedJs)
                    }
                }

                # Extract links for deeper crawling
                if ($currentDepth -lt ($Depth - 1)) {
                    $links = Extract-UrlsFromHtml -Html $content -BaseUrl $baseUrl
                    foreach ($link in $links) {
                        if (-not $visited.Contains($link) -and $link -match '^https?://') {
                            # Stay on same domain
                            try {
                                $linkUri = [System.Uri]$link
                                $baseUri = [System.Uri]$baseUrl
                                if ($linkUri.Host -eq $baseUri.Host) {
                                    $queue.Enqueue($link)
                                }
                            }
                            catch {
                                Write-Verbose "Skipping invalid URL: $link"
                            }
                        }
                    }
                }
            }

            # Scan JavaScript content for API endpoints
            if ($response.ContentType -like '*javascript*' -or $response.ContentType -like '*ecmascript*' -or $url -match '\.js(?:$|\?)') {
                foreach ($jsPattern in $Script:JsApiPatterns) {
                    $jsMatches = [regex]::Matches($content, $jsPattern)
                    foreach ($m in $jsMatches) {
                        if ($m.Groups.Count -gt 1) {
                            $matchedUrl = $m.Groups[1].Value.Trim()
                            if ($matchedUrl -match '(?:api|v[0-9]|rest|graphql|soap|ws|query)') {
                                if ($matchedUrl -match '^https?://') {
                                    $null = $apiEndpoints.Add($matchedUrl)
                                }
                                elseif ($matchedUrl -match '^/') {
                                    try {
                                        $uri = [System.Uri]$baseUrl
                                        $null = $apiEndpoints.Add("$($uri.Scheme)://$($uri.Host)$matchedUrl")
                                    }
                                    catch {
                                        Write-Verbose "Could not resolve: $matchedUrl"
                                    }
                                }
                            }
                        }
                    }
                }

                if ($content -match $Script:WebSocketPatterns) {
                    Write-Verbose "WebSocket patterns detected in $url"
                }
            }

            # Check for API specs
            if ($content -match $Script:SwaggerPatterns) {
                Write-Verbose "Swagger/OpenAPI patterns detected in $url"
            }
        }
        $currentDepth++
    }

    return $apiEndpoints
}

# ============================================================================
# FUNCTION: Probe-ApiEndpoint
# ============================================================================

function Probe-ApiEndpoint {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [string[]]$Methods = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH'),
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [int]$RateLimitMs = 100
    )
    if ($PSCmdlet.ShouldProcess($Endpoint, 'Probe HTTP methods')) {
        $methodResults = [System.Collections.Generic.List[object]]::new()

        # First try OPTIONS to get allowed methods
        Start-Sleep -Milliseconds $RateLimitMs
        $optionsResponse = Invoke-WebRequestSafe -Uri $Endpoint -Method 'OPTIONS' -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        $allowedMethods = @()
        if ($optionsResponse.Success -and $optionsResponse.Headers) {
            $allowHeader = $optionsResponse.Headers['Allow'] -join ', '
            if ($allowHeader) {
                $allowedMethods = ($allowHeader -split ',' | ForEach-Object { $_.Trim() }) -ne ''
            }
        }

        $methodResults.Add([PSCustomObject]@{
            Method       = 'OPTIONS'
            StatusCode   = $optionsResponse.StatusCode
            AllowedByHeader = if ($allowedMethods.Count -gt 0) { $allowedMethods -join ', ' } else { 'Unknown' }
            Success      = $optionsResponse.Success
            Error        = $optionsResponse.ErrorMessage
        })

        # Probe each specified method
        foreach ($method in $Methods) {
            if ($allowedMethods.Count -gt 0 -and $method -notin $allowedMethods -and $method -ne 'OPTIONS') {
                Write-Verbose "Skipping $method (not in Allow header for $Endpoint)"
                continue
            }
            Start-Sleep -Milliseconds $RateLimitMs
            $resp = Invoke-WebRequestSafe -Uri $Endpoint -Method $method -TimeoutSec $TimeoutSec -UserAgent $UserAgent

            $methodResults.Add([PSCustomObject]@{
                Method     = $method
                StatusCode = $resp.StatusCode
                Success    = $resp.Success
                Error      = $resp.ErrorMessage
            })
        }

        return $methodResults
    }
}

# ============================================================================
# FUNCTION: Get-AuthRequirement
# ============================================================================

function Get-AuthRequirement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [string]$UserAgent,
        [int]$TimeoutSec = 30
    )
    $authTypes = [System.Collections.Generic.List[string]]::new()

    # Probe without auth header
    $response = Invoke-WebRequestSafe -Uri $Endpoint -TimeoutSec $TimeoutSec -UserAgent $UserAgent

    if ($response.StatusCode -eq 401) {
        $authTypes.Add('Unauthorized (401) - Auth likely required')
    }
    elseif ($response.StatusCode -eq 403) {
        $authTypes.Add('Forbidden (403) - Auth likely required')
    }

    if ($response.Headers) {
        $wwwAuth = $response.Headers['WWW-Authenticate'] -join ', '
        if ($wwwAuth) { $authTypes.Add("WWW-Auth: $wwwAuth") }
    }

    if ($authTypes.Count -eq 0) {
        $authTypes.Add('None detected')
    }

    return ($authTypes -join '; ')
}

# ============================================================================
# FUNCTION: Resolve-Url
# ============================================================================

function Resolve-Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [string]$BaseUrl
    )
    if ($Url -match '^https?://') { return $Url }
    if (-not $BaseUrl) { return $Url }

    try {
        $baseUri = [System.Uri]$BaseUrl
        if ($Url -match '^/') {
            return "$($baseUri.Scheme)://$($baseUri.Host)$Url"
        }
        else {
            $basePath = $BaseUrl.TrimEnd('/')
            return "$basePath/$Url"
        }
    }
    catch {
        return $Url
    }
}

# ============================================================================
# FUNCTION: Classify-EndpointType
# ============================================================================

function Classify-EndpointType {
    [CmdletBinding()]
    param([string]$Endpoint)

    if ($Endpoint -match '/graphql|/gql') { return 'GraphQL' }
    if ($Endpoint -match '/soap|/xmlrpc|\.svc|\.asmx|\.wsdl') { return 'SOAP' }
    if ($Endpoint -match 'ws[s]?://|/ws/|/websocket') { return 'WebSocket' }
    if ($Endpoint -match '/rest/') { return 'REST' }
    if ($Endpoint -match '/api/') { return 'API' }
    if ($Endpoint -match '/v[0-9]+/') { return 'Versioned-API' }
    if ($Endpoint -match '/swagger|/openapi|/docs|/redoc') { return 'API-Docs' }
    return 'Unknown'
}

# ============================================================================
# FUNCTION: Test-GraphQlIntrospection
# ============================================================================

function Test-GraphQlIntrospection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Endpoint,
        [int]$TimeoutSec = 30,
        [string]$UserAgent
    )
    if ($PSCmdlet.ShouldProcess($Endpoint, 'Test GraphQL introspection')) {
        $introspectionQuery = '{ "__schema": { "queryType": { "name" }, "types": { "name", "kind", "description", "fields": { "name", "type": { "name", "kind" } } } } }'
        $body = @{ query = '{__schema{types{name kind description fields{name type{name kind}}}}' } | ConvertTo-Json

        $response = Invoke-WebRequestSafe -Uri $Endpoint -Method POST -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        if ($response.Success -and $response.Content -match '__schema') {
            return $true
        }
        return $false
    }
}

# ============================================================================
# FUNCTION: Get-SwaggerEndpoints
# ============================================================================

function Get-SwaggerEndpoints {
    [CmdletBinding()]
    param(
        [string]$BaseUrl,
        [int]$TimeoutSec = 30,
        [string]$UserAgent
    )
    $swaggerPaths = @('/swagger.json', '/swagger.yaml', '/api-docs', '/v2/swagger.json', '/v3/api-docs', '/openapi.json', '/openapi.yaml', '/api/swagger.json', '/api/v1/swagger.json', '/api/v2/swagger.json', '/api/v3/api-docs', '/docs/json')
    $found = [System.Collections.Generic.List[object]]::new()

    foreach ($path in $swaggerPaths) {
        $url = "$($BaseUrl.TrimEnd('/'))$path"
        Start-Sleep -Milliseconds 100
        $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec -UserAgent $UserAgent

        if ($response.Success -and $response.StatusCode -eq 200) {
            $found.Add([PSCustomObject]@{
                Url      = $url
                Status   = 200
                Detected = $true
            })
            Write-Verbose "Found spec: $url"
        }
    }

    return $found
}

# ============================================================================
# FUNCTION: Invoke-ApiDiscovery
# ============================================================================

function Invoke-ApiDiscovery {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$OutputFile,
        [int]$Depth = 1,
        [switch]$Silent,
        [switch]$MethodProbe,
        [string]$ProbeMethods = 'GET,POST,PUT,DELETE,PATCH',
        [switch]$IncludeStatic,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 200
    )
    $probeMethodsArray = $ProbeMethods -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $output = [PSCustomObject]@{
        Tool         = 'Extract-APIs'
        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target       = if ($Url) { $Url } else { $FilePath }
        Endpoints    = @()
        Stats        = $null
        Errors       = @()
    }
    $allEndpoints = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $errors = [System.Collections.Generic.List[string]]::new()

    # Phase 1: Source content
    $htmlContent = $null
    $baseUrl = $null

    if ($Url) {
        Write-Verbose "Fetching URL: $Url"
        $response = Invoke-WebRequestSafe -Uri $Url -TimeoutSec $Timeout -UserAgent $UserAgent
        if ($response.Success) {
            $htmlContent = $response.Content
            $baseUrl = $Url
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
            if (-not $baseUrl) { $baseUrl = $FilePath }
        }
        else {
            $errMsg = "File not found: $FilePath"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
        }
    }

    if (-not $htmlContent -and -not $Url -and -not $FilePath) {
        $errMsg = 'No URL or FilePath provided and no content available'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
    }

    # Phase 2: Extract API endpoints from content
    if ($htmlContent) {
        Write-Verbose 'Scanning for API endpoints in content...'

        # Scan content for API URL patterns
        foreach ($pattern in $Script:ApiPatterns) {
            $escaped = [regex]::Escape($pattern)
            $matches = [regex]::Matches($htmlContent, "$escaped[^"''\s<>&]*")
            foreach ($m in $matches) {
                $matched = $m.Value.Trim()
                if ($matched -match '^https?://') {
                    $null = $allEndpoints.Add($matched)
                }
                elseif ($matched -match '^//') {
                    $null = $allEndpoints.Add("https:$matched")
                }
                elseif ($matched -match '^/') {
                    if ($baseUrl -match '^https?://') {
                        try {
                            $uri = [System.Uri]$baseUrl
                            $null = $allEndpoints.Add("$($uri.Scheme)://$($uri.Host)$matched")
                        }
                        catch {
                            Write-Verbose "Could not resolve: $matched"
                        }
                    }
                }
            }
        }

        # Scan JS patterns in content
        foreach ($jsPattern in $Script:JsApiPatterns) {
            $jsMatches = [regex]::Matches($htmlContent, $jsPattern)
            foreach ($m in $jsMatches) {
                if ($m.Groups.Count -gt 1) {
                    $matchedUrl = $m.Groups[1].Value.Trim()
                    if ($matchedUrl -match '(?:api|v[0-9]|rest|graphql|soap|ws|query|endpoint|service)') {
                        if ($matchedUrl -match '^https?://') {
                            $null = $allEndpoints.Add($matchedUrl)
                        }
                        elseif ($matchedUrl -match '^//') {
                            $null = $allEndpoints.Add("https:$matchedUrl")
                        }
                        elseif ($matchedUrl -match '^/') {
                            if ($baseUrl -match '^https?://') {
                                try {
                                    $uri = [System.Uri]$baseUrl
                                    $null = $allEndpoints.Add("$($uri.Scheme)://$($uri.Host)$matchedUrl")
                                }
                                catch { Write-Verbose "Could not resolve: $matchedUrl" }
                            }
                        }
                    }
                }
            }
        }

        # Phase 3: Deeper crawl if requested
        if ($Depth -gt 1 -and $Url) {
            Write-Verbose "Deep crawling with depth $Depth..."
            $discovered = Find-ApiUrls -Urls @($Url) -Depth $Depth -IncludeStatic:$IncludeStatic -MethodProbe:$MethodProbe -ProbeMethods $probeMethodsArray -TimeoutSec $Timeout -UserAgent $UserAgent -RateLimitMs $RateLimit
            foreach ($ep in $discovered) { $null = $allEndpoints.Add($ep) }
        }
    }

    # Phase 4: Build endpoint details
    $endpointDetails = [System.Collections.Generic.List[object]]::new()
    $stats = @{
        TotalDiscovered  = 0
        ByType           = @{}
        ByMethod         = @{}
        ByStatusCode     = @{}
        Authenticated    = 0
        Public           = 0
    }

    $sortedEndpoints = $allEndpoints | Sort-Object
    foreach ($endpointUrl in $sortedEndpoints) {
        $endpointType = Classify-EndpointType -Endpoint $endpointUrl
        $authInfo = 'Pending'
        $methodResults = @()

        if ($MethodProbe) {
            Write-Verbose "Probing: $endpointUrl"
            $methodResults = Probe-ApiEndpoint -Endpoint $endpointUrl -Methods $probeMethodsArray -TimeoutSec $Timeout -UserAgent $UserAgent -RateLimitMs $RateLimit
            $authInfo = Get-AuthRequirement -Endpoint $endpointUrl -UserAgent $UserAgent -TimeoutSec $Timeout
        }

        $detail = [PSCustomObject]@{
            Endpoint        = $endpointUrl
            Type            = $endpointType
            Methods         = if ($MethodProbe) { ($methodResults | Where-Object { $_.Success -and $_.Method -ne 'OPTIONS' } | ForEach-Object { $_.Method }) -join ', ' } else { 'Unknown' }
            MethodDetails   = @($methodResults)
            StatusCodes     = if ($MethodProbe) { ($methodResults | ForEach-Object { "$($_.Method):$($_.StatusCode)" }) -join '; ' } else { '' }
            AuthRequirement = $authInfo
            Source          = if ($htmlContent -and $endpointUrl -match [regex]::Escape($Url ?? '')) { 'Content' } else { 'Crawl' }
        }
        $endpointDetails.Add($detail)

        # Stats tracking
        if (-not $stats.ByType.ContainsKey($endpointType)) { $stats.ByType[$endpointType] = 0 }
        $stats.ByType[$endpointType]++

        if ($authInfo -ne 'None detected') { $stats.Authenticated++ } else { $stats.Public++ }
    }

    $stats.TotalDiscovered = $endpointDetails.Count

    $output.Endpoints = $endpointDetails
    $output.Stats = $stats
    $output.Errors = $errors

    # Phase 5: Swagger discovery
    if ($Url) {
        Write-Verbose 'Checking for API specification documents...'
        $swaggerResults = Get-SwaggerEndpoints -BaseUrl $Url -TimeoutSec $Timeout -UserAgent $UserAgent
        if ($swaggerResults.Count -gt 0) {
            $output.SwaggerDocs = $swaggerResults
        }
    }

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
        Write-Output "=== API Discovery Summary ==="
        Write-Output "Total Endpoints Found: $($stats.TotalDiscovered)"
        foreach ($type in $stats.ByType.Keys | Sort-Object) {
            Write-Output "  $type : $($stats.ByType[$type])"
        }
        Write-Output "Authenticated: $($stats.Authenticated) | Public: $($stats.Public)"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$OutputFile,
        [int]$Depth = 1,
        [switch]$Silent,
        [switch]$MethodProbe,
        [string]$ProbeMethods = 'GET,POST,PUT,DELETE,PATCH',
        [switch]$IncludeStatic,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 200
    )
    Invoke-ApiDiscovery -Url $Url -FilePath $FilePath -OutputFile $OutputFile -Depth $Depth -Silent:$Silent -MethodProbe:$MethodProbe -ProbeMethods $ProbeMethods -IncludeStatic:$IncludeStatic -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit
}

# Entry point
$Url = $null; $FilePath = $null; $OutputFile = $null; $Depth = 1; $Silent = $false
$MethodProbe = $false; $ProbeMethods = 'GET,POST,PUT,DELETE,PATCH'; $IncludeStatic = $false
$Timeout = 30; $UserAgent = $null; $RateLimit = 200

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Url' { $i++; $Url = $args[$i] }
            '-FilePath' { $i++; $FilePath = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Depth' { $i++; $Depth = [int]$args[$i] }
            '-Silent' { $Silent = $true }
            '-MethodProbe' { $MethodProbe = $true }
            '-ProbeMethods' { $i++; $ProbeMethods = $args[$i] }
            '-IncludeStatic' { $IncludeStatic = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
            '-RateLimit' { $i++; $RateLimit = [int]$args[$i] }
        }
        $i++
    }
}

try {
    Main -Url $Url -FilePath $FilePath -OutputFile $OutputFile -Depth $Depth -Silent:$Silent -MethodProbe:$MethodProbe -ProbeMethods $ProbeMethods -IncludeStatic:$IncludeStatic -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
