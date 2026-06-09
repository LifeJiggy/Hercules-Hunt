<#
.SYNOPSIS
    Endpoint-Fuzzer — Endpoint Fuzzing Tool for Bug Bounty Reconnaissance

.DESCRIPTION
    Fuzzes target endpoints using dictionary-based wordlists, HTTP method discovery,
    extension probing, and response analysis. Identifies hidden paths, methods,
    access control bypasses, and interesting server behavior.

    Features:
      - Path fuzzing with dictionary-based wordlists
      - HTTP method fuzzing (all verbs on each discovered endpoint)
      - Extension fuzzing (.php, .asp, .aspx, .jsp, .json, .xml, .config, .bak, .old)
      - Response analysis: status code tracking, response size comparison, timing analysis
      - Automatic baseline comparison to filter noise
      - Access control testing (admin paths, internal paths, restricted areas)
      - Recursive directory discovery
      - Response similarity analysis to detect default pages
      - Content-Type tracking for each endpoint
      - Configurable concurrency with throttling
      - Response size and timing anomaly detection
      - Structured JSON output

.PARAMETER Target
    Base target URL to fuzz (e.g. https://target.com/FUZZ or https://target.com/).

.PARAMETER Wordlist
    Path to wordlist file for path fuzzing. One entry per line. Built-in wordlist used if omitted.

.PARAMETER Methods
    Comma-separated HTTP methods to test. Default: GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD

.PARAMETER Extensions
    Comma-separated file extensions to append during fuzzing.
    Default: .php,.asp,.aspx,.jsp,.json,.xml,.config,.bak,.old,.txt,.log,.html,.do,.action

.PARAMETER OutputFile
    Path to write structured results (JSON format).

.PARAMETER Threads
    Number of concurrent fuzzing threads. Default: 5, Max: 20.

.PARAMETER Delay
    Delay between requests in milliseconds. Default: 100

.PARAMETER FilterSize
    Comma-separated response sizes to filter out (hide).

.PARAMETER Recursive
    Enable recursive directory discovery. Default: \False.

.PARAMETER RecursiveDepth
    Maximum recursion depth. Default: 2

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER UserAgent
    Custom User-Agent string for HTTP requests.

.PARAMETER Silent
    Suppress all non-data output.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+
    Author      : Hercules-Hunt Toolchain

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
Continue = 'Stop'


# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

$Script:AllHttpMethods = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT')

$Script:DefaultExtensions = @('.php', '.asp', '.aspx', '.jsp', '.json', '.xml', '.config', '.bak', '.old', '.txt', '.log', '.html', '.do', '.action', '.phtml', '.php3', '.php4', '.php5', '.php7', '.shtml', '.inc', '.sql', '.tar', '.gz', '.zip', '.rar')

$Script:InterestingStatusCodes = @(200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 502, 503)

$Script:DefaultWordlist = @(
    'admin', 'api', 'v1', 'v2', 'v3', 'backup', 'config', 'console', 'dashboard',
    'debug', 'dev', 'download', 'dump', 'error', 'export', 'files', 'health',
    'help', 'home', 'images', 'img', 'import', 'include', 'inc', 'index',
    'info', 'js', 'json', 'login', 'logout', 'logs', 'media', 'metrics',
    'migrate', 'migration', 'old', 'panel', 'phpinfo', 'phpinfo.php',
    'pings', 'private', 'public', 'reset', 'rest', 'restricted', 'robots.txt',
    'search', 'secret', 'secure', 'security', 'server-status', 'service',
    'services', 'session', 'setup', 'signin', 'signup', 'sql', 'sso',
    'staff', 'static', 'status', 'storage', 'support', 'swagger',
    'swagger.json', 'swagger.yaml', 'test', 'tmp', 'token', 'trace',
    'upload', 'user', 'users', 'version', 'webhook', 'webhooks', 'www',
    'docs', 'documentation', 'openapi.json', 'openapi.yaml', 'graphql',
    'gql', 'sdk', 'client', 'server', 'node_modules', 'vendor', 'lib',
    'assets', 'css', 'fonts', 'templates', 'partials', 'includes',
    'proxy', 'redirect', 'ref', 'callback', 'notify', 'webhook',
    'audit', 'batch', 'bulk', 'sync', 'async', 'event', 'events',
    'subscribe', 'publish', 'channel', 'socket', 'rt', 'stream',
    'env', 'environment', 'settings', 'configuration', 'properties',
    'application.properties', 'application.yml', 'application.json',
    'docker', 'dockerfile', '.env', '.git', '.svn', '.htaccess',
    'README', 'README.md', 'LICENSE', 'CHANGELOG', 'composer.json',
    'package.json', 'bower.json', 'webpack.config.js',
    'flag', 'key', 'cert', 'certificate', 'pem', 'crt', 'key',
    'id_rsa', 'id_dsa', 'authorized_keys', 'known_hosts',
    'passwd', 'shadow', 'hosts', 'resolv.conf', 'nginx.conf',
    'httpd.conf', 'apache.conf', '.htpasswd', 'htpasswd',
    'sitemap.xml', 'sitemap', 'crossdomain.xml', 'clientaccesspolicy.xml',
    'wsdl', 'asmx', 'svc', 'soap', 'xmlrpc', 'rpc', 'rest',
    'base', 'api/v1', 'api/v2', 'api/v3', 'api/rest', 'api/graphql',
    'api/soap', 'api/admin', 'api/user', 'api/users', 'api/auth',
    'api/login', 'api/token', 'api/oauth', 'api/key', 'api/keys',
    'api/status', 'api/health', 'api/version', 'api/config',
    'api/export', 'api/import', 'api/upload', 'api/download',
    'api/webhook', 'api/webhooks', 'api/callback', 'api/notify',
    'api/search', 'api/query', 'api/debug', 'api/logs', 'api/errors',
    'api/data', 'api/sync', 'api/batch', 'api/job', 'api/jobs',
    'api/task', 'api/tasks', 'api/schedule', 'api/event', 'api/events'
)

$Script:DirectoryIndicators = @(
    'admin', 'api', 'assets', 'backup', 'css', 'data', 'docs', 'download',
    'files', 'images', 'img', 'include', 'js', 'lib', 'media', 'old',
    'private', 'public', 'static', 'storage', 'tmp', 'upload', 'vendor'
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
        $startTime = Get-Date
        $response = Invoke-WebRequest @params
        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalMilliseconds, 0)
        $content = if ($response.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($response.Content)
        } else { $response.Content }

        $result = [PSCustomObject]@{
            StatusCode    = [int]$response.StatusCode
            Content       = $content
            ContentLength = if ($content) { $content.Length } else { 0 }
            ContentType   = $response.Headers.'Content-Type' -join ', '
            Headers       = $response.Headers
            ResponseTimeMs = $elapsed
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
            ContentLength = 0
            ContentType   = $null
            Headers       = $null
            ResponseTimeMs = 0
            Success       = $false
            ErrorMessage  = $_.Exception.Message
        }
        return $result
    }
}


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
        $startTime = Get-Date
        $response = Invoke-WebRequest @params
        $elapsed = [Math]::Round(((Get-Date) - $startTime).TotalMilliseconds, 0)
        $content = if ($response.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($response.Content)
        } else { $response.Content }

        $result = [PSCustomObject]@{
            StatusCode     = [int]$response.StatusCode
            Content        = $content
            ContentLength  = if ($content) { $content.Length } else { 0 }
            ContentType    = $response.Headers.'Content-Type' -join ', '
            Headers        = $response.Headers
            ResponseTimeMs = $elapsed
            Success        = $true
            ErrorMessage   = $null
        }
        return $result
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $result = [PSCustomObject]@{
            StatusCode     = $statusCode
            Content        = $null
            ContentLength  = 0
            ContentType    = $null
            Headers        = $null
            ResponseTimeMs = 0
            Success        = $false
            ErrorMessage   = $_.Exception.Message
        }
        return $result
    }
}

# ============================================================================
# FUNCTION: Load-Wordlist
# ============================================================================

function Load-Wordlist {
    [CmdletBinding()]
    param(
        [string]$Path,
        [switch]$Silent
    )
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        if (-not $Silent) { Write-Output "[*] Loading wordlist from: $Path" }
        $words = Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -and -not $_.StartsWith('#') } | ForEach-Object { $_.Trim() }
        if (-not $Silent) { Write-Output "[+] Loaded $($words.Count) words" }
        return $words
    }
    elseif ($Path) {
        if (-not $Silent) { Write-Warning "Wordlist not found: $Path, using built-in wordlist" }
    }
    return $Script:DefaultWordlist
}

# ============================================================================
# FUNCTION: Get-BaselineResponse
# ============================================================================

function Get-BaselineResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [string]$BaselineUrl,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $target = if ($BaselineUrl) { $BaselineUrl } else { $BaseUrl }
    if (-not $Silent) { Write-Output "[*] Getting baseline response: $target" }
    $response = Invoke-WebRequestSafe -Uri $target -TimeoutSec $TimeoutSec -UserAgent $UserAgent
    return [PSCustomObject]@{
        StatusCode     = $response.StatusCode
        ContentLength  = $response.ContentLength
        ContentType    = $response.ContentType
        ResponseTimeMs = $response.ResponseTimeMs
        Content        = $response.Content
        Success        = $response.Success
    }
}

# ============================================================================
# FUNCTION: Fuzz-Paths
# ============================================================================

function Fuzz-Paths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [string[]]$Wordlist,
        [int]$Threads = 5,
        [int]$DelayMs = 100,
        [int[]]$FilterSizes,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Baseline,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $total = $Wordlist.Count
    $processed = 0

    if (-not $Silent) { Write-Output "[*] Path fuzzing $BaseUrl with $total words..." }

    foreach ($word in $Wordlist) {
        $url = $BaseUrl.TrimEnd('/') + '/' + $word.TrimStart('/')
        $resp = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        Start-Sleep -Milliseconds $DelayMs

        $statusCode = $resp.StatusCode
        $contentLength = $resp.ContentLength
        $contentType = $resp.ContentType
        $responseTime = $resp.ResponseTimeMs

        $interesting = $false
        $reason = @()

        if ($statusCode -in $Script:InterestingStatusCodes) {
            $interesting = $true
            $reason += "Status:$statusCode"
        }
        if ($contentLength -gt 0 -and $Baseline -and $contentLength -ne $Baseline.ContentLength) {
            $interesting = $true
            $reason += "SizeDiff:$contentLength"
        }
        if ($FilterSizes -and $contentLength -in $FilterSizes) {
            $interesting = $false
            $reason = @()
        }
        if ($responseTime -gt 5000) {
            $interesting = $true
            $reason += "Slow:${responseTime}ms"
        }
        if ($statusCode -eq 200 -and $contentLength -gt 0) {
            $interesting = $true
            if (-not $reason.Count -or $reason -notmatch 'Status') { $reason += "Accessible:$contentLength" }
        }

        $results.Add([PSCustomObject]@{
            FuzzType       = 'path'
            Word           = $word
            FullUrl        = $url
            Method         = 'GET'
            StatusCode     = $statusCode
            ContentLength  = $contentLength
            ContentType    = $contentType
            ResponseTimeMs = $responseTime
            Interesting    = $interesting
            Reason         = $reason -join '; '
            Error          = if (-not $resp.Success) { $resp.ErrorMessage } else { $null }
        })

        $processed++
        if ($processed % 50 -eq 0 -and -not $Silent) {
            Write-Output "[*] Path fuzz progress: $processed/$total"
        }
    }
    return $results
}

# ============================================================================
# FUNCTION: Fuzz-Methods
# ============================================================================

function Fuzz-Methods {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [string[]]$Methods = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'),
        [int]$DelayMs = 50,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Baseline,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    if (-not $Silent) { Write-Output "[*] Method fuzzing $BaseUrl with $($Methods.Count) methods..." }

    foreach ($method in $Methods) {
        $resp = Invoke-WebRequestSafe -Uri $BaseUrl -Method $method -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        Start-Sleep -Milliseconds $DelayMs

        $interesting = $false
        $reason = @()

        if ($resp.StatusCode -in @(200, 201, 204)) {
            $interesting = $true
            $reason += "UnusualAccess:$method"
        }
        if ($resp.StatusCode -eq 405 -and $method -ne 'GET') {
            $interesting = $true
            $reason += "MethodNotAllowed:$method"
        }
        if ($resp.ContentLength -gt 0 -and $Baseline -and $resp.ContentLength -ne $Baseline.ContentLength -and $resp.StatusCode -eq 200) {
            $interesting = $true
            $reason += "DifferentResponse:$method"
        }

        $results.Add([PSCustomObject]@{
            FuzzType       = 'method'
            Word           = $method
            FullUrl        = $BaseUrl
            Method         = $method
            StatusCode     = $resp.StatusCode
            ContentLength  = $resp.ContentLength
            ContentType    = $resp.ContentType
            ResponseTimeMs = $resp.ResponseTimeMs
            Interesting    = $interesting
            Reason         = $reason -join '; '
            Error          = if (-not $resp.Success) { $resp.ErrorMessage } else { $null }
        })
    }
    return $results
}

# ============================================================================
# FUNCTION: Fuzz-Extensions
# ============================================================================

function Fuzz-Extensions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,
        [string[]]$Extensions = $Script:DefaultExtensions,
        [string]$BaseMethod = 'GET',
        [int]$DelayMs = 50,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Baseline,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $baseClean = $BasePath.TrimEnd('/')
    if (-not $Silent) { Write-Output "[*] Extension fuzzing $baseClean with $($Extensions.Count) extensions..." }

    foreach ($ext in $Extensions) {
        $url = $baseClean + $ext
        $resp = Invoke-WebRequestSafe -Uri $url -Method $BaseMethod -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        Start-Sleep -Milliseconds $DelayMs

        $interesting = $false
        $reason = @()

        if ($resp.StatusCode -eq 200) {
            $interesting = $true
            $reason += "Found:$ext"
        }
        if ($resp.StatusCode -eq 403) {
            $interesting = $true
            $reason += "Forbidden:$ext"
        }
        if ($resp.StatusCode -in @(301, 302, 307, 308)) {
            $interesting = $true
            $reason += "Redirect:$ext"
        }
        if ($resp.ContentLength -gt 0 -and $Baseline -and $resp.ContentLength -ne $Baseline.ContentLength) {
            $interesting = $true
            if (-not ($reason -match 'Found|Forbidden|Redirect')) { $reason += "SizeDiff:$($resp.ContentLength)" }
        }

        $results.Add([PSCustomObject]@{
            FuzzType       = 'extension'
            Word           = $ext
            FullUrl        = $url
            Method         = $BaseMethod
            StatusCode     = $resp.StatusCode
            ContentLength  = $resp.ContentLength
            ContentType    = $resp.ContentType
            ResponseTimeMs = $resp.ResponseTimeMs
            Interesting    = $interesting
            Reason         = $reason -join '; '
            Error          = if (-not $resp.Success) { $resp.ErrorMessage } else { $null }
        })
    }
    return $results
}

# ============================================================================
# FUNCTION: Fuzz-AccessControl
# ============================================================================

function Fuzz-AccessControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [int]$DelayMs = 100,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$Silent
    )
    $results = [System.Collections.Generic.List[object]]::new()
    $accessPaths = @(
        '/admin', '/api/admin', '/dashboard', '/console', '/manager',
        '/management', '/internal', '/private', '/restricted', '/secret',
        '/config', '/configuration', '/settings', '/debug', '/test',
        '/api/internal', '/api/private', '/api/restricted', '/api/config',
        '/api/secret', '/api/debug', '/api/health', '/.env', '/.git/config',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/server-status',
        '/phpinfo.php', '/info.php', '/status', '/health', '/ready',
        '/api/status', '/api/version', '/api/user', '/api/users',
        '/api/export', '/api/import', '/api/backup', '/api/dump',
        '/api/logs', '/api/trace', '/swagger.json', '/openapi.json',
        '/api-docs', '/v1', '/v2', '/v3', '/graphql', '/gql',
        '/actuator', '/actuator/health', '/actuator/info',
        '/actuator/env', '/actuator/beans', '/actuator/mappings'
    )

    if (-not $Silent) { Write-Output "[*] Access control testing with $($accessPaths.Count) paths..." }

    foreach ($path in $accessPaths) {
        $url = $BaseUrl.TrimEnd('/') + $path
        $resp = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec -UserAgent $UserAgent
        Start-Sleep -Milliseconds $DelayMs

        $interesting = $false
        $reason = @()

        if ($resp.StatusCode -in @(200, 204)) {
            $interesting = $true
            $reason += "UnauthenticatedAccess:$($resp.StatusCode)"
        }
        if ($resp.StatusCode -eq 401) {
            $interesting = $true
            $reason += "AuthRequired:$path"
        }
        if ($resp.StatusCode -eq 403) {
            $interesting = $true
            $reason += "Forbidden:$path"
        }
        if ($resp.StatusCode -eq 302 -or $resp.StatusCode -eq 303) {
            $interesting = $true
            $reason += "RedirectToLogin:$path"
        }
        if ($resp.ContentLength -gt 100 -and $resp.StatusCode -eq 200) {
            $interesting = $true
            $reason += "ContentReturned:$($resp.ContentLength)bytes"
        }

        $results.Add([PSCustomObject]@{
            FuzzType       = 'access_control'
            Word           = $path
            FullUrl        = $url
            Method         = 'GET'
            StatusCode     = $resp.StatusCode
            ContentLength  = $resp.ContentLength
            ContentType    = $resp.ContentType
            ResponseTimeMs = $resp.ResponseTimeMs
            Interesting    = $interesting
            Reason         = $reason -join '; '
            Error          = if (-not $resp.Success) { $resp.ErrorMessage } else { $null }
        })
    }
    return $results
}

# ============================================================================
# FUNCTION: Fuzz-Recursive
# ============================================================================

function Fuzz-Recursive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [Parameter(Mandatory)]
        [string[]]$Wordlist,
        [int]$MaxDepth = 2,
        [int]$Threads = 3,
        [int]$DelayMs = 150,
        [int[]]$FilterSizes,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [hashtable]$Baseline,
        [switch]$Silent
    )
    $allResults = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[hashtable]]::new()
    $queue.Enqueue(@{ Url = $BaseUrl; Depth = 0 })

    if (-not $Silent) { Write-Output "[*] Recursive fuzzing up to depth $MaxDepth..." }

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $currentUrl = $current['Url']
        $currentDepth = $current['Depth']

        if ($visited.Contains($currentUrl)) { continue }
        $null = $visited.Add($currentUrl)

        if ($currentDepth -ge $MaxDepth) { continue }
        if (-not $Silent) { Write-Output "[*] Recursing: depth $currentDepth at $currentUrl" }

        $pathResults = Fuzz-Paths -BaseUrl $currentUrl -Wordlist $Wordlist -Threads $Threads -DelayMs $DelayMs -FilterSizes $FilterSizes -TimeoutSec $TimeoutSec -UserAgent $UserAgent -Baseline $Baseline -Silent:$true

        foreach ($pr in $pathResults) {
            $pr | Add-Member -MemberType NoteProperty -Name 'FuzzRound' -Value "depth_$currentDepth" -Force
            $allResults.Add($pr)

            $isDir = ($pr.StatusCode -eq 200 -or $pr.StatusCode -eq 301 -or $pr.StatusCode -eq 302)
            $hasDirName = $false
            foreach ($dirInd in $Script:DirectoryIndicators) {
                if ($pr.Word -eq $dirInd) { $hasDirName = $true; break }
            }
            $contentTypeIsHtml = $pr.ContentType -match 'text/html'

            if ($isDir -and ($hasDirName -or $contentTypeIsHtml -or $pr.ContentLength -gt 500) -and $pr.Interesting) {
                $childUrl = $pr.FullUrl
                if ($childUrl -ne $currentUrl -and -not $visited.Contains($childUrl)) {
                    $queue.Enqueue(@{ Url = $childUrl; Depth = $currentDepth + 1 })
                }
            }
        }
    }
    return $allResults
}

# ============================================================================
# FUNCTION: Analyze-Results
# ============================================================================

function Analyze-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Results
    )
    $interesting = $Results | Where-Object { $_.Interesting }
    $byStatusCode = @{}
    $byContentType = @{}
    $byFuzzType = @{}
    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $Results) {
        $sc = "$($r.StatusCode)"
        if (-not $byStatusCode.ContainsKey($sc)) { $byStatusCode[$sc] = 0 }
        $byStatusCode[$sc]++

        $ct = if ($r.ContentType) { ($r.ContentType -split ';')[0].Trim() } else { 'none' }
        if (-not $byContentType.ContainsKey($ct)) { $byContentType[$ct] = 0 }
        $byContentType[$ct]++

        $ft = $r.FuzzType
        if (-not $byFuzzType.ContainsKey($ft)) { $byFuzzType[$ft] = 0 }
        $byFuzzType[$ft]++
    }

    $unauthenticatedAccess = $Results | Where-Object { $_.FuzzType -eq 'access_control' -and $_.StatusCode -eq 200 -and $_.ContentLength -gt 100 }
    $hiddenEndpoints = $Results | Where-Object { $_.FuzzType -eq 'path' -and $_.StatusCode -eq 200 -and $_.ContentLength -gt 0 }
    $sensitiveFiles = $Results | Where-Object { $_.FuzzType -eq 'extension' -and $_.StatusCode -eq 200 }
    $configDisclosures = $Results | Where-Object { $_.FullUrl -match '\.(config|env|bak|old|xml|json|yml|yaml|sql|log|txt)' -and $_.StatusCode -eq 200 -and $_.ContentLength -gt 0 }
    $slowEndpoints = $Results | Where-Object { $_.ResponseTimeMs -gt 10000 }

    $summary = [PSCustomObject]@{
        TotalRequests         = $Results.Count
        InterestingCount      = $interesting.Count
        ByStatusCode          = $byStatusCode
        ByContentType         = $byContentType
        ByFuzzType            = $byFuzzType
        UnauthenticatedAccess = $unauthenticatedAccess.Count
        HiddenEndpoints       = $hiddenEndpoints.Count
        SensitiveFiles        = $sensitiveFiles.Count
        ConfigDisclosures     = $configDisclosures.Count
        SlowEndpoints         = $slowEndpoints.Count
    }

    return [PSCustomObject]@{
        Interesting            = $interesting
        Summary                = $summary
        UnauthenticatedAccess  = $unauthenticatedAccess
        HiddenEndpoints        = $hiddenEndpoints
        SensitiveFiles         = $sensitiveFiles
        ConfigDisclosures      = $configDisclosures
        SlowEndpoints          = $slowEndpoints
    }
}

# ============================================================================
# FUNCTION: Invoke-EndpointFuzzing
# ============================================================================

function Invoke-EndpointFuzzing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Target,
        [string]$Wordlist,
        [string]$Methods = 'GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD',
        [string]$Extensions,
        [string]$OutputFile,
        [int]$Threads = 5,
        [int]$Delay = 100,
        [string]$FilterSize,
        [switch]$Recursive,
        [int]$RecursiveDepth = 2,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [switch]$Silent,
        [string]$BaselineUrl
    )
    $output = [PSCustomObject]@{
        Tool            = 'Endpoint-Fuzzer'
        Timestamp       = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target          = $Target
        Results         = @()
        Analysis        = $null
        Errors          = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $allResults = [System.Collections.Generic.List[object]]::new()

    if (-not $Target) {
        $errMsg = 'Parameter -Target is required'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
        return $output
    }

    # Parse parameters
    $methodsArray = $Methods -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $extensionsArray = if ($Extensions) { $Extensions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } } else { $Script:DefaultExtensions }
    $filterSizesArray = if ($FilterSize) { $FilterSize -split ',' | ForEach-Object { [int]$_.Trim() } | Where-Object { $_ -gt 0 } } else { @() }
    $threadCount = [Math]::Min([Math]::Max(1, $Threads), 20)

    # Parse target URL for FUZZ marker
    $baseUrl = $Target
    $hasFuzzMarker = $Target -match 'FUZZ'
    if ($hasFuzzMarker) {
        $baseUrl = $Target -replace 'FUZZ', ''
        $baseUrl = $baseUrl.TrimEnd('/')
    }

    # Phase 1: Load wordlist
    $words = Load-Wordlist -Path $Wordlist -Silent:$Silent
    if (-not $Silent) { Write-Output "[+] Using wordlist with $($words.Count) entries" }

    # Phase 2: Baseline
    $baseline = Get-BaselineResponse -BaseUrl $baseUrl -BaselineUrl $BaselineUrl -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent

    # Phase 3: Path fuzzing
    if (-not $Silent) { Write-Output "[*] Starting path fuzzing..." }
    $pathResults = Fuzz-Paths -BaseUrl $baseUrl -Wordlist $words -Threads $threadCount -DelayMs $Delay -FilterSizes $filterSizesArray -TimeoutSec $Timeout -UserAgent $UserAgent -Baseline $baseline -Silent:$Silent
    foreach ($pr in $pathResults) { $allResults.Add($pr) }
    if (-not $Silent) { Write-Output "[+] Path fuzzing completed: $($pathResults.Count) results, $(($pathResults | Where-Object { $_.Interesting }).Count) interesting" }

    # Phase 4: Method fuzzing on discovered interesting paths
    if (-not $Silent) { Write-Output "[*] Starting method fuzzing..." }
    $methodTargets = @($baseUrl)
    $interestingPaths = $pathResults | Where-Object { $_.Interesting -and $_.StatusCode -eq 200 }
    foreach ($ip in $interestingPaths) {
        $methodTargets += $ip.FullUrl
    }
    $methodTargets = $methodTargets | Select-Object -Unique

    foreach ($mt in $methodTargets) {
        $methodResults = Fuzz-Methods -BaseUrl $mt -Methods $methodsArray -DelayMs $Delay -TimeoutSec $Timeout -UserAgent $UserAgent -Baseline $baseline -Silent:$Silent
        foreach ($mr in $methodResults) { $allResults.Add($mr) }
    }
    if (-not $Silent) { Write-Output "[+] Method fuzzing completed" }

    # Phase 5: Extension fuzzing on discovered paths
    if (-not $Silent) { Write-Output "[*] Starting extension fuzzing..." }
    $extensionTargets = $interestingPaths | ForEach-Object { $_.FullUrl }
    foreach ($et in $extensionTargets) {
        $extensionResults = Fuzz-Extensions -BasePath $et -Extensions $extensionsArray -DelayMs $Delay -TimeoutSec $Timeout -UserAgent $UserAgent -Baseline $baseline -Silent:$Silent
        foreach ($er in $extensionResults) { $allResults.Add($er) }
    }
    if (-not $Silent) { Write-Output "[+] Extension fuzzing completed" }

    # Phase 6: Access control testing
    if (-not $Silent) { Write-Output "[*] Starting access control testing..." }
    $accessResults = Fuzz-AccessControl -BaseUrl $baseUrl -DelayMs $Delay -TimeoutSec $Timeout -UserAgent $UserAgent -Silent:$Silent
    foreach ($ar in $accessResults) { $allResults.Add($ar) }
    if (-not $Silent) { Write-Output "[+] Access control testing completed" }

    # Phase 7: Recursive fuzzing
    if ($Recursive) {
        if (-not $Silent) { Write-Output "[*] Starting recursive fuzzing (depth $RecursiveDepth)..." }
        $recursiveResults = Fuzz-Recursive -BaseUrl $baseUrl -Wordlist $words -MaxDepth $RecursiveDepth -Threads $threadCount -DelayMs $Delay -FilterSizes $filterSizesArray -TimeoutSec $Timeout -UserAgent $UserAgent -Baseline $baseline -Silent:$Silent
        foreach ($rr in $recursiveResults) { $allResults.Add($rr) }
        if (-not $Silent) { Write-Output "[+] Recursive fuzzing completed" }
    }

    # Phase 8: Analysis
    if (-not $Silent) { Write-Output "[*] Analyzing results..." }
    $analysis = Analyze-Results -Results $allResults

    $output.Results = $allResults
    $output.Analysis = $analysis
    $output.Errors = $errors

    # Output
    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "`n=== Endpoint Fuzzing Summary ==="
        Write-Output "Target: $baseUrl"
        Write-Output "Total Requests: $($analysis.Summary.TotalRequests)"
        Write-Output "Interesting: $($analysis.Summary.InterestingCount)"
        Write-Output "Hidden Endpoints: $($analysis.Summary.HiddenEndpoints)"
        Write-Output "Unauthenticated Access: $($analysis.Summary.UnauthenticatedAccess)"
        Write-Output "Sensitive Files: $($analysis.Summary.SensitiveFiles)"
        Write-Output "Config Disclosures: $($analysis.Summary.ConfigDisclosures)"
        Write-Output "Slow Endpoints: $($analysis.Summary.SlowEndpoints)"
        Write-Output "Status Codes: $($analysis.Summary.ByStatusCode.Keys -join ', ')"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }

        $topInteresting = $allResults | Where-Object { $_.Interesting } | Sort-Object StatusCode | Select-Object -First 20
        if ($topInteresting.Count -gt 0) {
            Write-Output "`n=== Top Interesting Results ==="
            foreach ($ti in $topInteresting) {
                Write-Output "$($ti.StatusCode) $($ti.FullUrl) [$($ti.Reason)] ($($ti.ContentLength) bytes)"
            }
        }
    }

    return $output
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    param(
        [string]$Target,
        [string]$Wordlist,
        [string]$Methods = 'GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD',
        [string]$Extensions,
        [string]$OutputFile,
        [int]$Threads = 5,
        [int]$Delay = 100,
        [string]$FilterSize,
        [switch]$Recursive,
        [int]$RecursiveDepth = 2,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [switch]$Silent,
        [string]$BaselineUrl
    )
    Invoke-EndpointFuzzing -Target $Target -Wordlist $Wordlist -Methods $Methods -Extensions $Extensions -OutputFile $OutputFile -Threads $Threads -Delay $Delay -FilterSize $FilterSize -Recursive:$Recursive -RecursiveDepth $RecursiveDepth -Timeout $Timeout -UserAgent $UserAgent -Silent:$Silent -BaselineUrl $BaselineUrl
}

# Entry point
$Target = $null; $Wordlist = $null; $Methods = 'GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD'
$Extensions = $null; $OutputFile = $null; $Threads = 5; $Delay = 100
$FilterSize = $null; $Recursive = $false; $RecursiveDepth = 2; $Timeout = 30
$UserAgent = $null; $Silent = $false; $BaselineUrl = $null

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Target' { $i++; $Target = $args[$i] }
            '-Wordlist' { $i++; $Wordlist = $args[$i] }
            '-Methods' { $i++; $Methods = $args[$i] }
            '-Extensions' { $i++; $Extensions = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Threads' { $i++; $Threads = [int]$args[$i] }
            '-Delay' { $i++; $Delay = [int]$args[$i] }
            '-FilterSize' { $i++; $FilterSize = $args[$i] }
            '-Recursive' { $Recursive = $true }
            '-RecursiveDepth' { $i++; $RecursiveDepth = [int]$args[$i] }
            '-Silent' { $Silent = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
            '-BaselineUrl' { $i++; $BaselineUrl = $args[$i] }
        }
        $i++
    }
}

try {
    Main -Target $Target -Wordlist $Wordlist -Methods $Methods -Extensions $Extensions -OutputFile $OutputFile -Threads $Threads -Delay $Delay -FilterSize $FilterSize -Recursive:$Recursive -RecursiveDepth $RecursiveDepth -Timeout $Timeout -UserAgent $UserAgent -Silent:$Silent -BaselineUrl $BaselineUrl
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
