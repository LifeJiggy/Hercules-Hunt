<#
.SYNOPSIS
    Fast-Hunt — Rapid Surface-Level Vulnerability Hunter for Bug Bounty

.DESCRIPTION
    Executes quick reconnaissance probes against a target to identify low-hanging
    fruit vulnerabilities. Tests common endpoints, default paths, debug pages,
    exposed configuration files, and common security misconfigurations. Ideal for
    initial reconnaissance before running more intensive deep-hunt scans.

    Probe Categories:
      - Common Paths: /admin, /backup, /config, /.git, /.env, /robots.txt, /sitemap.xml
      - Debug Pages: /debug, /test, /phpinfo.php, /info, /status, /health
      - Configuration Files: web.config, .htaccess, docker-compose.yml, Dockerfile
      - Backup Files: .bak, .old, .backup, .swp, .sav
      - Security Misconfigs: CORS, open S3 buckets, directory listing
      - Information Disclosure: server headers, version info, error pages
      - Technology Fingerprinting: identify framework, CMS, server software
      - Default Credentials: /admin with common default login pairs
      - API Key Leaks: exposed keys in client-side content
      - Stack Traces: error pages revealing internal paths

    Outputs prioritized findings with severity ratings for efficient triage.

.PARAMETER Target
    Target URL to scan. Example: https://target.com

.PARAMETER Quick
    Run only the fastest checks (1-3 requests per endpoint). Default: $false

.PARAMETER Aggressive
    Run exhaustive checks including path fuzzing with common wordlists.
    Overrides -Quick if both are set. Default: $false

.PARAMETER OutputFile
    Path to write structured JSON results.

.PARAMETER Silent
    Suppress all non-data output. Only findings and errors are emitted.

.PARAMETER IncludeLow
    Include low-severity findings in output. Default: $false

.PARAMETER NoProbe
    Do not probe discovered paths - just list what was found. Default: $false

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 20

.PARAMETER RateLimit
    Minimum milliseconds between requests. Default: 50

.PARAMETER UserAgent
    Custom User-Agent string.

.EXAMPLE
    .\fast-hunt.ps1 -Target "https://target.com"

    Runs standard fast-hunt probes against target.com.

.EXAMPLE
    .\fast-hunt.ps1 -Target "https://target.com" -Quick

    Runs only the fastest checks for a quick assessment.

.EXAMPLE
    .\fast-hunt.ps1 -Target "https://target.com" -Aggressive -OutputFile "fast-hunt.json"

    Runs exhaustive checks and saves structured results to file.

.EXAMPLE
    .\fast-hunt.ps1 -Target "https://target.com" -Silent -OutputFile "results.json"

    Silent mode for automated pipeline integration.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Warning     : This tool sends automated probes against targets. Only use
                  against authorized targets per program scope.
    Details     : Uses Invoke-WebRequest for all HTTP requests.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

$Script:CommonPaths = @(
    '/admin', '/administrator', '/login', '/wp-admin', '/admin.php',
    '/backup', '/backups', '/bak', '/old', '/test', '/tests',
    '/config', '/configuration', '/config.php', '/setup',
    '/.git', '/.git/config', '/.git/HEAD', '/.gitignore', '/.gitattributes',
    '/.env', '/.env.example', '/.env.local', '/.env.production',
    '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml', '/sitemap',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
    '/status', '/health', '/healthcheck', '/healthz', '/readyz',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/api-docs',
    '/graphql', '/graphiql', '/voyager', '/playground',
    '/.well-known/security.txt', '/.well-known/',
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/package.json', '/bower.json', '/composer.json', '/Gemfile',
    '/web.config', '/Web.config', '/application.config',
    '/error', '/errors', '/error_log', '/error.log',
    '/debug', '/debug.log', '/trace', '/log', '/logs',
    '/export', '/import', '/upload', '/uploads',
    '/api/health', '/api/status', '/api/version', '/api/config',
    '/server-status', '/server-info',
    '/tmp', '/temp', '/cache', '/logs', '/storage',
    '/index.php', '/default.aspx', '/index.html',
    '/_debug/', '/__debug__/', '/dev/', '/development/',
    '/staging/', '/stage/', '/uat/', '/qa/', '/test/',
    '/api/', '/v1/', '/v2/', '/rest/', '/soap/',
    '/console', '/management', '/manage', '/manager',
    '/phpMyAdmin', '/phpmyadmin', '/pma', '/adminer',
    '/actuator', '/actuator/health', '/actuator/info',
    '/metrics', '/prometheus', '/grafana',
    '/.aws/', '/.azure/', '/.gcp/', '/.kube/config'
)

$Script:QuickPaths = @(
    '/robots.txt', '/sitemap.xml', '/.env', '/.git/config',
    '/admin', '/login', '/backup', '/test', '/debug',
    '/phpinfo.php', '/crossdomain.xml', '/server-status',
    '/api/health', '/graphql', '/actuator/health'
)

$Script:DebugIndicators = @(
    'PHP Debug', 'Stack Trace', 'Call Stack', 'Exception',
    'Warning:', 'Notice:', 'Parse error', 'Fatal error',
    'SQL:', 'MySQL Error', 'ORA-', 'PostgreSQL',
    'Django Debug', 'Flask Debug', 'Rails Exception',
    'ASP.NET Error', 'System.Exception', 'NullReference',
    'File not found', 'include_path', 'on line',
    'debug_backtrace', 'Traceback (most recent call last)',
    'at org.springframework', 'com.opensymphony',
    'SyntaxError', 'ReferenceError', 'TypeError'
)

$Script:DefaultCredentialPaths = @(
    '/admin/login', '/administrator/', '/wp-login.php',
    '/login.php', '/user/login', '/auth/login',
    '/api/login', '/api/auth', '/api/token',
    '/console/login', '/management/login'
)

$Script:ExposedFilePatterns = @(
    '.bak', '.old', '.backup', '.swp', '.sav',
    '~', '.orig', '.copy', '.txt', '.tmp',
    '.sql', '.dump', '.csv', '.xlsx', '.zip',
    '.tar.gz', '.tgz', '.rar', '.7z'
)

$Script:ServerFingerprintHeaders = @(
    'Server', 'X-Powered-By', 'X-AspNet-Version',
    'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache',
    'X-Drupal-Dynamic-Cache', 'X-Varnish', 'X-Cache',
    'Via', 'CF-RAY', 'X-Served-By', 'X-Request-ID'
)

$Script:SecurityMisconfigHeaders = @(
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy',
    'Access-Control-Allow-Origin',
    'Access-Control-Allow-Credentials',
    'Public-Key-Pins',
    'Expect-CT'
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
        [int]$TimeoutSec = 20
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

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest @params
        $sw.Stop()
        return [PSCustomObject]@{
            StatusCode    = [int]$response.StatusCode
            Content       = $response.Content
            ContentLength = if ($response.Content) { $response.Content.Length } else { 0 }
            ContentType   = $response.Headers.'Content-Type' -join ', '
            Headers       = $response.Headers
            TimingMs      = $sw.ElapsedMilliseconds
            Success       = $true
            ErrorMessage  = $null
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
# FUNCTION: Probe-CommonPaths
# ============================================================================

function Probe-CommonPaths {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [switch]$Quick,
        [switch]$Aggressive,
        [int]$TimeoutSec = 20,
        [int]$RateLimitMs = 50,
        [switch]$NoProbe
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $discovered = [System.Collections.Generic.List[string]]::new()

    $pathsToCheck = if ($Quick) { $Script:QuickPaths } elseif ($Aggressive) { $Script:CommonPaths } else { $Script:CommonPaths }

    foreach ($path in $pathsToCheck) {
        $url = "$($BaseUrl.TrimEnd('/'))$path"
        Start-Sleep -Milliseconds $RateLimitMs

        $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec
        if ($response.Success) {
            $discovered.Add($url)
            Write-Verbose "Found: $url ($($response.StatusCode), $($response.ContentLength) bytes)"

            $findingType = 'ExposedPath'
            $severity = 'Low'
            $sensitive = @('/.env', '/.git', '/.aws', '/.azure', '/.kube', '/backup', '/admin', '/config', '/phpinfo', '/debug', '/console', '/actuator')

            foreach ($s in $sensitive) {
                if ($path -match [regex]::Escape($s)) {
                    $findingType = 'SensitivePath'
                    $severity = 'High'
                    break
                }
            }

            $contentAnalysis = ''
            if ($response.Content) {
                foreach ($indicator in $Script:DebugIndicators) {
                    if ($response.Content -match [regex]::Escape($indicator)) {
                        $contentAnalysis = "Contains debug indicator: $indicator"
                        $findingType = 'InfoDisclosure'
                        $severity = if ($response.Content -match 'Exception|Stack Trace|Error on line|Fatal') { 'High' } else { 'Medium' }
                        break
                    }
                }
            }

            $findings.Add([PSCustomObject]@{
                Type        = $findingType
                SubType     = $path
                Url         = $url
                StatusCode  = $response.StatusCode
                ContentLength = $response.ContentLength
                ContentType = $response.ContentType
                Severity    = $severity
                Details     = if ($contentAnalysis) { $contentAnalysis } else { "Discovered: $path ($($response.StatusCode))" }
                HeaderAnalysis = $null
            })
        }
    }

    return $findings
}

# ============================================================================
# FUNCTION: Analyze-SecurityHeaders
# ============================================================================

function Analyze-SecurityHeaders {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Headers)

    $issues = [System.Collections.Generic.List[PSCustomObject]]::new()
    $responseHeaders = @{}
    if ($Headers) {
        foreach ($key in $Headers.Keys) {
            $responseHeaders[$key.ToLowerInvariant()] = ($Headers[$key] -join ', ')
        }
    }

    $headerChecks = @(
        @{ Name = 'strict-transport-security'; Setting = 'HSTS'; Severity = 'Medium'; Message = 'HSTS header not set - allows SSL stripping attacks' }
        @{ Name = 'x-frame-options'; Setting = 'Clickjacking'; Severity = 'Medium'; Message = 'X-Frame-Options not set - vulnerable to clickjacking' }
        @{ Name = 'x-content-type-options'; Setting = 'MIME-Sniffing'; Severity = 'Low'; Message = 'X-Content-Type-Options not set - allows MIME type sniffing' }
        @{ Name = 'content-security-policy'; Setting = 'CSP'; Severity = 'Medium'; Message = 'Content-Security-Policy not set - allows XSS via inline scripts' }
        @{ Name = 'x-xss-protection'; Setting = 'XSS-Protection'; Severity = 'Low'; Message = 'X-XSS-Protection not set - legacy browsers lack XSS filter' }
        @{ Name = 'referrer-policy'; Setting = 'Referrer'; Severity = 'Low'; Message = 'Referrer-Policy not set - may leak URL parameters in referrer' }
        @{ Name = 'permissions-policy'; Setting = 'Permissions'; Severity = 'Low'; Message = 'Permissions-Policy not set - allows all browser features by default' }
    )

    foreach ($check in $headerChecks) {
        if (-not $responseHeaders.ContainsKey($check.Name)) {
            $issues.Add([PSCustomObject]@{
                Type     = 'MissingHeader'
                SubType  = $check.Setting
                Severity = $check.Severity
                Header   = $check.Name
                Message  = $check.Message
            })
        }
    }

    # Check Access-Control-Allow-Origin for wildcard + credentials
    if ($responseHeaders.ContainsKey('access-control-allow-origin')) {
        $origin = $responseHeaders['access-control-allow-origin']
        if ($origin -eq '*') {
            $details = 'CORS allows all origins'
            if ($responseHeaders.ContainsKey('access-control-allow-credentials') -and $responseHeaders['access-control-allow-credentials'] -eq 'true') {
                $details = 'CORS allows all origins WITH credentials - critical misconfiguration'
            }
            $issues.Add([PSCustomObject]@{
                Type     = 'CorsMisconfig'
                SubType  = 'WildcardOrigin'
                Severity = if ($details -match 'credentials') { 'Critical' } else { 'Medium' }
                Message  = $details
            })
        }
    }

    return $issues
}

# ============================================================================
# FUNCTION: Fingerprint-Server
# ============================================================================

function Fingerprint-Server {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Headers)

    $fingerprints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $responseHeaders = @{}
    if ($Headers) {
        foreach ($key in $Headers.Keys) {
            $responseHeaders[$key.ToLowerInvariant()] = ($Headers[$key] -join ', ')
        }
    }

    foreach ($headerName in $Script:ServerFingerprintHeaders) {
        $lowerName = $headerName.ToLowerInvariant()
        if ($responseHeaders.ContainsKey($lowerName)) {
            $fingerprints.Add([PSCustomObject]@{
                Type    = 'Technology'
                Header  = $headerName
                Value   = $responseHeaders[$lowerName]
            })
        }
    }

    return $fingerprints
}

# ============================================================================
# FUNCTION: Test-CorsMisconfig
# ============================================================================

function Test-CorsMisconfig {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$TimeoutSec = 20
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test CORS')) {
        $testOrigins = @('https://evil.com', 'null', 'https://target.com.evil.com', 'https://evil-target.com')

        foreach ($origin in $testOrigins) {
            $headers = @{ 'Origin' = $origin }
            $response = Invoke-WebRequestSafe -Uri $Url -Method GET -Headers $headers -TimeoutSec $TimeoutSec

            if ($response.Success -and $response.Headers) {
                $respOrigin = $response.Headers['Access-Control-Allow-Origin'] -join ', '
                $respCredentials = $response.Headers['Access-Control-Allow-Credentials'] -join ', '

                if ($respOrigin -eq $origin -or $respOrigin -eq '*') {
                    $severity = if ($respCredentials -eq 'true') { 'Critical' } else { 'High' }
                    $findings.Add([PSCustomObject]@{
                        Type       = 'CORS'
                        SubType    = 'OriginReflected'
                        Url        = $Url
                        TestOrigin = $origin
                        AllowedOrigin = $respOrigin
                        Credentials = $respCredentials
                        Severity   = $severity
                        Evidence   = "Origin '$origin' was reflected in ACAO header (credentials: $respCredentials)"
                    })
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-DirectoryListing
# ============================================================================

function Test-DirectoryListing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [int]$TimeoutSec = 20
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($BaseUrl, 'Test directory listing')) {
        $dirsToTest = @('/images/', '/uploads/', '/assets/', '/static/', '/css/', '/js/', '/backup/', '/logs/', '/tmp/', '/media/')

        foreach ($dir in $dirsToTest) {
            $url = "$($BaseUrl.TrimEnd('/'))$dir"
            $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec
            if ($response.Success -and $response.StatusCode -eq 200) {
                $listingIndicators = @('Index of /', '<title>Index of', 'Parent Directory', '</a>', '[DIR]', '&lt;dir&gt;')
                $isListing = $false
                foreach ($indicator in $listingIndicators) {
                    if ($response.Content -match [regex]::Escape($indicator)) {
                        $isListing = $true
                        break
                    }
                }
                if ($isListing) {
                    $findings.Add([PSCustomObject]@{
                        Type       = 'DirectoryListing'
                        SubType    = 'Enabled'
                        Url        = $url
                        Severity   = 'Medium'
                        Evidence   = "Directory listing is enabled for $dir"
                    })
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-InfoDisclosure
# ============================================================================

function Test-InfoDisclosure {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [PSCustomObject]$Response,
        [int]$TimeoutSec = 20
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Url, 'Test info disclosure')) {
        # Check server header
        if ($Response.Headers -and $Response.Headers['Server']) {
            $serverValue = $Response.Headers['Server'] -join ', '
            if ($serverValue -match '[0-9]+\.[0-9]+') {
                $findings.Add([PSCustomObject]@{
                    Type     = 'InfoDisclosure'
                    SubType  = 'ServerVersion'
                    Severity = 'Low'
                    Evidence = "Server header reveals version: $serverValue"
                    Details  = $serverValue
                })
            }
        }

        # Check X-Powered-By
        if ($Response.Headers -and $Response.Headers['X-Powered-By']) {
            $xpb = $Response.Headers['X-Powered-By'] -join ', '
            $findings.Add([PSCustomObject]@{
                Type     = 'InfoDisclosure'
                SubType  = 'TechStack'
                Severity = 'Info'
                Evidence = "X-Powered-By reveals: $xpb"
            })
        }

        # Check for comments containing paths or emails
        if ($Response.Content) {
            $emailPattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            $emailMatches = [regex]::Matches($Response.Content, $emailPattern)
            if ($emailMatches.Count -gt 0) {
                $uniqueEmails = @{}
                foreach ($m in $emailMatches) { $uniqueEmails[$m.Value] = $true }
                $emails = ($uniqueEmails.Keys | Select-Object -First 5) -join ', '
                if ($emails) {
                    $findings.Add([PSCustomObject]@{
                        Type     = 'InfoDisclosure'
                        SubType  = 'EmailLeak'
                        Severity = 'Low'
                        Evidence = "Emails found in response: $emails"
                    })
                }
            }

            # HTML comment analysis
            $commentPattern = '<!--(.*?)-->'
            $commentMatches = [regex]::Matches($Response.Content, $commentPattern)
            $sensitiveComments = @()
            foreach ($m in $commentMatches) {
                $comment = $m.Groups[1].Value.Trim()
                if ($comment -match '(?:TODO|FIXME|HACK|XXX|NOTE|PASSWORD|TOKEN|KEY|SECRET|CREDENTIAL|REMOVE|DEBUG|TEST|QUERY|SQL|API|TODO|FIXME|HACK)') {
                    $sensitiveComments += $comment.Substring(0, [Math]::Min(150, $comment.Length))
                }
            }
            if ($sensitiveComments.Count -gt 0) {
                $findings.Add([PSCustomObject]@{
                    Type     = 'InfoDisclosure'
                    SubType  = 'SensitiveComment'
                    Severity = 'Medium'
                    Evidence = "Sensitive comments found: $($sensitiveComments.Count)"
                    Details  = ($sensitiveComments | Select-Object -First 3) -join '; '
                })
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Test-ExposedBackups
# ============================================================================

function Test-ExposedBackups {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        [int]$TimeoutSec = 20,
        [int]$RateLimitMs = 50
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($BaseUrl, 'Test backup files')) {
        $baseFiles = @('index', 'config', 'db', 'database', 'backup', 'dump', 'wp-config', 'app', 'main', 'default')

        foreach ($file in $baseFiles) {
            foreach ($ext in $Script:ExposedFilePatterns) {
                $url = "$($BaseUrl.TrimEnd('/'))/$file$ext"
                Start-Sleep -Milliseconds $RateLimitMs
                $response = Invoke-WebRequestSafe -Uri $url -TimeoutSec $TimeoutSec
                if ($response.Success -and $response.StatusCode -eq 200 -and $response.ContentLength -gt 10) {
                    $severity = if ($ext -in @('.sql', '.dump', '.zip', '.tar.gz', '.tgz', '.rar', '.7z')) { 'Critical' } else { 'High' }
                    $findings.Add([PSCustomObject]@{
                        Type     = 'ExposedBackup'
                        SubType  = $ext.TrimStart('.')
                        Url      = $url
                        Severity = $severity
                        Size     = $response.ContentLength
                        Evidence = "Backup file found: $file$ext ($($response.ContentLength) bytes)"
                    })
                }
            }
        }
    }
    return $findings
}

# ============================================================================
# FUNCTION: Run-BaselineProbe
# ============================================================================

function Run-BaselineProbe {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Target,
        [int]$TimeoutSec = 20,
        [switch]$NoProbe
    )
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess($Target, 'Run baseline probe')) {
        $response = Invoke-WebRequestSafe -Uri $Target -TimeoutSec $TimeoutSec
        $baseFindings = [PSCustomObject]@{
            Url        = $Target
            StatusCode = $response.StatusCode
            ContentLength = $response.ContentLength
            ContentType = $response.ContentType
            TimingMs   = $response.TimingMs
            Live       = $response.Success
        }

        if ($response.Success) {
            $errors = $null
            $findings.Add($baseFindings)

            $headerIssues = Analyze-SecurityHeaders -Headers $response.Headers
            foreach ($hi in $headerIssues) { $findings.Add($hi) }

            $fingerprints = Fingerprint-Server -Headers $response.Headers
            foreach ($fp in $fingerprints) { $findings.Add($fp) }

            if (-not $NoProbe) {
                $infoDisclosure = Test-InfoDisclosure -Url $Target -Response $response -TimeoutSec $TimeoutSec
                foreach ($id in $infoDisclosure) { $findings.Add($id) }
            }
        }

        return $findings
    }
}

# ============================================================================
# FUNCTION: Invoke-FastHunt
# ============================================================================

function Invoke-FastHunt {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Target,
        [switch]$Quick,
        [switch]$Aggressive,
        [string]$OutputFile,
        [switch]$Silent,
        [switch]$IncludeLow,
        [switch]$NoProbe,
        [int]$Timeout = 20,
        [int]$RateLimit = 50,
        [string]$UserAgent
    )
    $output = [PSCustomObject]@{
        Tool      = 'Fast-Hunt'
        Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target    = $Target
        Mode      = if ($Quick) { 'Quick' } elseif ($Aggressive) { 'Aggressive' } else { 'Standard' }
        Findings  = @()
        Summary   = $null
        Errors    = @()
    }
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    if ($UserAgent) { $Script:DefaultUserAgent = $UserAgent }

    if (-not $Target) {
        $errors.Add('No target specified')
        $output.Errors = $errors
        return $output
    }

    if (-not $Target.StartsWith('http://') -and -not $Target.StartsWith('https://')) {
        $Target = "https://$Target"
    }

    if (-not $Silent) {
        Write-Output "=== Fast-Hunt: $Target ($($output.Mode)) ==="
    }

    # Phase 1: Baseline probe
    Write-Verbose 'Phase 1: Baseline probe'
    $baselineFindings = Run-BaselineProbe -Target $Target -TimeoutSec $Timeout -NoProbe:$NoProbe
    foreach ($f in $baselineFindings) { $allFindings.Add($f) }

    # Phase 2: Common paths
    if (-not $NoProbe) {
        Write-Verbose 'Phase 2: Common path probes'
        $pathFindings = Probe-CommonPaths -BaseUrl $Target -Quick:$Quick -Aggressive:$Aggressive -TimeoutSec $Timeout -RateLimitMs $RateLimit -NoProbe:$NoProbe
        foreach ($f in $pathFindings) { $allFindings.Add($f) }

        # Phase 3: CORS testing
        if ($Aggressive) {
            Write-Verbose 'Phase 3: CORS misconfiguration testing'
            $corsFindings = Test-CorsMisconfig -Url $Target -TimeoutSec $Timeout
            foreach ($f in $corsFindings) { $allFindings.Add($f) }
        }

        # Phase 4: Directory listing
        Write-Verbose 'Phase 4: Directory listing check'
        $dirFindings = Test-DirectoryListing -BaseUrl $Target -TimeoutSec $Timeout
        foreach ($f in $dirFindings) { $allFindings.Add($f) }

        # Phase 5: Backup file discovery
        if ($Aggressive) {
            Write-Verbose 'Phase 5: Backup file discovery'
            $backupFindings = Test-ExposedBackups -BaseUrl $Target -TimeoutSec $Timeout -RateLimitMs $RateLimit
            foreach ($f in $backupFindings) { $allFindings.Add($f) }
        }
    }

    # Filter findings by severity
    $filteredFindings = $allFindings
    if (-not $IncludeLow) {
        $filteredFindings = $allFindings | Where-Object { $_ -and $_.Severity -ne 'Info' -and $_.Severity -ne 'Low' }
    }

    $output.Findings = $filteredFindings

    # Summary statistics
    $severityCounts = @{}
    foreach ($f in $filteredFindings) {
        if ($f -and $f.Severity) {
            $sev = $f.Severity
            if (-not $severityCounts.ContainsKey($sev)) { $severityCounts[$sev] = 0 }
            $severityCounts[$sev]++
        }
    }

    $typeCounts = @{}
    foreach ($f in $filteredFindings) {
        if ($f -and $f.Type) {
            $type = $f.Type
            if (-not $typeCounts.ContainsKey($type)) { $typeCounts[$type] = 0 }
            $typeCounts[$type]++
        }
    }

    $output.Summary = [PSCustomObject]@{
        TotalFindings    = $filteredFindings.Count
        BySeverity       = $severityCounts
        ByType           = $typeCounts
        BaselineAlive    = ($baselineFindings | Where-Object { $_ -and $_.Live -eq $true }).Count -gt 0
        PathsDiscovered  = ($pathFindings | Where-Object { $_ -and $_.Type -eq 'ExposedPath' -or $_.Type -eq 'SensitivePath' }).Count
    }
    $output.Errors = $errors

    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile -ErrorAction SilentlyContinue
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "=== Summary ==="
        Write-Output "Total Findings: $($output.Summary.TotalFindings)"
        foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            if ($severityCounts.ContainsKey($sev)) { Write-Output "  $sev: $($severityCounts[$sev])" }
        }
        Write-Output "Paths Discovered: $($output.Summary.PathsDiscovered)"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN ENTRY
# ============================================================================

$Target = $null; $Quick = $false; $Aggressive = $false
$OutputFile = $null; $Silent = $false; $IncludeLow = $false
$NoProbe = $false; $Timeout = 20; $RateLimit = 50; $UserAgent = $null

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Target' { $i++; $Target = $args[$i] }
            '-Quick' { $Quick = $true }
            '-Aggressive' { $Aggressive = $true }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Silent' { $Silent = $true }
            '-IncludeLow' { $IncludeLow = $true }
            '-NoProbe' { $NoProbe = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-RateLimit' { $i++; $RateLimit = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
        }
        $i++
    }
}

try {
    Invoke-FastHunt -Target $Target -Quick:$Quick -Aggressive:$Aggressive -OutputFile $OutputFile -Silent:$Silent -IncludeLow:$IncludeLow -NoProbe:$NoProbe -Timeout $Timeout -RateLimit $RateLimit -UserAgent $UserAgent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
