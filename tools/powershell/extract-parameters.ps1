<#
.SYNOPSIS
    Extract-Parameters — HTTP Parameter Extraction and Analysis Tool for Bug Bounty

.DESCRIPTION
    Discovers and extracts parameters from all HTTP interaction surfaces including
    GET query strings, POST bodies, URL-encoded data, JSON payloads, HTTP headers,
    and cookies. Performs URL parsing for query parameters, JSON body parameter
    discovery, and optional parameter name fuzzing to discover hidden parameters.

    Capabilities:
      - GET query string parameter extraction and analysis
      - POST form-data and JSON body parameter discovery
      - HTTP header parameter extraction (custom headers, auth headers)
      - Cookie parameter analysis
      - URL path parameter detection (/api/users/{id}/posts)
      - JSON schema inference from API responses
      - Parameter type detection (numeric, string, boolean, array, object)
      - Required vs optional parameter inference
      - Parameter value enumeration and pattern analysis
      - Optional fuzzing mode to discover undocumented parameters
      - Common parameter name dictionary for smart fuzzing
      - Parameter name normalization and deduplication
      - Structured JSON output for pipeline integration

.PARAMETER Url
    Target URL to analyze for parameters. Example: https://target.com/api/users

.PARAMETER FilePath
    Local file path to analyze (HTML, JSON, or HAR file). Can be combined with -Url.

.PARAMETER Method
    HTTP method to use for requests. Default: GET. Examples: GET, POST, PUT

.PARAMETER Body
    Request body template (JSON or form-encoded). Example: '{"name":"test","email":"test@test.com"}'

.PARAMETER Headers
    Additional HTTP headers as JSON string. Example: '{"Authorization":"Bearer token","X-Custom":"value"}'

.PARAMETER OutputFile
    Path to write structured JSON results.

.PARAMETER Fuzz
    Enable parameter fuzzing to discover hidden/undocumented parameters. Default: $false

.PARAMETER FuzzWordlist
    Path to custom fuzz wordlist file. Uses built-in list if not specified.

.PARAMETER Depth
    Recursion depth for nested parameter analysis in JSON. Default: 3

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER Silent
    Suppress all non-data output.

.PARAMETER ExtractHeaders
    Extract and analyze HTTP headers as parameters. Default: $true

.PARAMETER ExtractCookies
    Extract and analyze cookie parameters. Default: $true

.EXAMPLE
    .\extract-parameters.ps1 -Url "https://target.com/api/users?id=1&name=john&active=true"

    Extracts all parameters from the query string and classifies them by type.

.EXAMPLE
    .\extract-parameters.ps1 -Url "https://target.com/api/login" -Method POST -Body '{"username":"test","password":"test123"}'

    Analyzes POST parameters from JSON body payload.

.EXAMPLE
    .\extract-parameters.ps1 -Url "https://target.com/api/search" -Fuzz -OutputFile "params.json"

    Extracts visible parameters and fuzzes for hidden ones, saving results to file.

.EXAMPLE
    .\extract-parameters.ps1 -Url "https://target.com/api/users/{id}/posts" -Depth 5

    Extracts path parameters with deep nested analysis.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Details     : Uses Invoke-WebRequest for HTTP. Native JSON parsing.
    Security    : Parameter fuzzing may trigger rate limits. Use responsibly.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

$Script:CommonFuzzParams = @(
    'id', 'user_id', 'userId', 'userid', 'uid', 'uuid', 'token', 'access_token',
    'api_key', 'apikey', 'api-key', 'key', 'secret', 'password', 'passwd', 'pwd',
    'email', 'mail', 'username', 'login', 'name', 'fullname', 'firstname', 'lastname',
    'role', 'admin', 'is_admin', 'isAdmin', 'type', 'status', 'active', 'enabled',
    'limit', 'offset', 'page', 'per_page', 'perPage', 'sort', 'order', 'dir',
    'filter', 'search', 'q', 'query', 'term', 'keyword',
    'format', 'response_type', 'responseType', 'callback', 'jsonp',
    'redirect', 'redirect_uri', 'redirectUri', 'next', 'return', 'return_url',
    'url', 'uri', 'link', 'href', 'src', 'source', 'target',
    'file', 'filename', 'path', 'dir', 'directory',
    'debug', 'verbose', 'trace', 'log', 'logging',
    'timestamp', 'date', 'time', 'expires', 'expiry',
    'version', 'v', 'locale', 'lang', 'language',
    'action', 'method', 'operation', 'command',
    'data', 'payload', 'body', 'content', 'text',
    'include', 'exclude', 'fields', 'select', 'expand',
    'embed', 'depth', 'recursive', 'children',
    'sig', 'signature', 'hash', 'checksum',
    'nonce', 'state', 'scope', 'grant_type',
    'client_id', 'client_secret', 'code', 'auth_code',
    'session', 'session_id', 'sid', 'csrf', 'csrf_token',
    'X-Requested-With', 'X-Forwarded-For', 'X-Real-IP',
    'X-Forwarded-Proto', 'X-Forwarded-Host'
)

$Script:ParameterTypePatterns = @(
    @{ Pattern = '^\d+$'; Type = 'integer' }
    @{ Pattern = '^\d+\.\d+$'; Type = 'float' }
    @{ Pattern = '^true$|^false$'; Type = 'boolean' }
    @{ Pattern = '^[a-f0-9]{32}$'; Type = 'md5' }
    @{ Pattern = '^[a-f0-9]{40}$'; Type = 'sha1' }
    @{ Pattern = '^[a-f0-9]{64}$'; Type = 'sha256' }
    @{ Pattern = '^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+$'; Type = 'jwt' }
    @{ Pattern = '^[a-zA-Z0-9.!#$%&*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$'; Type = 'email' }
    @{ Pattern = '^https?://.+'; Type = 'url' }
    @{ Pattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; Type = 'uuid' }
    @{ Pattern = '^\d{4}-\d{2}-\d{2}'; Type = 'date' }
    @{ Pattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}'; Type = 'datetime' }
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

    try {
        $response = Invoke-WebRequest @params
        return [PSCustomObject]@{
            StatusCode   = [int]$response.StatusCode
            Content      = $response.Content
            ContentType  = $response.Headers.'Content-Type' -join ', '
            Headers      = $response.Headers
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
            Success      = $false
            ErrorMessage = $_.Exception.Message
        }
    }
}

# ============================================================================
# FUNCTION: Extract-QueryStringParameters
# ============================================================================

function Extract-QueryStringParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url)
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()

    $uri = $null
    try { $uri = [System.Uri]$Url } catch { return $params }
    $queryString = $uri.Query
    if (-not $queryString) { return $params }

    $queryString = $queryString.TrimStart('?')
    $pairs = $queryString -split '&'

    foreach ($pair in $pairs) {
        if (-not $pair) { continue }
        $split = $pair -split '=', 2
        $name = [System.Web.HttpUtility]::UrlDecode($split[0])
        $value = if ($split.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($split[1]) } else { '' }

        $paramType = Classify-ParameterType -Value $value
        $params.Add([PSCustomObject]@{
            Name       = $name
            Value      = $value
            Type       = $paramType
            Source     = 'QueryString'
            Required   = $false
            Sample     = $value
        })
    }
    return $params
}

# ============================================================================
# FUNCTION: Extract-PathParameters
# ============================================================================

function Extract-PathParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url)
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()

    $uri = $null
    try { $uri = [System.Uri]$Url } catch { return $params }

    foreach ($segment in $uri.Segments) {
        $segment = $segment.Trim('/')
        if (-not $segment) { continue }

        # Detect path parameters (numeric IDs, UUIDs, hashes)
        $classified = Classify-ParameterType -Value $segment
        if ($classified -in @('integer', 'uuid', 'md5', 'sha1', 'sha256')) {
            $paramName = $classified
            if ($classified -eq 'integer') {
                $prevSegments = $uri.Segments | Where-Object { $_ -ne $segment }
                $lastPrev = ($prevSegments | Select-Object -Last 1) -replace '/', '' -replace '-', '_'
                if ($lastPrev) { $paramName = "${lastPrev}_id" }
            }
            $params.Add([PSCustomObject]@{
                Name       = $paramName
                Value      = $segment
                Type       = $classified
                Source     = 'Path'
                Required   = $true
                Sample     = $segment
            })
        }
    }

    # Detect template-style parameters in URL
    $templatePattern = '\{([^}]+)\}'
    $matches = [regex]::Matches($Url, $templatePattern)
    foreach ($m in $matches) {
        $paramName = $m.Groups[1].Value.Trim()
        $params.Add([PSCustomObject]@{
            Name       = $paramName
            Value      = '{' + $paramName + '}'
            Type       = 'string'
            Source     = 'PathTemplate'
            Required   = $true
            Sample     = '{' + $paramName + '}'
        })
    }

    return $params
}

# ============================================================================
# FUNCTION: Extract-PostBodyParameters
# ============================================================================

function Extract-PostBodyParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Body,
        [string]$ContentType,
        [int]$Depth = 3,
        [string]$ParentKey = ''
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Body) { return $params }

    # JSON body
    if ($ContentType -like '*json*' -or ($Body -match '^\{') -or ($Body -match '^\[')) {
        try {
            $parsed = $Body | ConvertFrom-Json
            $params = Parse-JsonObject -Object $parsed -Depth $Depth -ParentKey $ParentKey
        }
        catch {
            # Not valid JSON, try form-urlencoded
            $params = Extract-FormUrlEncodedParameters -Body $Body
        }
    }
    elseif ($ContentType -like '*x-www-form-urlencoded*' -or $Body -match '^[a-zA-Z0-9_]+=') {
        $params = Extract-FormUrlEncodedParameters -Body $Body
    }
    elseif ($ContentType -like '*xml*' -or $Body -match '^<\?xml|<[a-zA-Z]+') {
        $params = Extract-XmlParameters -Body $Body -Depth $Depth
    }
    else {
        $params.Add([PSCustomObject]@{
            Name       = 'body_raw'
            Value      = $Body.Substring(0, [Math]::Min(200, $Body.Length))
            Type       = 'raw'
            Source     = 'Body'
            Required   = $true
            Sample     = $Body.Substring(0, [Math]::Min(200, $Body.Length))
        })
    }

    return $params
}

# ============================================================================
# FUNCTION: Parse-JsonObject
# ============================================================================

function Parse-JsonObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Object,
        [int]$Depth = 3,
        [string]$ParentKey = '',
        [int]$CurrentDepth = 0
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($CurrentDepth -gt $Depth) { return $params }

    if ($Object -is [PSCustomObject]) {
        foreach ($prop in $Object.PSObject.Properties) {
            $fullName = if ($ParentKey) { "$ParentKey.$($prop.Name)" } else { $prop.Name }
            $value = $prop.Value

            if ($null -eq $value) {
                $params.Add([PSCustomObject]@{
                    Name   = $fullName
                    Value  = $null
                    Type   = 'null'
                    Source = 'Body(JSON)'
                    Required = $false
                    Sample = $null
                })
            }
            elseif ($value -is [PSCustomObject]) {
                $nestedParams = Parse-JsonObject -Object $value -Depth $Depth -ParentKey $fullName -CurrentDepth ($CurrentDepth + 1)
                foreach ($np in $nestedParams) { $params.Add($np) }
            }
            elseif ($value -is [array]) {
                $paramType = if ($value.Count -gt 0) { "array<$($value[0].GetType().Name)>" } else { 'array<unknown>' }
                $sample = if ($value.Count -gt 0) { $value[0].ToString() } else { '[]' }
                $params.Add([PSCustomObject]@{
                    Name   = $fullName
                    Value  = $value
                    Type   = $paramType
                    Source = 'Body(JSON)'
                    Required = $false
                    Sample = $sample
                })
            }
            else {
                $classifiedType = Classify-ParameterType -Value $value.ToString()
                $params.Add([PSCustomObject]@{
                    Name   = $fullName
                    Value  = $value
                    Type   = $classifiedType
                    Source = 'Body(JSON)'
                    Required = $false
                    Sample = $value.ToString()
                })
            }
        }
    }
    elseif ($Object -is [array]) {
        for ($i = 0; $i -lt [Math]::Min($Object.Count, 5); $i++) {
            $fullName = if ($ParentKey) { "$ParentKey[$i]" } else { "[$i]" }
            if ($Object[$i] -is [PSCustomObject]) {
                $nestedParams = Parse-JsonObject -Object $Object[$i] -Depth $Depth -ParentKey $fullName -CurrentDepth ($CurrentDepth + 1)
                foreach ($np in $nestedParams) { $params.Add($np) }
            }
        }
    }

    return $params
}

# ============================================================================
# FUNCTION: Extract-FormUrlEncodedParameters
# ============================================================================

function Extract-FormUrlEncodedParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Body)
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pairs = $Body -split '&'

    foreach ($pair in $pairs) {
        if (-not $pair) { continue }
        $split = $pair -split '=', 2
        $name = [System.Web.HttpUtility]::UrlDecode($split[0])
        $value = if ($split.Count -gt 1) { [System.Web.HttpUtility]::UrlDecode($split[1]) } else { '' }

        $paramType = Classify-ParameterType -Value $value
        $params.Add([PSCustomObject]@{
            Name   = $name
            Value  = $value
            Type   = $paramType
            Source = 'Body(Form)'
            Required = $false
            Sample = $value
        })
    }
    return $params
}

# ============================================================================
# FUNCTION: Extract-XmlParameters
# ============================================================================

function Extract-XmlParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Body,
        [int]$Depth = 3
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $xml = [System.Xml.XmlDocument]::new()
        $xml.LoadXml($Body)
        $stack = [System.Collections.Generic.Stack[tuple]]::new()
        $stack.Push([tuple]::Create($xml.DocumentElement, ''))

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $element = $current.Item1
            $parentPath = $current.Item2

            foreach ($child in $element.ChildNodes) {
                if ($child.NodeType -eq 'Element') {
                    $fullPath = if ($parentPath) { "$parentPath/$($child.Name)" } else { $child.Name }

                    if ($child.HasChildNodes -and $child.ChildNodes.Count -eq 1 -and $child.ChildNodes[0].NodeType -eq 'Text') {
                        $paramType = Classify-ParameterType -Value $child.InnerText
                        $params.Add([PSCustomObject]@{
                            Name   = $fullPath
                            Value  = $child.InnerText
                            Type   = $paramType
                            Source = 'Body(XML)'
                            Required = $false
                            Sample = $child.InnerText
                        })
                    }

                    if ($child.HasChildNodes) {
                        $stack.Push([tuple]::Create($child, $fullPath))
                    }
                }
            }
        }
    }
    catch {
        $params.Add([PSCustomObject]@{
            Name   = 'xml_error'
            Value  = 'Could not parse XML'
            Type   = 'error'
            Source = 'Body(XML)'
            Required = $false
            Sample = $null
        })
    }
    return $params
}

# ============================================================================
# FUNCTION: Extract-HeaderParameters
# ============================================================================

function Extract-HeaderParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Headers) { return $params }

    foreach ($key in $Headers.Keys) {
        $value = ($Headers[$key] -join ', ')
        $paramType = Classify-ParameterType -Value $value

        # Classify header type
        $headerCategory = 'Custom'
        $knownHeaders = @{
            'Authorization' = 'Auth'
            'Content-Type' = 'Content'
            'Accept' = 'Content'
            'Cookie' = 'Session'
            'User-Agent' = 'Client'
            'Referer' = 'Navigation'
            'Origin' = 'Security'
            'Host' = 'Network'
            'X-Forwarded-For' = 'Proxy'
            'X-Real-IP' = 'Proxy'
            'X-Requested-With' = 'Ajax'
            'X-CSRF-Token' = 'Security'
            'X-Auth-Token' = 'Auth'
        }
        if ($knownHeaders.ContainsKey($key)) { $headerCategory = $knownHeaders[$key] }

        $params.Add([PSCustomObject]@{
            Name   = $key
            Value  = $value.Substring(0, [Math]::Min(200, $value.Length))
            Type   = $paramType
            Source = "Header($headerCategory)"
            Required = $false
            Sample = $value.Substring(0, [Math]::Min(100, $value.Length))
        })
    }
    return $params
}

# ============================================================================
# FUNCTION: Extract-CookieParameters
# ============================================================================

function Extract-CookieParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Headers -or -not $Headers['Cookie']) { return $params }

    $cookieValue = $Headers['Cookie'] -join '; '
    $cookies = $cookieValue -split ';'

    foreach ($cookie in $cookies) {
        $cookie = $cookie.Trim()
        if (-not $cookie) { continue }
        $split = $cookie -split '=', 2
        $name = $split[0].Trim()
        $value = if ($split.Count -gt 1) { $split[1].Trim() } else { '' }
        $paramType = Classify-ParameterType -Value $value

        $params.Add([PSCustomObject]@{
            Name   = $name
            Value  = $value.Substring(0, [Math]::Min(200, $value.Length))
            Type   = $paramType
            Source = 'Cookie'
            Required = $false
            Sample = $value.Substring(0, [Math]::Min(100, $value.Length))
        })
    }
    return $params
}

# ============================================================================
# FUNCTION: Classify-ParameterType
# ============================================================================

function Classify-ParameterType {
    [CmdletBinding()]
    param([string]$Value)

    if (-not $Value) { return 'empty' }
    $trimmed = $Value.Trim()

    foreach ($rule in $Script:ParameterTypePatterns) {
        if ($trimmed -match $rule.Pattern) { return $rule.Type }
    }

    return 'string'
}

# ============================================================================
# FUNCTION: Fuzz-Parameters
# ============================================================================

function Fuzz-Parameters {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType,
        [hashtable]$Headers,
        [string[]]$Wordlist,
        [int]$TimeoutSec = 30,
        [int]$RateLimitMs = 100
    )
    $allParams = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $PSCmdlet.ShouldProcess($Url, 'Fuzz parameters')) { return $allParams }

    if (-not $Wordlist) { $Wordlist = $Script:CommonFuzzParams }

    $baseUrl = $Url.Split('?')[0]
    $existingParams = Extract-QueryStringParameters -Url $Url
    $existingNames = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($ep in $existingParams) { $null = $existingNames.Add($ep.Name.ToLowerInvariant()) }

    $baselineResponse = Invoke-WebRequestSafe -Uri $Url -Method $Method -Body $Body -ContentType $ContentType -Headers $Headers -TimeoutSec $TimeoutSec
    $baselineSize = if ($baselineResponse.Success -and $baselineResponse.Content) { $baselineResponse.Content.Length } else { 0 }
    $baselineStatusCode = $baselineResponse.StatusCode

    foreach ($paramName in $Wordlist) {
        $lowerName = $paramName.ToLowerInvariant()
        if ($existingNames.Contains($lowerName)) { continue }
        $existingNames.Add($lowerName)

        Start-Sleep -Milliseconds $RateLimitMs
        $fuzzUrl = if ($Method -eq 'GET') {
            $separator = if ($baseUrl.Contains('?')) { '&' } else { '?' }
            "$baseUrl$separator$paramName=test"
        } else { $Url }

        $response = Invoke-WebRequestSafe -Uri $fuzzUrl -Method $Method -Body $Body -ContentType $ContentType -Headers $Headers -TimeoutSec $TimeoutSec

        if ($response.Success) {
            $responseSize = if ($response.Content) { $response.Content.Length } else { 0 }
            $sizeDelta = $responseSize - $baselineSize
            $statusChanged = ($response.StatusCode -ne $baselineStatusCode)

            # A parameter that changes the response significantly is interesting
            if ([Math]::Abs($sizeDelta) -gt 100 -or $statusChanged) {
                $allParams.Add([PSCustomObject]@{
                    Name             = $paramName
                    Value            = 'test'
                    Type             = 'fuzzed'
                    Source           = 'Fuzz'
                    Required         = $false
                    Sample           = 'test'
                    DetectedBy       = if ($statusChanged) { "Status change: $baselineStatusCode -> $($response.StatusCode)" } else { "Size change: $sizeDelta bytes" }
                    BaselineStatus   = $baselineStatusCode
                    FuzzStatus       = $response.StatusCode
                    SizeDelta        = $sizeDelta
                })
            }
        }
    }

    return $allParams
}

# ============================================================================
# FUNCTION: Analyze-ResponseForParameters
# ============================================================================

function Analyze-ResponseForParameters {
    [CmdletBinding()]
    param(
        [string]$Content,
        [string]$ContentType,
        [int]$Depth = 3
    )
    $params = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Content) { return $params }

    # JSON response - extract field names as potential parameters
    if ($ContentType -like '*json*' -or ($Content -match '^\s*\{') -or ($Content -match '^\s*\[')) {
        try {
            $parsed = $Content | ConvertFrom-Json
            $responseParams = Parse-JsonObject -Object $parsed -Depth $Depth -ParentKey ''
            foreach ($p in $responseParams) {
                if ($p.Source -eq 'Body(JSON)') {
                    $paramObj = [PSCustomObject]@{
                        Name   = $p.Name
                        Value  = $p.Sample
                        Type   = $p.Type
                        Source = 'Response(JSON)'
                        Required = $false
                        Sample = $p.Sample
                    }
                    $params.Add($paramObj)
                }
            }
        }
        catch { Write-Verbose "Could not parse JSON response: $($_.Exception.Message)" }
    }

    # HTML form fields
    if ($ContentType -like '*html*') {
        $formFieldPattern = '<input[^>]*name\s*=\s*["'']([^"''\s>]+)["'']'
        $matches = [regex]::Matches($Content, $formFieldPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $matches) {
            $name = $m.Groups[1].Value.Trim()
            if (-not $seen.Contains($name.ToLowerInvariant())) {
                $null = $seen.Add($name.ToLowerInvariant())
                $params.Add([PSCustomObject]@{
                    Name   = $name
                    Value  = ''
                    Type   = 'form_field'
                    Source = 'HTML Form'
                    Required = $true
                    Sample = ''
                })
            }
        }

        $selectPattern = '<select[^>]*name\s*=\s*["'']([^"''\s>]+)["'']'
        $selectMatches = [regex]::Matches($Content, $selectPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $selectMatches) {
            $name = $m.Groups[1].Value.Trim()
            if (-not $seen.Contains($name.ToLowerInvariant())) {
                $null = $seen.Add($name.ToLowerInvariant())
                $params.Add([PSCustomObject]@{
                    Name   = $name
                    Value  = ''
                    Type   = 'select'
                    Source = 'HTML Form'
                    Required = $false
                    Sample = ''
                })
            }
        }

        $textareaPattern = '<textarea[^>]*name\s*=\s*["'']([^"''\s>]+)["'']'
        $textareaMatches = [regex]::Matches($Content, $textareaPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $textareaMatches) {
            $name = $m.Groups[1].Value.Trim()
            if (-not $seen.Contains($name.ToLowerInvariant())) {
                $null = $seen.Add($name.ToLowerInvariant())
                $params.Add([PSCustomObject]@{
                    Name   = $name
                    Value  = ''
                    Type   = 'textarea'
                    Source = 'HTML Form'
                    Required = $false
                    Sample = ''
                })
            }
        }

        # JavaScript variable assignments
        $jsVarPattern = '(?:var|let|const)\s+(\w+)\s*=\s*["'']?([^"''\s;]+)["'']?'
        $jsMatches = [regex]::Matches($Content, $jsVarPattern)
        $jsSeen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($m in $jsMatches) {
            $name = $m.Groups[1].Value.Trim()
            $value = $m.Groups[2].Value.Trim()
            if (-not $jsSeen.Contains($name.ToLowerInvariant())) {
                $null = $jsSeen.Add($name.ToLowerInvariant())
                if ($name -match '^(?:api|endpoint|url|uri|base|service|token|key|secret|auth)') {
                    $params.Add([PSCustomObject]@{
                        Name   = $name
                        Value  = $value.Substring(0, [Math]::Min(200, $value.Length))
                        Type   = 'js_var'
                        Source = 'JavaScript'
                        Required = $false
                        Sample = $value.Substring(0, [Math]::Min(100, $value.Length))
                    })
                }
            }
        }
    }

    return $params
}

# ============================================================================
# FUNCTION: Invoke-ParameterExtraction
# ============================================================================

function Invoke-ParameterExtraction {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$Headers,
        [string]$OutputFile,
        [switch]$Fuzz,
        [string]$FuzzWordlist,
        [int]$Depth = 3,
        [int]$Timeout = 30,
        [switch]$Silent,
        [switch]$ExtractHeaders,
        [switch]$ExtractCookies
    )
    $output = [PSCustomObject]@{
        Tool       = 'Extract-Parameters'
        Timestamp  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target     = if ($Url) { $Url } else { $FilePath }
        Method     = $Method
        Parameters = @()
        BySource   = @{}
        FuzzParams = @()
        Stats      = $null
        Errors     = @()
    }
    $allParams = [System.Collections.Generic.List[PSCustomObject]]::new()
    $fuzzResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    $headerHashtable = $null
    if ($Headers) {
        try { $headerHashtable = $Headers | ConvertFrom-Json -AsHashtable }
        catch { $errors.Add("Invalid Headers JSON: $($_.Exception.Message)") }
    }

    # Phase 1: Extract from URL
    if ($Url) {
        Write-Verbose "Extracting from URL: $Url"

        $queryParams = Extract-QueryStringParameters -Url $Url
        foreach ($p in $queryParams) { $allParams.Add($p) }
        Write-Verbose "  Query params: $($queryParams.Count)"

        $pathParams = Extract-PathParameters -Url $Url
        foreach ($p in $pathParams) { $allParams.Add($p) }
        Write-Verbose "  Path params: $($pathParams.Count)"

        # Phase 2: Make request to get response
        if (-not $FilePath) {
            Write-Verbose "Making $Method request to $Url"
            $response = Invoke-WebRequestSafe -Uri $Url -Method $Method -Body $Body -Headers $headerHashtable -TimeoutSec $Timeout

            if ($response.Success) {
                # Extract from response content
                $responseParams = Analyze-ResponseForParameters -Content $response.Content -ContentType $response.ContentType -Depth $Depth
                foreach ($p in $responseParams) { $allParams.Add($p) }
                Write-Verbose "  Response params: $($responseParams.Count)"

                # Extract headers
                if ($ExtractHeaders -and $response.Headers) {
                    $headerParams = Extract-HeaderParameters -Headers $response.Headers
                    foreach ($p in $headerParams) { $allParams.Add($p) }
                    Write-Verbose "  Header params: $($headerParams.Count)"
                }

                # Extract cookies
                if ($ExtractCookies -and $response.Headers) {
                    $cookieParams = Extract-CookieParameters -Headers $response.Headers
                    foreach ($p in $cookieParams) { $allParams.Add($p) }
                    Write-Verbose "  Cookie params: $($cookieParams.Count)"
                }
            }
            else {
                $errors.Add("Request failed: $($response.ErrorMessage)")
            }
        }

        # Phase 3: Extract from POST body
        if ($Body -and $Method -match 'POST|PUT|PATCH') {
            $bodyParams = Extract-PostBodyParameters -Body $Body -ContentType ($headerHashtable['Content-Type']) -Depth $Depth
            foreach ($p in $bodyParams) { $allParams.Add($p) }
            Write-Verbose "  Body params: $($bodyParams.Count)"
        }
    }

    # Phase 4: Extract from file
    if ($FilePath) {
        if (Test-Path -LiteralPath $FilePath) {
            Write-Verbose "Reading file: $FilePath"
            $content = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
            $ext = [System.IO.Path]::GetExtension($FilePath).ToLowerInvariant()

            if ($ext -in @('.json', '.har')) {
                $fileParams = Analyze-ResponseForParameters -Content $content -ContentType 'application/json' -Depth $Depth
                foreach ($p in $fileParams) { $allParams.Add($p) }
            }
            elseif ($ext -in @('.html', '.htm')) {
                $fileParams = Analyze-ResponseForParameters -Content $content -ContentType 'text/html' -Depth $Depth
                foreach ($p in $fileParams) { $allParams.Add($p) }
            }
            elseif ($ext -eq '.xml') {
                $xmlParams = Extract-XmlParameters -Body $content -Depth $Depth
                foreach ($p in $xmlParams) { $allParams.Add($p) }
            }
        }
        else {
            $errors.Add("File not found: $FilePath")
        }
    }

    # Phase 5: Parameter fuzzing
    if ($Fuzz -and $Url) {
        Write-Verbose 'Parameter fuzzing enabled'
        $wordlistArray = $null
        if ($FuzzWordlist -and (Test-Path -LiteralPath $FuzzWordlist)) {
            $wordlistArray = Get-Content -LiteralPath $FuzzWordlist
        }
        $fuzzResultsList = Fuzz-Parameters -Url $Url -Method $Method -Body $Body -Headers $headerHashtable -Wordlist $wordlistArray -TimeoutSec $Timeout
        foreach ($f in $fuzzResultsList) { $fuzzResults.Add($f) }
        Write-Verbose "  Fuzz params: $($fuzzResults.Count)"
    }

    # Deduplicate by name
    $dedupMap = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $allParams) {
        $key = "$($p.Source):$($p.Name)"
        if (-not $dedupMap.ContainsKey($key)) { $dedupMap[$key] = $p }
    }

    $output.Parameters = $dedupMap.Values
    $output.FuzzParams = $fuzzResults

    # Stats by source
    $sourceCounts = @{}
    foreach ($p in $output.Parameters) {
        $source = $p.Source
        if (-not $sourceCounts.ContainsKey($source)) { $sourceCounts[$source] = 0 }
        $sourceCounts[$source]++
    }
    $output.BySource = $sourceCounts

    $typeCounts = @{}
    foreach ($p in $output.Parameters) {
        $type = $p.Type
        if (-not $typeCounts.ContainsKey($type)) { $typeCounts[$type] = 0 }
        $typeCounts[$type]++
    }

    $output.Stats = [PSCustomObject]@{
        TotalParams    = $output.Parameters.Count
        BySource       = $sourceCounts
        ByType         = $typeCounts
        FuzzedDiscovered = $fuzzResults.Count
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
        Write-Output "=== Parameter Extraction Summary ==="
        Write-Output "Total Parameters: $($output.Stats.TotalParams)"
        foreach ($src in $sourceCounts.Keys | Sort-Object) {
            Write-Output "  $src : $($sourceCounts[$src])"
        }
        if ($fuzzResults.Count -gt 0) { Write-Output "Fuzzed (new): $($fuzzResults.Count)" }
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN ENTRY
# ============================================================================

$Url = $null; $FilePath = $null; $Method = 'GET'; $Body = $null
$Headers = $null; $OutputFile = $null; $Fuzz = $false
$FuzzWordlist = $null; $Depth = 3; $Timeout = 30; $Silent = $false
$ExtractHeaders = $true; $ExtractCookies = $true

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Url' { $i++; $Url = $args[$i] }
            '-FilePath' { $i++; $FilePath = $args[$i] }
            '-Method' { $i++; $Method = $args[$i] }
            '-Body' { $i++; $Body = $args[$i] }
            '-Headers' { $i++; $Headers = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Fuzz' { $Fuzz = $true }
            '-FuzzWordlist' { $i++; $FuzzWordlist = $args[$i] }
            '-Depth' { $i++; $Depth = [int]$args[$i] }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-Silent' { $Silent = $true }
            '-ExtractHeaders' { $ExtractHeaders = $true }
            '-ExtractHeaders:$false' { $ExtractHeaders = $false }
            '-ExtractCookies' { $ExtractCookies = $true }
            '-ExtractCookies:$false' { $ExtractCookies = $false }
        }
        $i++
    }
}

try {
    Invoke-ParameterExtraction -Url $Url -FilePath $FilePath -Method $Method -Body $Body -Headers $Headers -OutputFile $OutputFile -Fuzz:$Fuzz -FuzzWordlist $FuzzWordlist -Depth $Depth -Timeout $Timeout -Silent:$Silent -ExtractHeaders:$ExtractHeaders -ExtractCookies:$ExtractCookies
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
