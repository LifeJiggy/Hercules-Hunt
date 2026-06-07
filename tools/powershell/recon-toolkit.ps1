<#
.SYNOPSIS
    Recon-Toolkit -- Windows-based bug bounty reconnaissance automation.

.DESCRIPTION
    Modular PowerShell recon toolkit for Windows bug bounty hunting.
    Provides subdomain enumeration (crt.sh, SecurityTrails, RapidDNS,
    DNS Dumpster), live host checking with parallel bulk support,
    technology fingerprinting from headers and HTML, robots.txt and
    sitemap.xml parsing, Wayback Machine CDX historical URL retrieval,
    DNS record resolution (A/AAAA/CNAME/MX/NS/TXT/SOA/SRV), TCP port
    scanning, wildcard scope expansion, and a full orchestrating
    pipeline (Invoke-ReconPipeline) that runs all phases sequentially
    and outputs structured Markdown reports and JSON exports.

    All functions use native PowerShell cmdlets and curl.exe (bundled
    with Windows 10 1803+ and Windows Server 2019+). No third-party
    modules, Python scripts, or external binaries are required.

    ##################################################################
    #  SCOPE SAFETY WARNING                                         #
    #  Only use against targets you are explicitly authorized        #
    #  to test. Scanning without written permission is illegal       #
    #  and violates platform ToS (HackerOne, Bugcrowd, etc.).       #
    #  Always verify scope before running any enumeration.           #
    ##################################################################

.NOTES
    Version    : 1.0.0
    Requires   : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    curl.exe   : Bundled with Windows 10 1803+ and Windows Server 2019+
    Author     : Recon-Toolkit
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DefaultTimeoutSeconds = 15

<#
.SYNOPSIS Query crt.sh Certificate Transparency logs for subdomains.
.PARAMETER Domain Target domain (e.g. "example.com").
.PARAMETER ExcludeWildcard Exclude wildcard entries.
#>
function Get-SubdomainsCrtSh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain,
        [Parameter()][switch]$ExcludeWildcard
    )
    $results = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $response = Invoke-RestMethod -Uri "https://crt.sh/?q=%.$Domain&output=json" -Method Get -TimeoutSec $script:DefaultTimeoutSeconds -ErrorAction Stop
    } catch {
        Write-Warning "[crt.sh] $($_.Exception.Message)"
        return @()
    }
    if (-not $response) { return @() }
    foreach ($entry in $response) {
        $names = @()
        if ($entry.common_name) { $names += $entry.common_name }
        if ($entry.name_value)  { $names += ($entry.name_value -split '\r?\n') }
        foreach ($raw in $names) {
            $raw = $raw.Trim().ToLowerInvariant()
            if ($ExcludeWildcard -and $raw.Contains('*')) { continue }
            if ($raw -eq $Domain) { continue }
            if ($raw -like "*$Domain") { $null = $results.Add($raw) }
        }
    }
    return ($results | Sort-Object)
}

<#
.SYNOPSIS Query SecurityTrails API for subdomains.
.PARAMETER Domain Target domain.
.PARAMETER ApiKey API key (falls back to $env:SECURITYTRAILS_API_KEY).
#>
function Get-SubdomainsSecurityTrails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain,
        [Parameter()][string]$ApiKey = $env:SECURITYTRAILS_API_KEY
    )
    if ([string]::IsNullOrEmpty($ApiKey)) {
        Write-Warning "[SecurityTrails] No API key provided"
        return @()
    }
    $results = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $response = Invoke-RestMethod -Uri "https://api.securitytrails.com/v1/domain/$Domain/subdomains" -Method Get -Headers @{APIKEY=$ApiKey;Accept='application/json'} -TimeoutSec $script:DefaultTimeoutSeconds -ErrorAction Stop
    } catch {
        Write-Warning "[SecurityTrails] $($_.Exception.Message)"
        return @()
    }
    if (-not $response.subdomains) { return @() }
    foreach ($sub in $response.subdomains) {
        $null = $results.Add("$sub.$Domain".ToLowerInvariant())
    }
    return ($results | Sort-Object)
}

<#
.SYNOPSIS Query RapidDNS.io for subdomains.
.PARAMETER Domain Target domain.
#>
function Get-SubdomainsRapidDns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain
    )
    $results = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $response = Invoke-WebRequest -Uri "https://rapiddns.io/subdomain/$Domain?full=1" -Method Get -TimeoutSec $script:DefaultTimeoutSeconds -UseBasicParsing -ErrorAction Stop
        if ($response.Content -match '<tbody>(.*?)</tbody>') {
            $tds = [regex]::Matches($Matches[1], '<td[^>]*>(.*?)</td>')
            for ($i = 0; $i -lt $tds.Count; $i += 5) {
                $sub = $tds[$i].Groups[1].Value.Trim().ToLowerInvariant()
                if ($sub -like "*$Domain" -and $sub -ne $Domain) { $null = $results.Add($sub) }
            }
        } else {
            $re = [regex]"(?:https?://)?([a-zA-Z0-9.-]+\.$Domain)"
            foreach ($m in $re.Matches($response.Content)) { $null = $results.Add($m.Groups[1].Value.ToLowerInvariant()) }
        }
    } catch {
        Write-Warning "[RapidDNS] $($_.Exception.Message)"
    }
    return ($results | Sort-Object)
}

<#
.SYNOPSIS Scrape DNS Dumpster for subdomains.
.PARAMETER Domain Target domain.
#>
function Get-SubdomainsDnsDumpster {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain
    )
    $results = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $resp = Invoke-WebRequest -Uri "https://dnsdumpster.com/" -Method Get -WebSession $session -UseBasicParsing -TimeoutSec $script:DefaultTimeoutSeconds
        $csrf = ''
        $m = [regex]::Match($resp.Content, '<input[^>]*name=["'']csrfmiddlewaretoken["''][^>]*value=["'']([^"'']+)["'']')
        if ($m.Success) { $csrf = $m.Groups[1].Value }
        $body = @{csrfmiddlewaretoken=$csrf;targetip=$Domain;user='free'}
        $headers = @{
            Referer='https://dnsdumpster.com/';Origin='https://dnsdumpster.com'
            'Content-Type'='application/x-www-form-urlencoded'
            'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
        }
        $resultPage = Invoke-WebRequest -Uri "https://dnsdumpster.com/" -Method Post -Body $body -Headers $headers -WebSession $session -UseBasicParsing -TimeoutSec $script:DefaultTimeoutSeconds
        $tableRegex = '<table[^>]*class=["'']table["''][^>]*>(.*?)</table>'
        $tableMatches = [regex]::Matches($resultPage.Content, $tableRegex, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        foreach ($tm in $tableMatches) {
            $re = [regex]"(?:https?://)?([a-zA-Z0-9._-]+\.$Domain)"
            foreach ($m2 in $re.Matches($tm.Groups[1].Value)) {
                $sub = $m2.Groups[1].Value.Trim().TrimEnd('.').ToLowerInvariant()
                if ($sub -ne $Domain) { $null = $results.Add($sub) }
            }
        }
    } catch {
        Write-Warning "[DNSDumpster] $($_.Exception.Message)"
    }
    return ($results | Sort-Object)
}

<#
.SYNOPSIS Test if a single host is live via HTTP HEAD.
.PARAMETER Hostname Host to check.
.PARAMETER UseHttps Prefer HTTPS (default $true).
.PARAMETER TimeoutSeconds Connection timeout.
#>
function Test-LiveHost {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Hostname,
        [Parameter()][switch]$UseHttps = $true,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds
    )
    $result = [PSCustomObject]@{
        Hostname=$Hostname;StatusCode=0;ResponseTimeMs=0;ContentLength=0
        Title='';RedirectUrl='';IsLive=$false
    }
    $schemes = if ($UseHttps) { @('https://','http://') } else { @('http://','https://') }
    foreach ($scheme in $schemes) {
        $url = "$scheme$Hostname"
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $out = & 'curl.exe' '-s' '-o' 'nul' '-w' '%{http_code}|%{time_total}|%{size_download}|%{redirect_url}' '--max-time' "$TimeoutSeconds" '-L' $url 2>&1
            $sw.Stop()
            if ($LASTEXITCODE -ne 0) { continue }
            $parts = ($out -join '') -split '\|'
            $result.StatusCode = [int](try { $parts[0] } catch { 0 })
            $result.ResponseTimeMs = [math]::Round([double](try { $parts[1] } catch { 0 }) * 1000)
            $result.ContentLength = [long](try { $parts[2] } catch { 0 })
            $result.RedirectUrl = if ($parts[3]) { $parts[3] } else { '' }
            if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 400) {
                $result.IsLive = $true
                $result.Title = Get-HttpTitle -Url $url -TimeoutSeconds $TimeoutSeconds
                return $result
            }
        } catch {
            Write-Verbose "[Test-LiveHost] $url failed: $($_.Exception.Message)"
        }
    }
    return $result
}

<#
.SYNOPSIS Check multiple hosts in parallel, return live results.
.PARAMETER Hostnames Array of hostnames.
.PARAMETER IncludeDead Also output dead hosts.
.PARAMETER ThrottleLimit Max parallel checks (default 10).
.PARAMETER TimeoutSeconds Per-host timeout.
#>
function Invoke-BulkHostCheck {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)][string[]]$Hostnames,
        [Parameter()][switch]$IncludeDead,
        [Parameter()][ValidateRange(1,50)][int]$ThrottleLimit = 10,
        [Parameter()][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds
    )
    begin { $allHosts = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($h in $Hostnames) { $allHosts.Add($h.Trim().ToLowerInvariant()) } }
    end {
        if ($allHosts.Count -eq 0) { return }
        $deduped = $allHosts | Sort-Object -Unique
        Write-Verbose "[BulkHostCheck] Checking $($deduped.Count) hosts"
        $results = @(); $batches = @(); $batch = @()
        foreach ($h in $deduped) {
            $batch += $h
            if ($batch.Count -ge $ThrottleLimit) { $batches += ,@($batch); $batch = @() }
        }
        if ($batch.Count -gt 0) { $batches += ,@($batch) }
        foreach ($b in $batches) {
            $jobs = @()
            foreach ($h in $b) {
                $jobs += Start-Job -ScriptBlock {
                    param($h,$t)
                    foreach ($scheme in @('https://','http://')) {
                        $url = "$scheme$h"
                        try {
                            $sw = [System.Diagnostics.Stopwatch]::StartNew()
                            $out = & 'curl.exe' '-s' '-o' 'nul' '-w' '%{http_code}' '--max-time' "$t" '-L' $url 2>&1
                            $sw.Stop()
                            if ($LASTEXITCODE -eq 0 -and $out -match '^\d{3}$' -and [int]$out -ge 200 -and [int]$out -lt 400) {
                                $status = [int]$out; $title = ''
                                try {
                                    $b = & 'curl.exe' '-s' '--max-time' "$t" '-L' $url 2>&1
                                    if ($LASTEXITCODE -eq 0) {
                                        $m2 = [regex]::Match($b, '<title[^>]*>(.*?)</title>', [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                                        if ($m2.Success) { $title = $m2.Groups[1].Value.Trim() }
                                    }
                                } catch {}
                                return [PSCustomObject]@{Hostname=$h;StatusCode=$status;ResponseTimeMs=[math]::Round($sw.Elapsed.TotalMilliseconds);Title=$title;IsLive=$true}
                            }
                        } catch {}
                    }
                    return $null
                } -ArgumentList $h,$TimeoutSeconds
            }
            $null = Wait-Job -Job $jobs -Timeout ($TimeoutSeconds + 10) -ErrorAction SilentlyContinue
            foreach ($j in $jobs) {
                $jr = Receive-Job -Job $j -ErrorAction SilentlyContinue
                if ($jr) { $results += $jr }
                Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not $IncludeDead) { $results = $results | Where-Object { $_.IsLive } }
        return ($results | Sort-Object Hostname)
    }
}

<#
.SYNOPSIS Extract <title> from an HTTP response.
.PARAMETER Url Full URL.
.PARAMETER TimeoutSeconds Request timeout.
#>
function Get-HttpTitle {
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Url,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds
    )
    try {
        $output = & 'curl.exe' '-s' '--max-time' "$TimeoutSeconds" '-L' $Url 2>&1
        if ($LASTEXITCODE -ne 0) { return '' }
        $m = [regex]::Match($output, '<title[^>]*>(.*?)</title>', [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
    } catch {}
    return ''
}

<#
.SYNOPSIS Detect web server, framework, CMS from headers and HTML.
.PARAMETER Url Full URL.
.PARAMETER TimeoutSeconds Request timeout.
#>
function Get-TechStack {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Url,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds
    )
    $tech = [PSCustomObject]@{
        Url=$Url;Server='';PoweredBy='';ContentType=''
        Technologies=@();Cms='';Framework='';Language='';Cdn=''
    }
    try {
        $headers = & 'curl.exe' '-s' '-I' '--max-time' "$TimeoutSeconds" '-L' $Url 2>&1
        $body = & 'curl.exe' '-s' '--max-time' "$TimeoutSeconds" '-L' $Url 2>&1
    } catch { return $tech }
    if ($headers -match '(?m)^Server:\s*(.+)$') { $tech.Server = $Matches[1].Trim() }
    if ($headers -match '(?m)^X-Powered-By:\s*(.+)$') { $tech.PoweredBy = $Matches[1].Trim() }
    if ($headers -match '(?m)^Content-Type:\s*(.+)$') { $tech.ContentType = $Matches[1].Trim() }
    if ($headers -match '(?m)^X-Generator:\s*(.+)$') { $tech.PoweredBy = $Matches[1].Trim() }
    $detected = [System.Collections.Generic.List[string]]::new()
    $srv = $tech.Server.ToLowerInvariant()
    switch -Wildcard ($srv) {
        '*cloudflare*'  { $detected.Add('Cloudflare') }
        '*cloudfront*'  { $detected.Add('CloudFront') }
        '*nginx*'       { $detected.Add('Nginx') }
        '*apache*'      { $detected.Add('Apache') }
        '*iis*'         { $detected.Add('IIS') }
        '*openresty*'   { $detected.Add('OpenResty') }
        '*caddy*'       { $detected.Add('Caddy') }
        '*gunicorn*'    { $detected.Add('Gunicorn') }
        '*netlify*'     { $detected.Add('Netlify') }
        '*vercel*'      { $detected.Add('Vercel') }
        '*lighttpd*'    { $detected.Add('Lighttpd') }
        '*tomcat*'      { $detected.Add('Apache Tomcat') }
        '*jetty*'       { $detected.Add('Jetty') }
        '*kestrel*'     { $detected.Add('Kestrel (ASP.NET Core)') }
    }
    $pb = $tech.PoweredBy.ToLowerInvariant()
    if ($pb -match 'asp\.net')       { $detected.Add('ASP.NET'); $tech.Framework='ASP.NET';$tech.Language='C#' }
    if ($pb -match 'php')            { $detected.Add('PHP');$tech.Language='PHP' }
    if ($pb -match 'express')        { $detected.Add('Express.js');$tech.Framework='Express.js' }
    if ($pb -match 'django')         { $detected.Add('Django');$tech.Framework='Django';$tech.Language='Python' }
    if ($pb -match 'rails|ruby')     { $detected.Add('Ruby on Rails');$tech.Framework='Ruby on Rails';$tech.Language='Ruby' }
    if ($pb -match 'laravel')        { $detected.Add('Laravel');$tech.Framework='Laravel';$tech.Language='PHP' }
    if ($pb -match 'next\.js')       { $detected.Add('Next.js');$tech.Framework='Next.js' }
    if ($pb -match 'spring')         { $detected.Add('Spring');$tech.Framework='Spring';$tech.Language='Java' }
    if ($pb -match 'flask')          { $detected.Add('Flask');$tech.Framework='Flask';$tech.Language='Python' }
    if ($pb -match 'nuxt')           { $detected.Add('Nuxt.js');$tech.Framework='Nuxt.js' }
    if ($pb -match 'cakephp')        { $detected.Add('CakePHP');$tech.Framework='CakePHP';$tech.Language='PHP' }
    if ($pb -match 'symfony')        { $detected.Add('Symfony');$tech.Framework='Symfony';$tech.Language='PHP' }
    if ($pb -match 'yii')            { $detected.Add('Yii');$tech.Framework='Yii';$tech.Language='PHP' }
    if ($pb -match 'grails')         { $detected.Add('Grails');$tech.Framework='Grails';$tech.Language='Groovy' }
    if ($body -match '<meta[^>]*name=["'']generator["''][^>]*content=["'']([^"'']+)["'']') {
        $g = $Matches[1].Trim(); $detected.Add("Generator:$g"); $gl = $g.ToLowerInvariant()
        if ($gl -match 'wordpress')  { $tech.Cms='WordPress';$detected.Add('WordPress') }
        if ($gl -match 'joomla')     { $tech.Cms='Joomla';$detected.Add('Joomla') }
        if ($gl -match 'drupal')     { $tech.Cms='Drupal';$detected.Add('Drupal') }
        if ($gl -match 'shopify')    { $tech.Cms='Shopify';$detected.Add('Shopify') }
        if ($gl -match 'wix')        { $tech.Cms='Wix';$detected.Add('Wix') }
        if ($gl -match 'squarespace'){ $tech.Cms='Squarespace';$detected.Add('Squarespace') }
        if ($gl -match 'blogger')    { $tech.Cms='Blogger';$detected.Add('Blogger') }
        if ($gl -match 'ghost')      { $tech.Cms='Ghost';$detected.Add('Ghost') }
        if ($gl -match 'magento')    { $tech.Cms='Magento';$detected.Add('Magento');$tech.Framework='Magento';$tech.Language='PHP' }
    }
    if ($body -match '/wp-content/' -or $body -match '/wp-includes/' -or $body -match '/wp-json/') { $tech.Cms='WordPress' }
    if ($body -match '/sites/default/files/' -or $body -match 'Drupal.settings') { $tech.Cms='Drupal' }
    if ($body -match '/components/com_' -or $body -match '/modules/mod_') { $tech.Cms='Joomla' }
    if ($body -match '__NEXT_DATA__' -or $body -match '/_next/static/') { $detected.Add('Next.js');$tech.Framework='Next.js' }
    if ($body -match '__NUXT__' -or $body -match '/_nuxt/') { $detected.Add('Nuxt.js');$tech.Framework='Nuxt.js' }
    if ($body -match 'react[.-]root' -or $body -match 'data-reactroot' -or $body -match 'data-reactid') { $detected.Add('React');$tech.Framework='React' }
    if ($body -match 'ng-version' -or $body -match 'ng-app') { $detected.Add('Angular');$tech.Framework='Angular' }
    if ($body -match 'vue[.-]' -or $body -match 'v-bind' -or $body -match 'v-model') { $detected.Add('Vue.js');$tech.Framework='Vue.js' }
    if ($body -match 'svelte' -or $body -match '__svelte') { $detected.Add('Svelte');$tech.Framework='Svelte' }
    if ($body -match 'jquery')     { $detected.Add('jQuery') }
    if ($body -match 'bootstrap')  { $detected.Add('Bootstrap') }
    if ($body -match 'tailwind')   { $detected.Add('Tailwind CSS') }
    if ($body -match 'htmx')       { $detected.Add('htmx') }
    if ($body -match 'alpine')     { $detected.Add('Alpine.js') }
    $hl = $headers.ToLowerInvariant()
    if ($hl -match 'cf-ray:')       { $detected.Add('Cloudflare');$tech.Cdn='Cloudflare' }
    if ($hl -match 'x-amz-cf-id:')  { $detected.Add('CloudFront');$tech.Cdn='CloudFront' }
    if ($hl -match 'x-sucuri-id:')  { $detected.Add('Sucuri WAF') }
    if ($hl -match 'x-fecache:')    { $detected.Add('Fastly');$tech.Cdn='Fastly' }
    if ($hl -match 'x-cache:')      { $detected.Add('CDN (generic)') }
    if ($hl -match 'set-cookie:.*incap_ses_') { $detected.Add('Imperva/Incapsula') }
    if ($hl -match 'x-robots-tag:') { $detected.Add('X-Robots-Tag') }
    if ($hl -match 'x-frame-options:') { $detected.Add('X-Frame-Options') }
    if ($hl -match 'content-security-policy:') { $detected.Add('CSP Headers') }
    if ($hl -match 'strict-transport-security:') { $detected.Add('HSTS') }
    if ($hl -match 'x-content-type-options:') { $detected.Add('X-Content-Type-Options') }
    $tech.Technologies = $detected | Select-Object -Unique | Sort-Object
    return $tech
}

<#
.SYNOPSIS Fetch and parse robots.txt.
.PARAMETER Url Base URL.
.PARAMETER TimeoutSeconds Request timeout.
#>
function Get-RobotsPaths {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Url,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds
    )
    $robotsUrl = "$($Url.TrimEnd('/'))/robots.txt"
    $result = [PSCustomObject]@{RobotsUrl=$robotsUrl;Fetched=$false;UserAgents=@();Sitemaps=@();RawContent=''}
    try {
        $content = & 'curl.exe' '-s' '--max-time' "$TimeoutSeconds" '-L' $robotsUrl 2>&1
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($content)) { return $result }
        $result.Fetched = $true; $result.RawContent = $content
        $agents = [System.Collections.Generic.List[PSCustomObject]]::new()
        $ua=''; $dis=[System.Collections.Generic.List[string]]::new(); $al=[System.Collections.Generic.List[string]]::new(); $sm=[System.Collections.Generic.List[string]]::new()
        foreach ($line in $content -split '\r?\n') {
            $line = $line.Trim()
            if ([string]::IsNullOrEmpty($line) -or $line.StartsWith('#')) { continue }
            if ($line -match '(?i)^User-agent:\s*(.+)$') {
                if ($ua) { $agents.Add([PSCustomObject]@{UserAgent=$ua;Disallow=$dis.ToArray();Allow=$al.ToArray()}) }
                $ua=$Matches[1].Trim(); $dis=[System.Collections.Generic.List[string]]::new(); $al=[System.Collections.Generic.List[string]]::new()
            } elseif ($line -match '(?i)^Disallow:\s*(.*)$') { $p=$Matches[1].Trim(); if($p){$dis.Add($p)}
            } elseif ($line -match '(?i)^Allow:\s*(.*)$') { $p=$Matches[1].Trim(); if($p){$al.Add($p)}
            } elseif ($line -match '(?i)^Sitemap:\s*(.+)$') { $sm.Add($Matches[1].Trim()) }
        }
        if ($ua) { $agents.Add([PSCustomObject]@{UserAgent=$ua;Disallow=$dis.ToArray();Allow=$al.ToArray()}) }
        $result.UserAgents = $agents; $result.Sitemaps = $sm
    } catch {
        Write-Warning "[Robots] $($_.Exception.Message)"
    }
    return $result
}

<#
.SYNOPSIS Fetch and parse sitemap.xml.
.PARAMETER Url Base URL.
.PARAMETER TimeoutSeconds Request timeout.
.PARAMETER Recursive Follow sitemap index links.
#>
function Get-SitemapPaths {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Url,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds = $script:DefaultTimeoutSeconds,
        [Parameter()][switch]$Recursive
    )
    $sitemapUrl = "$($Url.TrimEnd('/'))/sitemap.xml"
    $result = [PSCustomObject]@{SitemapUrl=$sitemapUrl;Fetched=$false;IsIndex=$false;Urls=@()}
    $allUrls = [System.Collections.Generic.List[string]]::new()
    function _fetchSitemap { param([string]$U,[int]$Depth)
        if ($Depth -gt 3) { return }
        try {
            $c = & 'curl.exe' '-s' '--max-time' "$TimeoutSeconds" '-L' $U 2>&1
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($c)) { return }
            if ($c -match '<sitemapindex' -or $c -match '<sitemap>') {
                $result.IsIndex = $true
                $locMatches = [regex]::Matches($c,'<loc>\s*(.*?)\s*</loc>',[System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($lm in $locMatches) { if ($Recursive) { _fetchSitemap -U $lm.Groups[1].Value.Trim() -Depth ($Depth+1) } }
            } else {
                $locMatches = [regex]::Matches($c,'<loc>\s*(.*?)\s*</loc>',[System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($lm in $locMatches) { $null = $allUrls.Add($lm.Groups[1].Value.Trim()) }
            }
            $result.Fetched = $true
        } catch {}
    }
    _fetchSitemap -U $sitemapUrl -Depth 0
    $result.Urls = $allUrls | Sort-Object -Unique
    return $result
}

<#
.SYNOPSIS Query Wayback Machine CDX API for historical URLs.
.PARAMETER Domain Target domain.
.PARAMETER MatchType URL match type (domain|host|prefix|exact).
.PARAMETER FromDate Start date YYYYMMDD.
.PARAMETER ToDate End date YYYYMMDD.
.PARAMETER FilterStatus Include only these status codes.
.PARAMETER Limit Max results (default 1000).
.PARAMETER TimeoutSeconds Request timeout.
#>
function Get-UrlFromWayback {
    [CmdletBinding()][OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Domain,
        [Parameter()][ValidateSet('domain','host','prefix','exact')][string]$MatchType='domain',
        [Parameter()][string]$FromDate='', [Parameter()][string]$ToDate='',
        [Parameter()][int[]]$FilterStatus=@(),
        [Parameter()][ValidateRange(1,50000)][int]$Limit=1000,
        [Parameter()][ValidateRange(1,60)][int]$TimeoutSeconds=$script:DefaultTimeoutSeconds
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $params = @{
        url=$Domain;matchType=$MatchType;output='json';limit=$Limit
        fl='timestamp,original,statuscode,mimetype,digest,length';collapse='urlkey'
    }
    if ($FromDate) { $params.from = $FromDate }
    if ($ToDate) { $params.to = $ToDate }
    $qs = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=[uri]::EscapeDataString($($_.Value))" }) -join '&'
    try {
        $response = Invoke-RestMethod -Uri "https://web.archive.org/cdx/search/cdx?$qs" -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        if ($response -is [array] -and $response.Count -gt 1) {
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($row in $response[1..($response.Count-1)]) {
                $ts=$row[0];$orig=$row[1];$sc=[int]$row[2];$mime=$row[3];$dig=$row[4];$len=[long]$row[5]
                if ($FilterStatus.Count -gt 0 -and $sc -notin $FilterStatus) { continue }
                if ($seen.Contains($orig)) { continue }; $null = $seen.Add($orig)
                $results.Add([PSCustomObject]@{Timestamp=$ts;Original=$orig;StatusCode=$sc;MimeType=$mime;Digest=$dig;Length=$len;WaybackUrl="https://web.archive.org/web/$ts/$orig"})
            }
        }
    } catch {
        Write-Warning "[Wayback] $($_.Exception.Message)"
    }
    return $results
}

<#
.SYNOPSIS Expand *.domain.com to common subdomain list.
.PARAMETER Domain Target domain.
.PARAMETER IncludeExtra Extra prefixes to include.
#>
function Expand-WildcardScope {
    [CmdletBinding()][OutputType([string[]])]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain,
        [Parameter()][string[]]$IncludeExtra=@()
    )
    $prefixes = @(
        'www','api','dev','staging','admin','mail','cdn','static','assets','docs',
        'blog','app','dashboard','portal','auth','login','sso','status','support',
        'test','demo','backup','git','jenkins','ci','monitor','vpn','files','upload',
        'calendar','chat','shop','store','jobs','legal','ns1','ns2','edge','origin'
    ) + $IncludeExtra
    return ($prefixes | ForEach-Object { "$_.$Domain".ToLowerInvariant() } | Sort-Object -Unique)
}

<#
.SYNOPSIS Resolve DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV).
.PARAMETER Hostname Target hostname.
.PARAMETER RecordTypes Record types to query (default: A,AAAA,CNAME,MX,NS,TXT).
#>
function Get-DnsRecords {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Hostname,
        [Parameter()][ValidateSet('A','AAAA','CNAME','MX','NS','TXT','SOA','SRV')][string[]]$RecordTypes=@('A','AAAA','CNAME','MX','NS','TXT')
    )
    $r = [PSCustomObject]@{Hostname=$Hostname.ToLowerInvariant();A=@();AAAA=@();CNAME=@();MX=@();NS=@();TXT=@();SOA=@();SRV=@()}
    try { if('A'-in$RecordTypes){$r.A=[System.Net.Dns]::GetHostAddresses($Hostname)|Where-Object{$_.AddressFamily-eq'InterNetwork'}|ForEach-Object{$_.IPAddressToString}|Sort-Object -Unique} } catch {}
    try { if('AAAA'-in$RecordTypes){$r.AAAA=[System.Net.Dns]::GetHostAddresses($Hostname)|Where-Object{$_.AddressFamily-eq'InterNetworkV6'}|ForEach-Object{$_.IPAddressToString}|Sort-Object -Unique} } catch {}
    try { if('CNAME'-in$RecordTypes){$e=[System.Net.Dns]::GetHostEntry($Hostname);if($e.HostName-and$e.HostName-ne$Hostname-and$e.HostName-notmatch'^(\d+\.){3}\d+$'){$r.CNAME=@($e.HostName.ToLowerInvariant())}}} catch {}
    try { if('MX'-in$RecordTypes){$mxData=Resolve-DnsName -Name $Hostname -Type MX -ErrorAction SilentlyContinue;if($mxData){$r.MX=$mxData|ForEach-Object{"$($_.Preference) $($_.NameExchange.ToLowerInvariant())"}|Sort-Object}} } catch {}
    try { if('NS'-in$RecordTypes){$nsData=Resolve-DnsName -Name $Hostname -Type NS -ErrorAction SilentlyContinue;if($nsData){$r.NS=$nsData|ForEach-Object{$_.NameHost.ToLowerInvariant().TrimEnd('.')}|Sort-Object -Unique}} } catch {}
    try { if('TXT'-in$RecordTypes){$txtData=Resolve-DnsName -Name $Hostname -Type TXT -ErrorAction SilentlyContinue;if($txtData){$r.TXT=$txtData|ForEach-Object{($_.Strings -join '')}|Where-Object{$_}|Sort-Object -Unique}} } catch {}
    try { if('SOA'-in$RecordTypes){$soaData=Resolve-DnsName -Name $Hostname -Type SOA -ErrorAction SilentlyContinue;if($soaData){$r.SOA=@($soaData|ForEach-Object{"$($_.PrimaryServer) $($_.ResponsiblePerson) (serial=$($_.Serial))"})}} } catch {}
    try { if('SRV'-in$RecordTypes){$srvData=Resolve-DnsName -Name "_services.$Hostname" -Type SRV -ErrorAction SilentlyContinue;if($srvData){$r.SRV=$srvData|ForEach-Object{"$($_.Target):$($_.Port) priority=$($_.Priority) weight=$($_.Weight)"}|Sort-Object}} } catch {}
    return $r
}

<#
.SYNOPSIS Test if a TCP port is open using Test-NetConnection.
.PARAMETER Hostname Target host.
.PARAMETER Port Port number(s).
.PARAMETER TimeoutMs Connection timeout (default 3000).
#>
function Test-PortOpen {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)][ValidateNotNullOrEmpty()][string]$Hostname,
        [Parameter(Mandatory, ValueFromPipeline, Position=1)][ValidateRange(1,65535)][int[]]$Port,
        [Parameter()][ValidateRange(500,30000)][int]$TimeoutMs=3000
    )
    process {
        foreach ($p in $Port) {
            $isOpen=$false; $rtt=0
            try {
                $tnc=Test-NetConnection -ComputerName $Hostname -Port $p -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                $isOpen=$tnc.TcpTestSucceeded; if($isOpen){$rtt=1}
            } catch {
                try {
                    $s=New-Object System.Net.Sockets.TcpClient
                    $cb=$s.BeginConnect($Hostname,$p,$null,$null)
                    $sw=[System.Diagnostics.Stopwatch]::StartNew()
                    $wr=$cb.AsyncWaitHandle.WaitOne($TimeoutMs,$false)
                    $sw.Stop()
                    if($wr-and$s.Connected){$isOpen=$true;$rtt=[math]::Round($sw.Elapsed.TotalMilliseconds)}
                    $s.Close()
                } catch { $isOpen=$false }
            }
            $svcMap = @{
                21='FTP';22='SSH';23='Telnet';25='SMTP';53='DNS';80='HTTP'
                110='POP3';143='IMAP';443='HTTPS';465='SMTPS';587='SMTP Submission'
                993='IMAPS';995='POP3S';1433='MSSQL';1521='Oracle DB';2049='NFS'
                2375='Docker';3306='MySQL';3389='RDP';5432='PostgreSQL';5900='VNC'
                5985='WinRM HTTP';5986='WinRM HTTPS';6379='Redis';6443='K8s API'
                8080='HTTP Proxy';8443='HTTPS Alt';9090='Prometheus';9200='Elasticsearch'
                27017='MongoDB'
            }
            $svc = $svcMap[[int]$p]
            [PSCustomObject]@{Hostname=$Hostname.ToLowerInvariant();Port=$p;Service=$svc;IsOpen=$isOpen;ResponseTimeMs=$rtt}
        }
    }
}

<#
.SYNOPSIS Run full recon pipeline against a target domain.
.DESCRIPTION Orchestrates subdomain enum, live check, tech detect,
    robots/sitemap parsing, Wayback Machine URL history, DNS records,
    port scanning, and outputs structured results with optional
    Markdown report and JSON export.
.PARAMETER Domain Target domain.
.PARAMETER ExpandWildcard Also enumerate from common subdomain wordlist.
.PARAMETER ApiKey SecurityTrails API key.
.PARAMETER UseDnsDumpster Include DNS Dumpster.
.PARAMETER UseRapidDns Include RapidDNS.io.
.PARAMETER CrtShExcludeWildcard Exclude wildcard from crt.sh.
.PARAMETER PortScanPorts Ports to scan (default 80,443,8443,8080,22).
.PARAMETER WayBackLimit Max Wayback results (default 500).
.PARAMETER ReportPath Write Markdown report to this path.
.PARAMETER JsonPath Export JSON to this path.
.PARAMETER NoWayback Skip Wayback queries.
.PARAMETER NoTechDetect Skip tech detection.
.PARAMETER ThrottleLimit Max parallel checks (default 10).
#>
function Invoke-ReconPipeline {
    [CmdletBinding()][OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, Position=0)]
        [ValidateScript({ $_ -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' })]
        [string]$Domain,
        [Parameter()][switch]$ExpandWildcard,
        [Parameter()][string]$ApiKey=$env:SECURITYTRAILS_API_KEY,
        [Parameter()][switch]$UseDnsDumpster,
        [Parameter()][switch]$UseRapidDns,
        [Parameter()][switch]$CrtShExcludeWildcard,
        [Parameter()][int[]]$PortScanPorts=@(80,443,8443,8080,22),
        [Parameter()][ValidateRange(1,50000)][int]$WayBackLimit=500,
        [Parameter()][string]$ReportPath='',
        [Parameter()][string]$JsonPath='',
        [Parameter()][switch]$NoWayback,
        [Parameter()][switch]$NoTechDetect,
        [Parameter()][ValidateRange(1,50)][int]$ThrottleLimit=10
    )
    $start = Get-Date
    Write-Host "===== Recon Pipeline: $Domain =====" -ForegroundColor Cyan
    Write-Host ""

    $result = [PSCustomObject]@{
        Domain=$Domain; ScanStarted=$start; ScanCompleted=$null
        ExpandedScope=@(); Subdomains=@{}; SubdomainsMerged=@()
        LiveHosts=@(); TechStacks=@(); RobotsData=$null; SitemapData=$null
        WaybackUrls=@(); DnsRecords=$null; OpenPorts=@()
        Summary=[PSCustomObject]@{
            TotalSubdomains=0; LiveHostCount=0
            InterestingPaths=@(); TechSummary=@{}
        }
    }

    # Phase 1: Wildcard scope expansion
    Write-Host "[Phase 1] Wildcard scope expansion" -ForegroundColor Yellow
    if ($ExpandWildcard) {
        Write-Host "  Expanding *.$Domain ... " -NoNewline
        $result.ExpandedScope = Expand-WildcardScope -Domain $Domain
        Write-Host "$($result.ExpandedScope.Count) subdomains generated" -ForegroundColor Green
    } else {
        Write-Host "  Skipped (use -ExpandWildcard to enable)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Phase 2: Subdomain enumeration
    Write-Host "[Phase 2] Subdomain enumeration" -ForegroundColor Yellow
    $allSubs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    Write-Host "  Source: crt.sh"
    try {
        $crt = Get-SubdomainsCrtSh -Domain $Domain -ExcludeWildcard:$CrtShExcludeWildcard
        $result.Subdomains['crt.sh'] = $crt
        foreach ($s in $crt) { $null = $allSubs.Add($s) }
        Write-Host "    -> $($crt.Count) subdomains" -ForegroundColor Green
    } catch { Write-Warning "    -> FAILED: $($_.Exception.Message)" }

    if ($ApiKey) {
        Write-Host "  Source: SecurityTrails"
        try {
            $st = Get-SubdomainsSecurityTrails -Domain $Domain -ApiKey $ApiKey
            $result.Subdomains['securitytrails'] = $st
            foreach ($s in $st) { $null = $allSubs.Add($s) }
            Write-Host "    -> $($st.Count) subdomains" -ForegroundColor Green
        } catch { Write-Warning "    -> FAILED: $($_.Exception.Message)" }
    } else {
        Write-Host "  Source: SecurityTrails (skipped - no API key)" -ForegroundColor DarkGray
    }

    if ($UseRapidDns) {
        Write-Host "  Source: RapidDNS.io"
        try {
            $rd = Get-SubdomainsRapidDns -Domain $Domain
            $result.Subdomains['rapiddns'] = $rd
            foreach ($s in $rd) { $null = $allSubs.Add($s) }
            Write-Host "    -> $($rd.Count) subdomains" -ForegroundColor Green
        } catch { Write-Warning "    -> FAILED: $($_.Exception.Message)" }
    } else {
        Write-Host "  Source: RapidDNS.io (skipped - use -UseRapidDns)" -ForegroundColor DarkGray
    }

    if ($UseDnsDumpster) {
        Write-Host "  Source: DNS Dumpster"
        try {
            $dd = Get-SubdomainsDnsDumpster -Domain $Domain
            $result.Subdomains['dnsdumpster'] = $dd
            foreach ($s in $dd) { $null = $allSubs.Add($s) }
            Write-Host "    -> $($dd.Count) subdomains" -ForegroundColor Green
        } catch { Write-Warning "    -> FAILED: $($_.Exception.Message)" }
    } else {
        Write-Host "  Source: DNS Dumpster (skipped - use -UseDnsDumpster)" -ForegroundColor DarkGray
    }

    $merged = $allSubs | Sort-Object
    $result.SubdomainsMerged = $merged
    $result.Summary.TotalSubdomains = $merged.Count
    Write-Host "  => $($merged.Count) unique subdomains across all sources" -ForegroundColor Green
    Write-Host ""

    # Phase 3: Live host validation
    Write-Host "[Phase 3] Live host validation" -ForegroundColor Yellow
    $targets = @($merged)
    if ($ExpandWildcard -and $result.ExpandedScope.Count -gt 0) {
        $inMerged = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($s in $merged) { $null = $inMerged.Add($s) }
        $targets += $result.ExpandedScope | Where-Object { -not $inMerged.Contains($_) }
    }
    $targets = $targets | Sort-Object -Unique
    Write-Host "  Checking $($targets.Count) unique targets (throttle=$ThrottleLimit) ..."
    if ($targets.Count -gt 0) {
        $result.LiveHosts = Invoke-BulkHostCheck -Hostnames $targets -ThrottleLimit $ThrottleLimit | Sort-Object Hostname
        $result.Summary.LiveHostCount = $result.LiveHosts.Count
        Write-Host "  => $($result.LiveHosts.Count) hosts returned HTTP 2xx/3xx" -ForegroundColor Green
        foreach ($h in $result.LiveHosts) {
            $titleSnippet = if ($h.Title) { " - $($h.Title)" } else { '' }
            Write-Host "     $($h.Hostname) [$($h.StatusCode)] $($h.ResponseTimeMs)ms$titleSnippet" -ForegroundColor Gray
        }
    } else {
        Write-Host "  (no targets to check)" -ForegroundColor DarkYellow
    }
    Write-Host ""

    # Phase 4: Technology detection
    if (-not $NoTechDetect -and $result.LiveHosts.Count -gt 0) {
        Write-Host "[Phase 4] Technology detection" -ForegroundColor Yellow
        $ts = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($h in $result.LiveHosts) {
            Write-Host "  Analyzing $($h.Hostname) ... " -NoNewline
            try {
                $t = Get-TechStack -Url "https://$($h.Hostname)"
                $ts.Add($t)
                $techStr = ($t.Technologies | Select-Object -First 5) -join ', '
                if (-not $techStr) { $techStr = '(none detected)' }
                Write-Host "$techStr" -ForegroundColor Green
            } catch {
                $ts.Add([PSCustomObject]@{
                    Url="https://$($h.Hostname)";Server='';PoweredBy='';ContentType=''
                    Technologies=@('Error');Cms='';Framework='';Language='';Cdn=''
                })
                Write-Host "ERROR ($($_.Exception.Message))" -ForegroundColor Red
            }
        }
        $result.TechStacks = $ts
        $techSum = @{}
        foreach ($t in $ts) {
            foreach ($tn in $t.Technologies) {
                if (-not $techSum.ContainsKey($tn)) { $techSum[$tn] = 0 }
                $techSum[$tn]++
            }
        }
        $result.Summary.TechSummary = $techSum
        Write-Host ""
    }

    # Phase 5: robots.txt & sitemap.xml
    Write-Host "[Phase 5] Robots.txt & sitemap.xml" -ForegroundColor Yellow
    if ($result.LiveHosts.Count -gt 0) {
        $apexUrl = "https://$Domain"
        Write-Host "  $apexUrl/robots.txt ... " -NoNewline
        try {
            $rob = Get-RobotsPaths -Url $apexUrl
            $result.RobotsData = $rob
            if ($rob.Fetched) {
                $totalRules = ($rob.UserAgents | ForEach-Object { $_.Disallow.Count + $_.Allow.Count }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
                Write-Host "$totalRules rules, $($rob.Sitemaps.Count) sitemap refs" -ForegroundColor Green
            } else { Write-Host "Not found" -ForegroundColor DarkYellow }
        } catch { Write-Host "ERROR ($($_.Exception.Message))" -ForegroundColor Red }

        Write-Host "  $apexUrl/sitemap.xml ... " -NoNewline
        try {
            $sm = Get-SitemapPaths -Url $apexUrl
            $result.SitemapData = $sm
            if ($sm.Fetched) { Write-Host "$($sm.Urls.Count) URLs" -ForegroundColor Green }
            else { Write-Host "Not found" -ForegroundColor DarkYellow }
        } catch { Write-Host "ERROR ($($_.Exception.Message))" -ForegroundColor Red }
    } else {
        Write-Host "  Skipped (no live hosts to query)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Phase 6: Wayback Machine URL history
    Write-Host "[Phase 6] Wayback Machine URL history" -ForegroundColor Yellow
    if (-not $NoWayback) {
        Write-Host "  Querying CDX API for $Domain (limit=$WayBackLimit) ... " -NoNewline
        try {
            $result.WaybackUrls = Get-UrlFromWayback -Domain $Domain -Limit $WayBackLimit
            Write-Host "$($result.WaybackUrls.Count) unique URLs retrieved" -ForegroundColor Green
        } catch { Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red }
    } else {
        Write-Host "  Skipped (use -NoWayback:`$false to enable)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Phase 7: DNS record resolution
    Write-Host "[Phase 7] DNS record resolution" -ForegroundColor Yellow
    Write-Host "  Resolving $Domain ... " -NoNewline
    try {
        $result.DnsRecords = Get-DnsRecords -Hostname $Domain
        $recordCount = @($result.DnsRecords.A).Count + @($result.DnsRecords.AAAA).Count + @($result.DnsRecords.CNAME).Count + @($result.DnsRecords.MX).Count + @($result.DnsRecords.NS).Count + @($result.DnsRecords.TXT).Count
        Write-Host "$recordCount records" -ForegroundColor Green
    } catch { Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red }
    Write-Host ""

    # Phase 8: Port scanning
    if ($PortScanPorts.Count -gt 0 -and $result.LiveHosts.Count -gt 0) {
        Write-Host "[Phase 8] Port scanning" -ForegroundColor Yellow
        Write-Host "  Scanning ports: $($PortScanPorts -join ', ')" -ForegroundColor Gray
        $allPorts = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($h in $result.LiveHosts) {
            Write-Host "  $($h.Hostname) ... " -NoNewline
            try {
                $op = Test-PortOpen -Hostname $h.Hostname -Port $PortScanPorts | Where-Object { $_.IsOpen }
                foreach ($p in $op) { $allPorts.Add($p) }
                if ($op.Count -gt 0) {
                    $openDetails = ($op | ForEach-Object { "$($_.Port)/$($_.Service)" }) -join ', '
                    Write-Host "$($op.Count) open ($openDetails)" -ForegroundColor Yellow
                } else { Write-Host "0 open" -ForegroundColor DarkGray }
            } catch { Write-Host "ERROR ($($_.Exception.Message))" -ForegroundColor Red }
        }
        $result.OpenPorts = $allPorts
        Write-Host ""
    }

    # Interesting path extraction from Wayback
    if ($result.WaybackUrls.Count -gt 0) {
        $patterns = @(
            'admin','api','config','backup','dump','sql','db','debug','test',
            'staging','swagger','graphql','.git','.env','wp-admin','wp-config',
            'phpinfo','aws','s3','credentials','token','secret','payment',
            'checkout','invoice','refund','export','import','upload','download'
        )
        $interesting = [System.Collections.Generic.List[string]]::new()
        foreach ($e in $result.WaybackUrls) {
            $ul = $e.Original.ToLowerInvariant()
            foreach ($p in $patterns) {
                if ($ul -like "*$p*") {
                    $null = $interesting.Add("$($e.Original) [status=$($e.StatusCode), $($e.Timestamp)]")
                    break
                }
            }
        }
        $result.Summary.InterestingPaths = $interesting | Sort-Object -Unique
    }

    # Finalize
    $result.ScanCompleted = Get-Date
    $elapsed = $result.ScanCompleted - $result.ScanStarted
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  Recon complete for $Domain" -ForegroundColor Cyan
    Write-Host "  Elapsed: $([math]::Round($elapsed.TotalSeconds, 1))s"
    Write-Host "  Subdomains: $($result.Summary.TotalSubdomains)  |  Live: $($result.Summary.LiveHostCount)"
    if ($result.Summary.InterestingPaths.Count -gt 0) {
        Write-Host "  Interesting paths found: $($result.Summary.InterestingPaths.Count)" -ForegroundColor Yellow
    }
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    if ($ReportPath) {
        Write-Host "[Output] Writing Markdown report to $ReportPath" -ForegroundColor Magenta
        Out-ReconReport -ReconResult $result -Path $ReportPath
    }
    if ($JsonPath) {
        Write-Host "[Output] Writing JSON export to $JsonPath" -ForegroundColor Magenta
        Export-ReconJson -ReconResult $result -Path $JsonPath
    }

    return $result
}

<#
.SYNOPSIS Format recon results as Markdown report.
.PARAMETER ReconResult Pipeline output object.
.PARAMETER Path Output file path.
#>
function Out-ReconReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)][PSCustomObject]$ReconResult,
        [Parameter(Mandatory, Position=1)][string]$Path
    )
    begin { $lines = [System.Collections.Generic.List[string]]::new() }
    process {
        $r = $ReconResult
        $duration = [math]::Round(($r.ScanCompleted - $r.ScanStarted).TotalSeconds, 1)
        $lines.Add("# Recon Report: $($r.Domain)")
        $lines.Add("")
        $lines.Add("**Started:** $($r.ScanStarted)  **Completed:** $($r.ScanCompleted)  **Duration:** ${duration}s")
        $lines.Add("")
        $lines.Add("---")
        $lines.Add("")
        $lines.Add("## Summary")
        $lines.Add("")
        $lines.Add("| Metric | Count |")
        $lines.Add("|--------|-------|")
        $lines.Add("| Subdomains | $($r.Summary.TotalSubdomains) |")
        $lines.Add("| Live hosts | $($r.Summary.LiveHostCount) |")
        $lines.Add("| Interesting URLs | $($r.Summary.InterestingPaths.Count) |")
        $lines.Add("| Wayback URLs | $($r.WaybackUrls.Count) |")
        if ($r.SitemapData -and $r.SitemapData.Fetched) {
            $lines.Add("| Sitemap URLs | $($r.SitemapData.Urls.Count) |")
        }
        $lines.Add("| Open ports | $($r.OpenPorts.Count) |")
        $lines.Add("")
        if ($r.Summary.TechSummary.Keys.Count -gt 0) {
            $lines.Add("### Technology")
            $lines.Add("")
            $lines.Add("| Tech | Hosts |")
            $lines.Add("|------|-------|")
            $sortedTech = $r.Summary.TechSummary.GetEnumerator() | Sort-Object Value -Descending
            foreach ($kv in $sortedTech) { $lines.Add("| $($kv.Key) | $($kv.Value) |") }
            $lines.Add("")
        }
        $lines.Add("## Subdomains ($($r.SubdomainsMerged.Count))")
        $lines.Add("")
        $lines.Add('```')
        foreach ($s in $r.SubdomainsMerged) { $lines.Add($s) }
        $lines.Add('```')
        $lines.Add("")
        if ($r.ExpandedScope.Count -gt 0) {
            $lines.Add("### Expanded Scope")
            $lines.Add('```')
            foreach ($s in $r.ExpandedScope) { $lines.Add($s) }
            $lines.Add('```')
            $lines.Add("")
        }
        if ($r.LiveHosts.Count -gt 0) {
            $lines.Add("## Live Hosts ($($r.LiveHosts.Count))")
            $lines.Add("")
            $lines.Add("| Hostname | Status | ms | Title |")
            $lines.Add("|----------|--------|----|-------|")
            foreach ($h in $r.LiveHosts) {
                $t = if ($h.Title) { $h.Title -replace '\|','/' } else { '' }
                $lines.Add("| $($h.Hostname) | $($h.StatusCode) | $($h.ResponseTimeMs) | $t |")
            }
            $lines.Add("")
        }
        if ($r.TechStacks.Count -gt 0) {
            $lines.Add("## Technology Details")
            $lines.Add("")
            foreach ($t in $r.TechStacks) {
                $techList = ($t.Technologies | Select-Object -Unique) -join ', '
                $lines.Add("- **$($t.Url)** -- Server: $($t.Server), CMS: $($t.Cms), Framework: $($t.Framework), Tech: $techList")
            }
            $lines.Add("")
        }
        if ($r.DnsRecords) {
            $lines.Add("## DNS Records")
            $lines.Add("")
            $recordTypes = @('A','AAAA','CNAME','MX','NS','TXT')
            foreach ($rt in $recordTypes) {
                $records = $r.DnsRecords.$rt
                if ($records.Count -gt 0) {
                    $lines.Add("### $rt")
                    $lines.Add('```')
                    foreach ($rec in $records) { $lines.Add($rec) }
                    $lines.Add('```')
                    $lines.Add("")
                }
            }
        }
        if ($r.OpenPorts.Count -gt 0) {
            $lines.Add("## Open Ports")
            $lines.Add("")
            $lines.Add("| Host | Port | Service | ms |")
            $lines.Add("|------|------|---------|----|")
            foreach ($p in $r.OpenPorts) { $lines.Add("| $($p.Hostname) | $($p.Port) | $($p.Service) | $($p.ResponseTimeMs) |") }
            $lines.Add("")
        }
        if ($r.RobotsData -and $r.RobotsData.Fetched) {
            $lines.Add("## Robots.txt")
            $lines.Add("")
            $lines.Add("**URL:** $($r.RobotsData.RobotsUrl)")
            $lines.Add("")
            foreach ($ua in $r.RobotsData.UserAgents) {
                $lines.Add("### User-agent: $($ua.UserAgent)")
                $lines.Add("")
                if ($ua.Disallow.Count -gt 0) {
                    $lines.Add("**Disallow:**")
                    $lines.Add('```')
                    foreach ($d in $ua.Disallow) { $lines.Add($d) }
                    $lines.Add('```')
                }
                if ($ua.Allow.Count -gt 0) {
                    $lines.Add("**Allow:**")
                    $lines.Add('```')
                    foreach ($a in $ua.Allow) { $lines.Add($a) }
                    $lines.Add('```')
                }
            }
            if ($r.RobotsData.Sitemaps.Count -gt 0) {
                $lines.Add("**Sitemaps referenced:**")
                foreach ($sm in $r.RobotsData.Sitemaps) { $lines.Add("- $sm") }
                $lines.Add("")
            }
        }
        if ($r.SitemapData -and $r.SitemapData.Fetched -and $r.SitemapData.Urls.Count -gt 0) {
            $lines.Add("## Sitemap URLs ($($r.SitemapData.Urls.Count))")
            $lines.Add("")
            $display = $r.SitemapData.Urls | Select-Object -First 200
            $lines.Add('```')
            foreach ($u in $display) { $lines.Add($u) }
            $lines.Add('```')
            if ($r.SitemapData.Urls.Count -gt 200) {
                $lines.Add("> Showing first 200 of $($r.SitemapData.Urls.Count) URLs")
            }
            $lines.Add("")
        }
        if ($r.WaybackUrls.Count -gt 0) {
            $lines.Add("## Wayback URLs ($($r.WaybackUrls.Count))")
            $lines.Add("")
            $display = $r.WaybackUrls | Select-Object -First 300
            $lines.Add("| Timestamp | Original | Status | Type |")
            $lines.Add("|-----------|----------|--------|------|")
            foreach ($w in $display) {
                $short = if ($w.Original.Length -gt 80) { $w.Original.Substring(0,77) + '...' } else { $w.Original }
                $lines.Add("| $($w.Timestamp) | $short | $($w.StatusCode) | $($w.MimeType) |")
            }
            $lines.Add("")
        }
        if ($r.Summary.InterestingPaths.Count -gt 0) {
            $lines.Add("## Interesting Paths")
            $lines.Add("")
            $lines.Add('```')
            foreach ($ip in $r.Summary.InterestingPaths) { $lines.Add($ip) }
            $lines.Add('```')
            $lines.Add("")
        }
        $lines.Add("---")
        $lines.Add("")
        $lines.Add("*Report generated by Recon-Toolkit on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')*")
    }
    end {
        $parent = Split-Path -Path $Path -Parent
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        $lines -join "`r`n" | Out-File -FilePath $Path -Encoding utf8 -Force
        Write-Verbose "[Out-ReconReport] Written to $Path"
    }
}

<#
.SYNOPSIS Export recon data as JSON.
.PARAMETER ReconResult Pipeline output object.
.PARAMETER Path Output file path.
.PARAMETER PrettyPrint Indent JSON for readability.
#>
function Export-ReconJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position=0)][PSCustomObject]$ReconResult,
        [Parameter(Mandatory, Position=1)][string]$Path,
        [Parameter()][switch]$PrettyPrint
    )
    process {
        $parent = Split-Path -Path $Path -Parent
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        }
        $json = $ReconResult | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $Path -Encoding utf8 -Force
        Write-Verbose "[Export-ReconJson] Written to $Path"
    }
}

$exportedFunctions = @(
    'Get-SubdomainsCrtSh','Get-SubdomainsSecurityTrails','Get-SubdomainsRapidDns','Get-SubdomainsDnsDumpster',
    'Test-LiveHost','Invoke-BulkHostCheck','Get-HttpTitle','Get-TechStack',
    'Get-RobotsPaths','Get-SitemapPaths','Get-UrlFromWayback','Expand-WildcardScope',
    'Get-DnsRecords','Test-PortOpen','Invoke-ReconPipeline','Out-ReconReport','Export-ReconJson'
)
# Export-ModuleMember intentionally omitted for standalone dot-sourcing.
# Rename to *.psm1 and place in a module path to use module semantics.
# All functions are available after dot-sourcing this script directly.

Write-Host " Recon-Toolkit loaded - $($exportedFunctions.Count) functions" -ForegroundColor Cyan
Write-Host " Quick: Invoke-ReconPipeline -Domain 'example.com' -Verbose" -ForegroundColor Cyan
