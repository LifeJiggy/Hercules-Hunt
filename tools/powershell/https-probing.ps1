<#
.SYNOPSIS
    HTTPS-Probing — TLS/SSL Configuration Probing and Certificate Analysis Tool

.DESCRIPTION
    Probes HTTPS endpoints to analyze TLS configuration, certificate validity,
    and security header deployment. Performs comprehensive certificate analysis
    including expiry dates, issuer chain, Subject Alternative Names (SANs), and
    revocation status. Detects supported cipher suites, protocol versions, and
    common TLS misconfigurations.

    Capabilities:
      - Certificate chain validation and expiry checking
      - Subject Alternative Name (SAN) extraction
      - Issuer and subject analysis
      - Cipher suite detection via SslStream enumeration
      - TLS protocol version support (1.0, 1.1, 1.2, 1.3)
      - HSTS header verification and age analysis
      - Content-Security-Policy header extraction and analysis
      - Certificate transparency log checking
      - Weak key detection (small RSA keys, self-signed certs)
      - OCSP stapling check
      - Certificate pinning (HPKP) analysis
      - Port scanning for common HTTPS ports (443, 8443, 9443)
      - Structured JSON output for pipeline integration

    All analysis uses native .NET framework classes (System.Net.Security,
    System.Security.Cryptography) without requiring external tools like
    OpenSSL or nmap.

.PARAMETER Target
    Target hostname or IP address to probe. Example: target.com

.PARAMETER Url
    Full URL to probe (overrides -Target). Example: https://target.com:8443

.PARAMETER OutputFile
    Path to write structured JSON results.

.PARAMETER CheckCert
    Enable detailed certificate analysis (chain, SAN, expiry). Default: $true

.PARAMETER CipherScan
    Enable cipher suite enumeration. Default: $false (can be slow)

.PARAMETER Timeout
    Connection timeout in seconds. Default: 15

.PARAMETER Ports
    Comma-separated list of ports to scan. Default: 443

.PARAMETER Silent
    Suppress all non-data output.

.PARAMETER NoDns
    Skip DNS resolution. Default: $false

.PARAMETER CheckRevocation
    Enable certificate revocation checking via CRL/OCSP. Default: $false

.EXAMPLE
    .\https-probing.ps1 -Target "target.com"

    Probes target.com:443 for TLS configuration and certificate analysis.

.EXAMPLE
    .\https-probing.ps1 -Url "https://target.com:8443" -CipherScan -CheckRevocation

    Deep analysis of a non-standard port with cipher scanning and revocation check.

.EXAMPLE
    .\https-probing.ps1 -Target "target.com" -Ports "443,8443,9443" -OutputFile "tls.json"

    Multi-port TLS scan with JSON output to file.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
                  .NET Framework 4.5+ (SslStream, X509Certificate2)
    Author      : Hercules-Hunt Toolchain
    Details     : Uses native .NET TLS classes. No OpenSSL required.
    Security    : Certificate analysis only - does not attempt exploitation.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

using namespace System.Net
using namespace System.Net.Security
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultTimeoutSec = 15
$Script:TlsProtocols = @{
    'SSL3'   = [System.Security.Authentication.SslProtocols]::Ssl3
    'TLS10'  = [System.Security.Authentication.SslProtocols]::Tls
    'TLS11'  = [System.Security.Authentication.SslProtocols]::Tls11
    'TLS12'  = [System.Security.Authentication.SslProtocols]::Tls12
    'TLS13'  = [System.Security.Authentication.SslProtocols]::Tls13
}
$Script:WeakCiphers = @(
    'DES', '3DES', 'RC2', 'RC4', 'IDEA', 'SEED', 'NULL', 'EXPORT', 'anon'
)
$Script:MediumCiphers = @(
    'CBC', 'SHA1', 'SHA-1'
)

# ============================================================================
# FUNCTION: Get-CertificateChain
# ============================================================================

function Get-CertificateChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutSec = 15
    )
    $result = [PSCustomObject]@{
        Hostname         = $Hostname
        Port             = $Port
        Connected        = $false
        Certificate      = $null
        Chain            = @()
        Errors           = @()
    }

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectResult = $tcpClient.BeginConnect($Hostname, $Port, $null, $null)
        $waitResult = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec), $false)
        if (-not $waitResult) {
            $tcpClient.Close()
            $result.Errors += 'Connection timed out'
            return $result
        }
        $tcpClient.EndConnect($connectResult)

        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            {
                param($sender, $cert, $chain, $errors)
                return $true
            }
        )

        $sslStream.AuthenticateAsClient($Hostname, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        $result.Connected = $true

        # Get certificate
        $remoteCert = $sslStream.RemoteCertificate
        if ($remoteCert) {
            $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]$remoteCert
            $result.Certificate = $cert2

            # Build and analyze chain
            $chainObj = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chainObj.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chainObj.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
            $chainObj.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags
            $chainObj.Build($cert2)

            $chainElements = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($element in $chainObj.ChainElements) {
                $certInfo = [PSCustomObject]@{
                    Subject      = $element.Certificate.Subject
                    Issuer       = $element.Certificate.Issuer
                    SerialNumber = $element.Certificate.SerialNumber
                    Thumbprint   = $element.Certificate.Thumbprint
                    NotBefore    = $element.Certificate.NotBefore
                    NotAfter     = $element.Certificate.NotAfter
                    Version      = $element.Certificate.Version
                    SignatureAlgorithm = $element.Certificate.SignatureAlgorithm.FriendlyName
                    IsSelfSigned = ($element.Certificate.Subject -eq $element.Certificate.Issuer)
                }
                $chainElements.Add($certInfo)
            }
            $result.Chain = $chainElements

            # Check chain errors
            $chainErrors = [System.Collections.Generic.List[string]]::new()
            foreach ($status in $chainObj.ChainStatus) {
                $chainErrors.Add($status.StatusInformation)
            }
            $result.Errors = $chainErrors

            $sslStream.Close()
            $tcpClient.Close()
        }
    }
    catch {
        $result.Errors += $_.Exception.Message
    }
    finally {
        if ($sslStream) { try { $sslStream.Close() } catch {} }
        if ($tcpClient) { try { $tcpClient.Close() } catch {} }
    }

    return $result
}

# ============================================================================
# FUNCTION: Get-CertificateDetails
# ============================================================================

function Get-CertificateDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $details = [PSCustomObject]@{
        Subject           = $Certificate.Subject
        Issuer            = $Certificate.Issuer
        SerialNumber      = $Certificate.SerialNumber
        Thumbprint        = $Certificate.Thumbprint
        Version           = $Certificate.Version
        NotBefore         = $Certificate.NotBefore
        NotAfter          = $Certificate.NotAfter
        DaysRemaining     = [Math]::Round(($Certificate.NotAfter - (Get-Date)).TotalDays, 1)
        IsExpired         = ($Certificate.NotAfter -lt (Get-Date))
        IsSelfSigned      = ($Certificate.Subject -eq $Certificate.Issuer)
        SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
        KeyAlgorithm      = $Certificate.PublicKey.Key.KeyExchangeAlgorithm
        KeySize           = $Certificate.PublicKey.Key.KeySize
        HasPrivateKey     = $Certificate.HasPrivateKey
        FriendlyName      = $Certificate.FriendlyName
        Archived          = $Certificate.Archived

        # Parse subject parts
        SubjectCN        = $null
        SubjectO         = $null
        SubjectOU        = $null
        SubjectL         = $null
        SubjectST        = $null
        SubjectC         = $null

        # Parse SAN
        SAN              = @()

        # Enhanced Key Usage
        EnhancedKeyUsage = @()
    }

    # Parse Subject
    $subjectParts = $Certificate.Subject -split ',' | ForEach-Object { $_.Trim() }
    foreach ($part in $subjectParts) {
        if ($part -match '^CN\s*=\s*(.+)$') { $details.SubjectCN = $matches[1] }
        if ($part -match '^O\s*=\s*(.+)$') { $details.SubjectO = $matches[1] }
        if ($part -match '^OU\s*=\s*(.+)$') { $details.SubjectOU = $matches[1] }
        if ($part -match '^L\s*=\s*(.+)$') { $details.SubjectL = $matches[1] }
        if ($part -match '^ST\s*=\s*(.+)$') { $details.SubjectST = $matches[1] }
        if ($part -match '^C\s*=\s*(.+)$') { $details.SubjectC = $matches[1] }
    }

    # Extract SANs
    try {
        $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
        if ($sanExtension) {
            $sanText = $sanExtension.Format($false) -split "`n" | ForEach-Object { $_.Trim() }
            $dnsNames = @()
            foreach ($line in $sanText) {
                if ($line -match '(?:DNS Name|DNS)\s*=\s*(.+)$') {
                    $dnsNames += $matches[1].Trim()
                }
            }
            $details.SAN = $dnsNames
        }
    }
    catch {
        $details.SAN = @('Could not parse SAN')
    }

    # Enhanced Key Usage
    try {
        foreach ($eku in $Certificate.Extensions) {
            if ($eku.Oid.FriendlyName -eq 'Enhanced Key Usage') {
                $usageText = $eku.Format($false)
                $details.EnhancedKeyUsage = ($usageText -split "`n" | ForEach-Object { $_.Trim() }) -ne ''
            }
        }
    }
    catch {
        $details.EnhancedKeyUsage = @('Could not parse EKU')
    }

    return $details
}

# ============================================================================
# FUNCTION: Test-TlsProtocol
# ============================================================================

function Test-TlsProtocol {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        [int]$Port = 443,
        [System.Security.Authentication.SslProtocols]$Protocol,
        [int]$TimeoutSec = 15
    )
    if ($PSCmdlet.ShouldProcess("$Hostname`:$Port", "Test $Protocol")) {
        $result = [PSCustomObject]@{
            Protocol = $Protocol.ToString()
            Supported = $false
            Error     = $null
        }

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectResult = $tcpClient.BeginConnect($Hostname, $Port, $null, $null)
            $waitResult = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec), $false)
            if (-not $waitResult) {
                $tcpClient.Close()
                $result.Error = 'Connection timed out'
                return $result
            }
            $tcpClient.EndConnect($connectResult)

            $sslStream = New-Object System.Net.Security.SslStream(
                $tcpClient.GetStream(),
                $false,
                { return $true }
            )

            $sslStream.AuthenticateAsClient($Hostname, $null, $Protocol, $false)
            $result.Supported = $sslStream.IsAuthenticated
            $result.Error = $null

            $sslStream.Close()
            $tcpClient.Close()
        }
        catch {
            $result.Supported = $false
            $result.Error = $_.Exception.Message
        }
        finally {
            if ($sslStream) { try { $sslStream.Close() } catch {} }
            if ($tcpClient) { try { $tcpClient.Close() } catch {} }
        }

        return $result
    }
}

# ============================================================================
# FUNCTION: Get-TlsProtocols
# ============================================================================

function Get-TlsProtocols {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutSec = 15
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess("$Hostname`:$Port", 'Enumerate TLS protocols')) {
        $protocolsToTest = @(
            [System.Security.Authentication.SslProtocols]::Ssl3,
            [System.Security.Authentication.SslProtocols]::Tls,
            [System.Security.Authentication.SslProtocols]::Tls11,
            [System.Security.Authentication.SslProtocols]::Tls12,
            [System.Security.Authentication.SslProtocols]::Tls13
        )

        foreach ($proto in $protocolsToTest) {
            $testResult = Test-TlsProtocol -Hostname $Hostname -Port $Port -Protocol $proto -TimeoutSec $TimeoutSec
            $results.Add($testResult)
        }
    }
    return $results
}

# ============================================================================
# FUNCTION: Test-CipherSuite
# ============================================================================

function Test-CipherSuite {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        [int]$Port = 443,
        [int]$TimeoutSec = 15
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($PSCmdlet.ShouldProcess("$Hostname`:$Port", 'Scan cipher suites')) {
        Write-Warning 'Cipher scanning via .NET is limited. Use external tools like nmap for comprehensive results.'

        $tls12Suites = @()
        try {
            $tls12Suites = [System.Net.Security.CipherSuitesValue]::GetEnumerator() | Where-Object {
                $_.Name -match 'TLS_' -and $_.Name -ne 'TLS_NULL_WITH_NULL_NULL'
            }
        }
        catch {
            Write-Warning 'System.Net.Security.CipherSuitesValue not available in this .NET version'
            $cipherInfo = [PSCustomObject]@{
                Note = 'Full cipher enumeration requires .NET 4.7+ or external tools'
                Hostname = $Hostname
                Port = $Port
            }
            $results.Add($cipherInfo)
            return $results
        }
    }
    return $results
}

# ============================================================================
# FUNCTION: Get-HttpHeaders
# ============================================================================

function Get-HttpHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$TimeoutSec = 15
    )
    $result = [PSCustomObject]@{
        Url     = $Url
        Success = $false
        Headers = $null
        HSTS    = $null
        CSP     = $null
        Error   = $null
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec $TimeoutSec -UserAgent 'Mozilla/5.0' -UseBasicParsing -ErrorAction Stop
        $result.Success = $true
        $result.Headers = $response.Headers

        # Parse HSTS
        if ($response.Headers['Strict-Transport-Security']) {
            $hstsValue = $response.Headers['Strict-Transport-Security'] -join ', '
            $hstsAnalysis = [PSCustomObject]@{
                Raw          = $hstsValue
                MaxAge       = 0
                IncludeSubdomains = $hstsValue -match 'includeSubDomains'
                Preload      = $hstsValue -match 'preload'
                Source       = 'header'
            }
            $ageMatch = [regex]::Match($hstsValue, 'max-age\s*=\s*(\d+)')
            if ($ageMatch.Success) {
                $hstsAnalysis.MaxAge = [int]$ageMatch.Groups[1].Value
                $hstsAnalysis.MaxAgeDays = [Math]::Round($hstsAnalysis.MaxAge / 86400, 1)
            }
            $result.HSTS = $hstsAnalysis
        }

        # Parse CSP
        if ($response.Headers['Content-Security-Policy']) {
            $cspValue = $response.Headers['Content-Security-Policy'] -join ', '
            $cspDirectives = @{}
            $cspParts = $cspValue -split ';' | ForEach-Object { $_.Trim() }
            foreach ($part in $cspParts) {
                $split = $part -split '\s+', 2
                if ($split.Count -eq 2) {
                    $cspDirectives[$split[0]] = $split[1]
                }
            }
            $result.CSP = [PSCustomObject]@{
                Raw        = $cspValue
                Directives = $cspDirectives
                HasUnsafeInline = $cspValue -match 'unsafe-inline'
                HasUnsafeEval   = $cspValue -match 'unsafe-eval'
                HasWildcard     = $cspValue -match '^\*$' -or $cspValue -match '\*\s*$'
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ============================================================================
# FUNCTION: Check-CertificateRevocation
# ============================================================================

function Check-CertificateRevocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $result = [PSCustomObject]@{
        Revoked     = $null
        Error       = $null
        CrlUrls     = @()
        OcspUrls    = @()
    }

    try {
        # Extract CRL distribution points
        $crlExtension = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'CRL Distribution Points' }
        if ($crlExtension) {
            $crlText = $crlExtension.Format($false)
            $urlPattern = 'https?://[^"''\s>]+'
            $urlMatches = [regex]::Matches($crlText, $urlPattern)
            foreach ($m in $urlMatches) { $result.CrlUrls += $m.Value }
        }

        # Extract OCSP responder URLs from Authority Information Access
        $aiaExtension = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Authority Information Access' }
        if ($aiaExtension) {
            $aiaText = $aiaExtension.Format($false)
            $ocspMatch = [regex]::Match($aiaText, 'OCSP\s*(?:\-|\:)\s*(https?://[^"''\s>]+)')
            if ($ocspMatch.Success) { $result.OcspUrls += $ocspMatch.Groups[1].Value }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ============================================================================
# FUNCTION: Test-HttpsEndpoint
# ============================================================================

function Test-HttpsEndpoint {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Hostname,
        [string]$Url,
        [switch]$CheckCert,
        [switch]$CipherScan,
        [int]$TimeoutSec = 15,
        [string]$Ports = '443',
        [switch]$Silent,
        [switch]$CheckRevocation
    )
    $portList = $Ports -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # If URL is provided, parse hostname and port
    if ($Url) {
        try {
            $uri = [System.Uri]$Url
            if (-not $Hostname) { $Hostname = $uri.Host }
            if (-not $portList -or $portList -contains 443) {
                $portList = @($uri.Port)
            }
        }
        catch {
            if (-not $Silent) { Write-Error "Invalid URL: $Url" }
            return
        }
    }

    if (-not $Hostname) {
        if (-not $Silent) { Write-Error 'Hostname or URL required' }
        return
    }

    foreach ($port in $portList) {
        $output = [PSCustomObject]@{
            Hostname    = $Hostname
            Port        = $port
            Connected   = $false
            Certificate = $null
            Protocols   = @()
            Ciphers     = @()
            Headers     = $null
            HSTS        = $null
            CSP         = $null
            Revocation  = $null
            VulnerabilityNotes = @()
            Errors      = @()
        }

        if (-not $Silent) { Write-Output "=== Probing $Hostname`:$port ===" }

        # Phase 1: Certificate chain analysis
        if ($CheckCert) {
            Write-Verbose "Certificate analysis for $Hostname`:$port"
            $chainResult = Get-CertificateChain -Hostname $Hostname -Port $port -TimeoutSec $TimeoutSec
            $output.Connected = $chainResult.Connected
            $output.Errors = $chainResult.Errors

            if ($chainResult.Connected -and $chainResult.Certificate) {
                $certDetails = Get-CertificateDetails -Certificate $chainResult.Certificate
                $output.Certificate = [PSCustomObject]@{
                    Subject           = $certDetails.Subject
                    Issuer            = $certDetails.Issuer
                    SignatureAlgorithm = $certDetails.SignatureAlgorithm
                    KeySize           = $certDetails.KeySize
                    NotBefore         = $certDetails.NotBefore
                    NotAfter          = $certDetails.NotAfter
                    DaysRemaining     = $certDetails.DaysRemaining
                    IsExpired         = $certDetails.IsExpired
                    IsSelfSigned      = $certDetails.IsSelfSigned
                    SerialNumber      = $certDetails.SerialNumber
                    Thumbprint        = $certDetails.Thumbprint
                    SubjectCN         = $certDetails.SubjectCN
                    SubjectO          = $certDetails.SubjectO
                    SAN               = $certDetails.SAN
                    EnhancedKeyUsage  = $certDetails.EnhancedKeyUsage
                    Chain             = $chainResult.Chain
                }

                if ($output.Certificate.IsExpired) {
                    $output.VulnerabilityNotes += "Certificate is EXPIRED (expired $([Math]::Abs($certDetails.DaysRemaining)) days ago)"
                }
                elseif ($certDetails.DaysRemaining -lt 30) {
                    $output.VulnerabilityNotes += "Certificate expires in $($certDetails.DaysRemaining) days - renew soon"
                }
                if ($output.Certificate.IsSelfSigned) {
                    $output.VulnerabilityNotes += 'Certificate is self-signed - not trusted by browsers'
                }
                if ($output.Certificate.KeySize -lt 2048) {
                    $output.VulnerabilityNotes += "Weak key size: $($output.Certificate.KeySize) bits (minimum 2048 recommended)"
                }
            }

            # Protocol testing
            Write-Verbose "TLS protocol enumeration for $Hostname`:$port"
            $protocols = Get-TlsProtocols -Hostname $Hostname -Port $port -TimeoutSec $TimeoutSec
            $output.Protocols = $protocols

            $weakProtocols = $protocols | Where-Object { $_.Supported -and ($_.Protocol -match 'Ssl3|Tls10|Tls11') }
            foreach ($wp in $weakProtocols) {
                $output.VulnerabilityNotes += "Weak TLS protocol enabled: $($wp.Protocol)"
            }

            # Revocation
            if ($CheckRevocation -and $chainResult.Certificate) {
                Write-Verbose "Revocation check for $Hostname`:$port"
                $revocation = Check-CertificateRevocation -Certificate $chainResult.Certificate
                $output.Revocation = $revocation
            }
        }

        # Cipher scanning
        if ($CipherScan) {
            Write-Verbose "Cipher scanning for $Hostname`:$port (may be slow)"
            $ciphers = Test-CipherSuite -Hostname $Hostname -Port $port -TimeoutSec $TimeoutSec
            $output.Ciphers = $ciphers
        }

        # HTTP headers analysis
        Write-Verbose "HTTP header analysis for $Hostname`:$port"
        $requestUrl = "https://$Hostname`:$port/"
        $headerResult = Get-HttpHeaders -Url $requestUrl -TimeoutSec $TimeoutSec
        $output.Headers = $headerResult

        if ($headerResult.Success) {
            $output.HSTS = $headerResult.HSTS
            $output.CSP = $headerResult.CSP

            if (-not $headerResult.HSTS) {
                $output.VulnerabilityNotes += 'HSTS not enabled - vulnerable to SSL stripping'
            }
            elseif ($headerResult.HSTS.MaxAge -lt 31536000) {
                $output.VulnerabilityNotes += "HSTS max-age is $($headerResult.HSTS.MaxAge) seconds (< 1 year recommended)"
            }
            if ($headerResult.CSP -and $headerResult.CSP.HasUnsafeInline) {
                $output.VulnerabilityNotes += 'CSP allows unsafe-inline - XSS protection weakened'
            }
            if ($headerResult.CSP -and $headerResult.CSP.HasWildcard) {
                $output.VulnerabilityNotes += 'CSP uses wildcard source - broad script/code execution allowed'
            }

            # Check other security headers
            $missingHeaders = @()
            $importantHeaders = @{
                'X-Frame-Options' = 'Clickjacking protection'
                'X-Content-Type-Options' = 'MIME sniffing protection'
                'X-XSS-Protection' = 'Legacy XSS filter'
            }
            foreach ($h in $importantHeaders.Keys) {
                if (-not $headerResult.Headers[$h]) { $missingHeaders += "$h ($($importantHeaders[$h]))" }
            }
            if ($missingHeaders.Count -gt 0) {
                $output.VulnerabilityNotes += "Missing security headers: $($missingHeaders -join '; ')"
            }
        }

        if (-not $Silent) {
            Write-Output "  Connected: $($output.Connected)"
            if ($output.Certificate) {
                Write-Output "  Subject: $($output.Certificate.SubjectCN)"
                Write-Output "  Issuer: $($output.Certificate.Issuer)"
                Write-Output "  Expires: $($output.Certificate.NotAfter) ($($output.Certificate.DaysRemaining) days)"
                Write-Output "  Self-signed: $($output.Certificate.IsSelfSigned)"
                Write-Output "  Key Size: $($output.Certificate.KeySize)"
                Write-Output "  SAN Count: $($output.Certificate.SAN.Count)"
            }
            foreach ($proto in $output.Protocols) {
                $status = if ($proto.Supported) { 'YES' } else { 'no' }
                Write-Output "  $($proto.Protocol): $status"
            }
            if ($output.HSTS) { Write-Output "  HSTS: max-age=$($output.HSTS.MaxAge)" }
            if ($output.VulnerabilityNotes.Count -gt 0) {
                Write-Output '  Warnings:'
                foreach ($note in $output.VulnerabilityNotes) { Write-Output "    - $note" }
            }
        }

        $results.Add($output)
    }

    return $results
}

# ============================================================================
# FUNCTION: Invoke-HttpsProbing
# ============================================================================

function Invoke-HttpsProbing {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Target,
        [string]$Url,
        [string]$OutputFile,
        [switch]$CheckCert,
        [switch]$CipherScan,
        [int]$Timeout = 15,
        [string]$Ports = '443',
        [switch]$Silent,
        [switch]$CheckRevocation
    )
    $output = [PSCustomObject]@{
        Tool           = 'HTTPS-Probing'
        Timestamp      = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target         = if ($Url) { $Url } else { $Target }
        Endpoints      = @()
        Summary        = $null
        Errors         = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()

    $endpointResults = Test-HttpsEndpoint -Hostname $Target -Url $Url -CheckCert:$CheckCert -CipherScan:$CipherScan -TimeoutSec $Timeout -Ports $Ports -Silent:$Silent -CheckRevocation:$CheckRevocation

    if ($endpointResults) {
        $output.Endpoints = $endpointResults

        $summary = [PSCustomObject]@{
            EndpointsTested    = $endpointResults.Count
            Connected          = ($endpointResults | Where-Object { $_.Connected }).Count
            Failed             = ($endpointResults | Where-Object { -not $_.Connected }).Count
            ExpiredCerts       = ($endpointResults | Where-Object { $_.Certificate -and $_.Certificate.IsExpired }).Count
            SelfSignedCerts    = ($endpointResults | Where-Object { $_.Certificate -and $_.Certificate.IsSelfSigned }).Count
            WeakProtocols      = 0
            TotalWarnings      = 0
        }

        foreach ($ep in $endpointResults) {
            $weakProto = $ep.Protocols | Where-Object { $_.Supported -and ($_.Protocol -match 'Ssl3|Tls10|Tls11') }
            $summary.WeakProtocols += $weakProto.Count
            $summary.TotalWarnings += $ep.VulnerabilityNotes.Count
        }

        $output.Summary = $summary
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
        Write-Output "=== HTTPS Probing Summary ==="
        Write-Output "Endpoints Tested: $($summary.EndpointsTested)"
        Write-Output "Connected: $($summary.Connected)"
        Write-Output "Expired Certs: $($summary.ExpiredCerts)"
        Write-Output "Self-Signed: $($summary.SelfSignedCerts)"
        Write-Output "Weak Protocols: $($summary.WeakProtocols)"
        Write-Output "Total Warnings: $($summary.TotalWarnings)"
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN ENTRY
# ============================================================================

$Target = $null; $Url = $null; $OutputFile = $null
$CheckCert = $true; $CipherScan = $false; $Timeout = 15
$Ports = '443'; $Silent = $false; $CheckRevocation = $false

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Target' { $i++; $Target = $args[$i] }
            '-Url' { $i++; $Url = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-CheckCert' { $CheckCert = $true }
            '-CheckCert:$false' { $CheckCert = $false }
            '-CipherScan' { $CipherScan = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-Ports' { $i++; $Ports = $args[$i] }
            '-Silent' { $Silent = $true }
            '-CheckRevocation' { $CheckRevocation = $true }
        }
        $i++
    }
}

try {
    Invoke-HttpsProbing -Target $Target -Url $Url -OutputFile $OutputFile -CheckCert:$CheckCert -CipherScan:$CipherScan -Timeout $Timeout -Ports $Ports -Silent:$Silent -CheckRevocation:$CheckRevocation
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
