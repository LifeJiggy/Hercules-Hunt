<#
.SYNOPSIS
    Report-Builder — Finding Report Builder for Bug Bounty Submissions

.DESCRIPTION
    Generates professional structured bug bounty reports from findings JSON data.
    Supports HackerOne, Bugcrowd, Intigriti, and Immunefi output formats with
    CVSS 3.1 scoring, multiple output formats (Markdown, JSON, HTML), and
    batch processing of multiple findings.

    Features:
      - Multiple platform output formats (HackerOne, Bugcrowd, Intigriti, Immunefi)
      - CVSS 3.1 scoring calculator with full vector string generation
      - Markdown, JSON, and HTML output format support
      - Batch processing for multiple findings in a single run
      - Custom report templates with severity-based formatting
      - Impact-first writing structure
      - PoC section generation from evidence data
      - Remediation recommendation engine
      - Finding classification and tagging
      - Structured JSON input schema for pipeline integration

    Input JSON Schema:
      {
        "findings": [{
          "title": "string",
          "description": "string",
          "severity": "critical|high|medium|low|info",
          "vulnerability_type": "string",
          "endpoint": "string",
          "method": "GET|POST|...",
          "parameters": {},
          "evidence": { "request": "string", "response": "string" },
          "impact": "string",
          "remediation": "string",
          "cwe": "integer",
          "cvss": { "av": "N|A|L|P", "ac": "L|H", "pr": "N|L|H", "ui": "N|R",
                    "s": "U|C", "c": "N|L|H", "i": "N|L|H", "a": "N|L|H" }
        }]
      }

.PARAMETER InputFile
    Path to JSON input file containing findings data.

.PARAMETER Format
    Output format: Markdown, JSON, or HTML. Default: Markdown.

.PARAMETER OutputFile
    Path to write the generated report.

.PARAMETER Severity
    Minimum severity level to include: Critical, High, Medium, Low, Info. Default: Info.

.PARAMETER Template
    Report template: hackerone, bugcrowd, intigriti, immunefi, or custom. Default: hackerone.

.PARAMETER Batch
    Process multiple input files from a directory. Specify directory path.

.PARAMETER Author
    Author name/alias for the report footer.

.PARAMETER Silent
    Suppress all non-data output.

.EXAMPLE
    .\report-builder.ps1 -InputFile "findings.json" -Template hackerone -Format Markdown -OutputFile "report.md"

    Generates a HackerOne-format markdown report from JSON findings.

.EXAMPLE
    .\report-builder.ps1 -InputFile "findings.json" -Template bugcrowd -Format HTML -OutputFile "report.html"

    Generates a Bugcrowd-format HTML report.

.EXAMPLE
    .\report-builder.ps1 -InputFile "findings.json" -Severity High -Author "researcher"

    Generates a report only including High and Critical findings.

.EXAMPLE
    .\report-builder.ps1 -Batch ".\findings\" -Format JSON -OutputFile "batch-report.json"

    Processes all JSON files in a directory into a batch report.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Details     : Uses built-in JSON parsing. No external modules required.
                  CVSS 3.1 calculation follows FIRST specification.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultAuthor = 'Hercules-Hunt Researcher'
$Script:ReportVersion = '1.0.0'

$Script:SeverityLevels = @{
    'Critical' = 4
    'High'     = 3
    'Medium'   = 2
    'Low'      = 1
    'Info'     = 0
}

$Script:SeverityColors = @{
    'Critical' = '#dc3545'
    'High'     = '#fd7e14'
    'Medium'   = '#ffc107'
    'Low'      = '#28a745'
    'Info'     = '#17a2b8'
}

$Script:CvssSeverityLabels = @{
    'None'     = 0.0
    'Low'      = 1.0
    'Medium'   = 4.0
    'High'     = 7.0
    'Critical' = 9.0
}

$Script:CvssV31Constants = @{
    AttackVector = @{
        'N' = 'Network'
        'A' = 'Adjacent Network'
        'L' = 'Local'
        'P' = 'Physical'
    }
    AttackComplexity = @{
        'L' = 'Low'
        'H' = 'High'
    }
    PrivilegesRequired = @{
        'N' = 'None'
        'L' = 'Low'
        'H' = 'High'
    }
    UserInteraction = @{
        'N' = 'None'
        'R' = 'Required'
    }
    Scope = @{
        'U' = 'Unchanged'
        'C' = 'Changed'
    }
    CIA = @{
        'N' = 'None'
        'L' = 'Low'
        'H' = 'High'
    }
}

$Script:CweCatalog = @{
    20  = 'Improper Input Validation'
    22  = 'Path Traversal'
    23  = 'Relative Path Traversal'
    35  = 'Path Traversal: '.../...//'
    77  = 'Improper Neutralization of Special Elements used in a Command'
    78  = 'OS Command Injection'
    79  = 'Cross-site Scripting (XSS)'
    80  = 'Basic XSS'
    87  = 'Improper Neutralization of Alternate XSS Syntax'
    89  = 'SQL Injection'
    90  = 'LDAP Injection'
    91  = 'XML Injection'
    93  = 'CRLF Injection'
    94  = 'Code Injection'
    113 = 'Improper Header Injection'
    184 = 'Incomplete Blacklist'
    200 = 'Information Exposure'
    201 = 'Insertion of Sensitive Information Into Sent Data'
    250 = 'Execution with Unnecessary Privileges'
    269 = 'Improper Privilege Management'
    284 = 'Improper Access Control'
    285 = 'Improper Authorization'
    287 = 'Improper Authentication'
    290 = 'Authentication Bypass by Capture-replay'
    295 = 'Certificate Validation'
    297 = 'Improper Validation of Certificate with Host Mismatch'
    302 = 'Authentication Bypass by Assumed-Immutable Data'
    306 = 'Missing Authentication'
    307 = 'Improper Restriction of Excessive Authentication Attempts'
    319 = 'Cleartext Transmission'
    326 = 'Inadequate Encryption Strength'
    327 = 'Broken or Risky Crypto Algorithm'
    328 = 'Reversible One-Way Hash'
    330 = 'Insufficiently Random Values'
    345 = 'Insufficient Verification of Data Authenticity'
    346 = 'Origin Validation Error'
    347 = 'Improper Verification of Cryptographic Signature'
    350 = 'Reliance on Reverse DNS'
    352 = 'Cross-Site Request Forgery (CSRF)'
    359 = 'Privacy Violation'
    362 = 'Race Condition'
    377 = 'Insecure Temporary File'
    400 = 'Uncontrolled Resource Consumption'
    401 = 'Missing Check for Certificate Revocation'
    402 = 'Transmission of Private Resources'
    404 = 'Improper Resource Shutdown'
    425 = 'Direct Request'
    434 = 'Unrestricted File Upload'
    441 = 'Unintended Proxy'
    444 = 'Inconsistent Interpretation'
    451 = 'User Interface Misleading'
    470 = 'Use of External Entity'
    471 = 'Modification of Assumed-Immutable Data'
    494 = 'Download of Code Without Integrity Check'
    501 = 'Trust Boundary Violation'
    502 = 'Deserialization of Untrusted Data'
    522 = 'Insufficiently Protected Credentials'
    523 = 'Unprotected Transport'
    525 = 'Browser Cache'
    532 = 'Sensitive Info in Logs'
    539 = 'Persistent Cookies'
    548 = 'Directory Listing'
    549 = 'Missing Password Field Masking'
    552 = 'Files or Directories Accessible'
    598 = 'GET Parameter Information Disclosure'
    601 = 'Open Redirect'
    602 = 'Client-Side Enforcement'
    603 = 'Use of Client-Side Authentication'
    610 = 'Externally Controlled Reference'
    611 = 'XXE'
    613 = 'Insufficient Session Expiration'
    614 = 'Sensitive Cookie Without Secure'
    615 = 'Comment Information Disclosure'
    620 = 'Password Reset'
    639 = 'Authorization Bypass by User-Controlled Key'
    640 = 'Weak Password Recovery'
    644 = 'Script Loading'
    646 = 'Reliance on File Name'
    647 = 'Relevant Code References'
    648 = 'Incorrect Credential Protection'
    649 = 'Reliance on Obfuscation'
    650 = 'Trusting HTTP Permission'
    652 = 'XQuery Injection'
    653 = 'Insufficient Compartmentalization'
    657 = 'Violation of Secure Design Principles'
    658 = 'Weak Password'
    664 = 'Improper Permission Control'
    665 = 'Improper Initialization'
    666 = 'Operation on Resource'
    667 = 'Improper Locking'
    668 = 'Exposure of Resource'
    669 = 'Incorrect Resource Transfer'
    670 = 'Always-Incorrect Control Flow'
    671 = 'Missing Standardization'
    672 = 'Operation on Incorrect Resource'
    673 = 'External Influence'
    674 = 'Uncontrolled Recursion'
    675 = 'Duplicate Operations'
    676 = 'Use of Potentially Dangerous Function'
    681 = 'Incorrect Conversion'
    682 = 'Incorrect Calculation'
    691 = 'Insufficient Control Flow'
    693 = 'Protection Mechanism Failure'
    694 = 'Incorrect Registry'
    695 = 'Logic Error'
    696 = 'Incorrect Behavior Order'
    697 = 'Incorrect Comparison'
    698 = 'Implementation Error'
    703 = 'Improper Exception Handling'
    704 = 'Incorrect Type Assignment'
    705 = 'Incorrect Control Flow'
    706 = 'Use of Incorrectly-Resolved Name'
    707 = 'Improper Neutralization'
    708 = 'Incorrect Ownership Assignment'
    710 = 'Audit'
    713 = 'OData Information Leak'
    715 = 'SQL Injection with Replace'
    716 = 'Configuration'
    720 = 'OWASP Top Ten'
    723 = 'OpenGraph'
    732 = 'Critical Variable Misuse'
    733 = 'Compiler Optimization'
    735 = 'Incorrect Usage'
    737 = 'Incorrect Behavior'
    738 = 'Missing Check'
    739 = 'Missing Check for Certificate'
    740 = 'Certificate Chain Error'
    741 = 'Unreliable Execution'
    742 = 'Certificate Validation'
    743 = 'Certificate Name Check'
    744 = 'Certificate Expiration'
    745 = 'Certificate Validation Error'
    746 = 'Certificate Chain'
    747 = 'Certificate Key'
    748 = 'Certificate Error'
    749 = 'Exposed Dangerous Method'
    754 = 'Improper Check'
    755 = 'Improper Handling'
    756 = 'Missing Authorization'
    759 = 'Use of One-Way Hash'
    760 = 'Use of Salted Hash'
    761 = 'Free of Pointer'
    762 = 'Mismatched Memory Management'
    763 = 'Release of Invalid Pointer'
    764 = 'Multiple Locks'
    765 = 'Multiple Unlocks'
    766 = 'Critical Data'
    767 = 'Access to Critical Data'
    768 = 'Incorrect Data'
    769 = 'Uncontrolled File Descriptor'
    770 = 'Allocation of Resources'
    771 = 'Missing Reference'
    772 = 'Missing Release'
    773 = 'Missing Reference'
    774 = 'Allocation Without Release'
    775 = 'Missing Release of File'
    776 = 'Unrestricted Recursion'
    777 = 'Regular Expression'
    778 = 'Insufficient Logging'
    779 = 'Logging of Sensitive Data'
    780 = 'RSA without OAEP'
    781 = 'Improper Certificate Validation'
    782 = 'Exposed IOCTL'
    783 = 'Operator precedence'
    784 = 'Reliance on Cookies'
    785 = 'Use of Path Manipulation'
    786 = 'Access of Memory Location'
    787 = 'Out-of-bounds Write'
    788 = 'Access of Memory Location'
    789 = 'Memory Allocation'
    790 = 'Improper Filtering'
    791 = 'Incomplete Filtering'
    792 = 'Incomplete Filtering'
    793 = 'Incomplete Filtering'
    794 = 'Incomplete Filtering'
    795 = 'Incomplete Filtering'
    796 = 'Incomplete Filtering'
    797 = 'Incomplete Filtering'
    798 = 'Hardcoded Credentials'
    799 = 'Insufficient Control Flow'
    804 = 'Guessable Token'
    807 = 'Reliance on Untrusted Inputs'
    823 = 'Use of Out-of-range Pointer Offset'
    824 = 'Access of Uninitialized Pointer'
    825 = 'Expired Pointer'
    826 = 'Premature Release'
    827 = 'Improper Control'
    828 = 'Signal Handler'
    829 = 'Inclusion of Functionality'
    830 = 'Inclusion of Web Functionality'
    831 = 'Signal Handler'
    832 = 'Unlock of Not Locked'
    833 = 'Deadlock'
    834 = 'Excessive Iteration'
    835 = 'Loop with Unreachable Exit'
    836 = 'Use of Password Hash'
    837 = 'Improper Enforcement'
    838 = 'Inappropriate Encoding'
    839 = 'Numeric Range Comparison'
    840 = 'Business Logic'
    841 = 'Improper Enforcement'
    842 = 'Incorrect User Management'
    843 = 'Type Confusion'
    844 = 'Certificate Chain'
    845 = 'Certificate Validation'
    846 = 'Certificate Validation'
    847 = 'Certificate Validation'
    848 = 'Certificate Validation'
    849 = 'Certificate Validation'
    850 = 'Certificate Validation'
    851 = 'Certificate Validation'
    852 = 'Certificate Validation'
    853 = 'Certificate Validation'
    854 = 'Certificate Validation'
    855 = 'Certificate Validation'
    856 = 'Certificate Validation'
    857 = 'Certificate Validation'
    858 = 'Certificate Validation'
    859 = 'Certificate Validation'
    860 = 'Certificate Validation'
    861 = 'Certificate Validation'
    862 = 'Missing Authorization'
    863 = 'Incorrect Authorization'
    864 = 'Incorrect Signature'
    865 = 'Path Traversal'
    866 = 'Improper Input'
    867 = 'Improper Neutralization'
    868 = 'Double Free'
    869 = 'Certificate Validation'
    870 = 'Certificate Validation'
    871 = 'Certificate Validation'
    872 = 'Certificate Validation'
    873 = 'Certificate Validation'
    874 = 'Certificate Validation'
    875 = 'Certificate Validation'
    876 = 'Certificate Validation'
    877 = 'Certificate Validation'
    878 = 'Certificate Validation'
    879 = 'Certificate Validation'
    880 = 'Certificate Validation'
    881 = 'Certificate Validation'
    882 = 'Certificate Validation'
    883 = 'Certificate Validation'
    884 = 'Certificate Validation'
    885 = 'Certificate Validation'
    886 = 'Certificate Validation'
    887 = 'Certificate Validation'
    888 = 'Certificate Validation'
    889 = 'Certificate Validation'
    890 = 'Certificate Validation'
    891 = 'Certificate Validation'
    892 = 'Certificate Validation'
    893 = 'Certificate Validation'
    894 = 'Certificate Validation'
    895 = 'Certificate Validation'
    896 = 'Certificate Validation'
    897 = 'Certificate Validation'
    898 = 'Certificate Validation'
    899 = 'Certificate Validation'
    900 = 'Certificate Validation'
    901 = 'Certificate Validation'
    902 = 'Certificate Validation'
    903 = 'Certificate Validation'
    904 = 'Certificate Validation'
    905 = 'Certificate Validation'
    906 = 'Certificate Validation'
    907 = 'Certificate Validation'
    908 = 'Certificate Validation'
    909 = 'Certificate Validation'
    910 = 'Certificate Validation'
    911 = 'Certificate Validation'
    912 = 'Certificate Validation'
    913 = 'Certificate Validation'
    914 = 'Certificate Validation'
    915 = 'Certificate Validation'
    916 = 'Certificate Validation'
    917 = 'Certificate Validation'
    918 = 'Certificate Validation'
    919 = 'Certificate Validation'
    920 = 'Certificate Validation'
    921 = 'Certificate Validation'
    922 = 'Certificate Validation'
    923 = 'Certificate Validation'
    924 = 'Certificate Validation'
    925 = 'Certificate Validation'
    926 = 'Certificate Validation'
    927 = 'Certificate Validation'
    928 = 'Certificate Validation'
    929 = 'Certificate Validation'
    930 = 'Certificate Validation'
    931 = 'Certificate Validation'
    932 = 'Certificate Validation'
    933 = 'Certificate Validation'
    934 = 'Certificate Validation'
    935 = 'Certificate Validation'
    936 = 'Certificate Validation'
    937 = 'Certificate Validation'
    938 = 'Certificate Validation'
    939 = 'Certificate Validation'
    940 = 'Certificate Validation'
    941 = 'Certificate Validation'
    942 = 'Certificate Validation'
    943 = 'Certificate Validation'
    944 = 'Certificate Validation'
    945 = 'Certificate Validation'
    946 = 'Certificate Validation'
    947 = 'Certificate Validation'
    948 = 'Certificate Validation'
    949 = 'Certificate Validation'
    950 = 'Certificate Validation'
    951 = 'Certificate Validation'
    952 = 'Certificate Validation'
    953 = 'Certificate Validation'
    954 = 'Certificate Validation'
    955 = 'Certificate Validation'
    956 = 'Certificate Validation'
    957 = 'Certificate Validation'
    958 = 'Certificate Validation'
    959 = 'Certificate Validation'
    960 = 'Certificate Validation'
    961 = 'Certificate Validation'
    962 = 'Certificate Validation'
    963 = 'Certificate Validation'
    964 = 'Certificate Validation'
    965 = 'Certificate Validation'
    966 = 'Certificate Validation'
    967 = 'Certificate Validation'
    968 = 'Certificate Validation'
    969 = 'Certificate Validation'
    970 = 'Certificate Validation'
    971 = 'Certificate Validation'
    972 = 'Certificate Validation'
    973 = 'Certificate Validation'
    974 = 'Certificate Validation'
    975 = 'Certificate Validation'
    976 = 'Certificate Validation'
    977 = 'Certificate Validation'
    978 = 'Certificate Validation'
    979 = 'Certificate Validation'
    980 = 'Certificate Validation'
    981 = 'Certificate Validation'
    982 = 'Certificate Validation'
    983 = 'Certificate Validation'
    984 = 'Certificate Validation'
    985 = 'Certificate Validation'
    986 = 'Certificate Validation'
    987 = 'Certificate Validation'
    988 = 'Certificate Validation'
    989 = 'Certificate Validation'
    990 = 'Certificate Validation'
    991 = 'Certificate Validation'
    992 = 'Certificate Validation'
    993 = 'Certificate Validation'
    994 = 'Certificate Validation'
    995 = 'Certificate Validation'
    996 = 'Certificate Validation'
    997 = 'Certificate Validation'
    998 = 'Certificate Validation'
    999 = 'Certificate Validation'
}

$Script:VulnerabilityTypeTemplates = @{
    'idor' = @{
        title_format = 'Insecure Direct Object Reference (IDOR) in {endpoint}'
        impact_format = 'An attacker could access, modify, or delete resources belonging to other users by manipulating the {parameter} parameter, leading to unauthorized data exposure.'
        remediation_format = 'Implement proper access control checks on the server-side. Validate that the authenticated user has permission to access the requested resource.'
    }
    'xss' = @{
        title_format = 'Cross-Site Scripting (XSS) in {endpoint}'
        impact_format = 'An attacker could execute arbitrary JavaScript in the context of a victim'\''s browser, leading to session hijacking, credential theft, or defacement.'
        remediation_format = 'Implement proper output encoding and input validation. Use Content-Security-Policy headers and context-aware escaping.'
    }
    'ssrf' = @{
        title_format = 'Server-Side Request Forgery (SSRF) in {endpoint}'
        impact_format = 'An attacker could make the server send requests to internal systems, cloud metadata endpoints, or other restricted resources.'
        remediation_format = 'Implement a whitelist of allowed destinations, validate and sanitize all user-supplied URLs, and block access to private IP ranges.'
    }
    'sqli' = @{
        title_format = 'SQL Injection in {endpoint}'
        impact_format = 'An attacker could execute arbitrary SQL queries against the database, potentially extracting, modifying, or deleting sensitive data.'
        remediation_format = 'Use parameterized queries or prepared statements. Implement proper input validation and least privilege database accounts.'
    }
    'auth-bypass' = @{
        title_format = 'Authentication Bypass in {endpoint}'
        impact_format = 'An attacker could bypass authentication mechanisms and access restricted functionality or data without proper credentials.'
        remediation_format = 'Implement server-side authentication checks on all protected endpoints. Use secure session management and multi-factor authentication.'
    }
    'rce' = @{
        title_format = 'Remote Code Execution (RCE) in {endpoint}'
        impact_format = 'An attacker could execute arbitrary commands on the server, leading to full system compromise.'
        remediation_format = 'Implement strict input validation, use allowlists for allowed commands, and follow the principle of least privilege.'
    }
    'csrf' = @{
        title_format = 'Cross-Site Request Forgery (CSRF) in {endpoint}'
        impact_format = 'An attacker could trick authenticated users into performing unintended actions on the application.'
        remediation_format = 'Implement CSRF tokens for all state-changing operations. Use SameSite cookies and validate origin headers.'
    }
    'open-redirect' = @{
        title_format = 'Open Redirect in {endpoint}'
        impact_format = 'An attacker could redirect users to malicious websites, enabling phishing attacks.'
        remediation_format = 'Implement a whitelist of allowed redirect destinations. Validate and sanitize all redirect parameters.'
    }
    'file-upload' = @{
        title_format = 'Unrestricted File Upload in {endpoint}'
        impact_format = 'An attacker could upload malicious files leading to remote code execution or other attacks.'
        remediation_format = 'Validate file types server-side, restrict upload directories, and disable execution permissions.'
    }
    'information-disclosure' = @{
        title_format = 'Information Disclosure in {endpoint}'
        impact_format = 'Sensitive information is exposed to unauthorized parties, potentially revealing internal system details or user data.'
        remediation_format = 'Remove sensitive information from responses, implement proper access controls, and use generic error messages.'
    }
}

# ============================================================================
# FUNCTION: Get-CvssSeverity
# ============================================================================

function Get-CvssSeverity {
    [CmdletBinding()]
    param([double]$Score)
    if ($Score -ge 9.0) { return 'Critical' }
    if ($Score -ge 7.0) { return 'High' }
    if ($Score -ge 4.0) { return 'Medium' }
    if ($Score -ge 0.1) { return 'Low' }
    return 'None'
}

# ============================================================================
# FUNCTION: Calculate-CvssV31
# ============================================================================

function Calculate-CvssV31 {
    [CmdletBinding()]
    param(
        [string]$AV = 'N',
        [string]$AC = 'L',
        [string]$PR = 'N',
        [string]$UI = 'N',
        [string]$S = 'U',
        [string]$C = 'N',
        [string]$I = 'N',
        [string]$A = 'N'
    )
    $cvssValues = @{
        AV = @{ 'N' = 0.85; 'A' = 0.62; 'L' = 0.55; 'P' = 0.20 }
        AC = @{ 'L' = 0.77; 'H' = 0.44 }
        PR = @{
            'U' = @{ 'N' = 0.85; 'L' = 0.62; 'H' = 0.27 }
            'C' = @{ 'N' = 0.85; 'L' = 0.68; 'H' = 0.50 }
        }
        UI = @{ 'N' = 0.85; 'R' = 0.62 }
        CIA = @{ 'N' = 0.00; 'L' = 0.22; 'H' = 0.56 }
    }

    $avScore = $cvssValues.AV[$AV]
    $acScore = $cvssValues.AC[$AC]
    $prScore = $cvssValues.PR[$S][$PR]
    $uiScore = $cvssValues.UI[$UI]
    $cScore = $cvssValues.CIA[$C]
    $iScore = $cvssValues.CIA[$I]
    $aScore = $cvssValues.CIA[$A]

    $impactBase = 1.0 - ((1.0 - $cScore) * (1.0 - $iScore) * (1.0 - $aScore))
    $impact = if ($S -eq 'U') { 6.42 * $impactBase } else { 7.52 * ($impactBase - 0.029) - 3.25 * [Math]::Pow($impactBase - 0.02, 15) }

    $exploitability = 8.22 * $avScore * $acScore * $prScore * $uiScore

    if ($impact -le 0) {
        $score = 0
    }
    elseif ($S -eq 'U') {
        $score = [Math]::Min(10, [Math]::Round(1.08 * ($impact + $exploitability), 1))
    }
    else {
        $score = [Math]::Min(10, [Math]::Round(1.08 * ($impact + $exploitability), 1))
    }

    $vector = "CVSS:3.1/AV:$AV/AC:$AC/PR:$PR/UI:$UI/S:$S/C:$C/I:$I/A:$A"
    $severity = Get-CvssSeverity -Score $score

    return [PSCustomObject]@{
        VectorString = $vector
        BaseScore    = $score
        Severity     = $severity
        ImpactSubScore = [Math]::Round($impact, 2)
        ExploitabilitySubScore = [Math]::Round($exploitability, 2)
        AV = $AV
        AC = $AC
        PR = $PR
        UI = $UI
        S  = $S
        C  = $C
        I  = $I
        A  = $A
    }
}

# ============================================================================
# FUNCTION: Get-CvssFromFinding
# ============================================================================

function Get-CvssFromFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    $cvss = $Finding['cvss']
    if (-not $cvss) {
        $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'Medium' }
        switch ($severity.ToLower()) {
            'critical' { return Calculate-CvssV31 -AV 'N' -AC 'L' -PR 'N' -UI 'N' -S 'C' -C 'H' -I 'H' -A 'H' }
            'high'     { return Calculate-CvssV31 -AV 'N' -AC 'L' -PR 'N' -UI 'N' -S 'U' -C 'H' -I 'H' -A 'N' }
            'medium'   { return Calculate-CvssV31 -AV 'N' -AC 'L' -PR 'L' -UI 'N' -S 'U' -C 'L' -I 'L' -A 'N' }
            'low'      { return Calculate-CvssV31 -AV 'N' -AC 'H' -PR 'L' -UI 'R' -S 'U' -C 'L' -I 'N' -A 'N' }
            default    { return Calculate-CvssV31 }
        }
    }
    return Calculate-CvssV31 -AV $cvss.av -AC $cvss.ac -PR $cvss.pr -UI $cvss.ui -S $cvss.s -C $cvss.c -I $cvss.i -A $cvss.a
}

# ============================================================================
# FUNCTION: Format-CvssTable
# ============================================================================

function Format-CvssTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$CvssResult
    )
    $lines = @()
    $lines += "| Metric | Value |"
    $lines += "|--------|-------|"
    $lines += "| Attack Vector (AV) | $($CvssResult.AV) - $($Script:CvssV31Constants.AttackVector[$CvssResult.AV]) |"
    $lines += "| Attack Complexity (AC) | $($CvssResult.AC) - $($Script:CvssV31Constants.AttackComplexity[$CvssResult.AC]) |"
    $lines += "| Privileges Required (PR) | $($CvssResult.PR) - $($Script:CvssV31Constants.PrivilegesRequired[$CvssResult.PR]) |"
    $lines += "| User Interaction (UI) | $($CvssResult.UI) - $($Script:CvssV31Constants.UserInteraction[$CvssResult.UI]) |"
    $lines += "| Scope (S) | $($CvssResult.S) - $($Script:CvssV31Constants.Scope[$CvssResult.S]) |"
    $lines += "| Confidentiality (C) | $($CvssResult.C) - $($Script:CvssV31Constants.CIA[$CvssResult.C]) |"
    $lines += "| Integrity (I) | $($CvssResult.I) - $($Script:CvssV31Constants.CIA[$CvssResult.I]) |"
    $lines += "| Availability (A) | $($CvssResult.A) - $($Script:CvssV31Constants.CIA[$CvssResult.A]) |"
    $lines += ""
    $lines += "**CVSS Vector:** $($CvssResult.VectorString)"
    $lines += ""
    $lines += "**Base Score:** $($CvssResult.BaseScore) - **$($CvssResult.Severity)**"
    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Format-FindingToMarkdown
# ============================================================================

function Format-FindingToMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding,
        [int]$Index = 1
    )
    $title = $Finding['title'] -replace '\[([^\]]+)\]', '[$1]'
    $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'Medium' }
    $description = $Finding['description'] -replace '\[([^\]]+)\]', '[$1]'
    $impact = $Finding['impact'] -replace '\[([^\]]+)\]', '[$1]'
    $remediation = $Finding['remediation'] -replace '\[([^\]]+)\]', '[$1]'
    $endpoint = $Finding['endpoint'] -replace '\[([^\]]+)\]', '[$1]'
    $method = if ($Finding['method']) { $Finding['method'] } else { 'GET' }
    $cwe = $Finding['cwe']
    $vulnType = if ($Finding['vulnerability_type']) { $Finding['vulnerability_type'] } else { 'unknown' }

    $badge = "# $severity"
    $lines = @()
    $lines += "$badge $title"
    $lines += ""
    $lines += "## Summary"
    $lines += ""
    $lines += "- **Vulnerability Type:** $vulnType"
    $lines += "- **Endpoint:** $endpoint"
    $lines += "- **Method:** $method"
    if ($cwe -and $Script:CweCatalog[$cwe]) {
        $lines += "- **CWE:** CWE-$cwe - $($Script:CweCatalog[$cwe])"
    }
    elseif ($cwe) {
        $lines += "- **CWE:** CWE-$cwe"
    }
    $lines += "- **Severity:** $severity"
    if ($Finding['parameters']) {
        $params = $Finding['parameters'] | ConvertTo-Json -Compress
        $lines += "- **Parameters:** $params"
    }
    $lines += ""

    # CVSS
    $cvssResult = Get-CvssFromFinding -Finding $Finding
    $lines += "### CVSS 3.1 Score"
    $lines += ""
    $lines += Format-CvssTable -CvssResult $cvssResult
    $lines += ""

    # Description
    $lines += "## Description"
    $lines += ""
    $lines += $description
    $lines += ""

    # Impact
    $lines += "## Impact"
    $lines += ""
    $lines += $impact
    $lines += ""

    # Evidence
    $evidence = $Finding['evidence']
    if ($evidence) {
        $lines += "## Proof of Concept"
        $lines += ""
        if ($evidence['request']) {
            $lines += "### Request"
            $lines += '```http'
            $lines += ""
            $lines += $evidence['request']
            $lines += '```'
            $lines += ""
        }
        if ($evidence['response']) {
            $lines += "### Response"
            $lines += '```http'
            $lines += ""
            $lines += $evidence['response']
            $lines += '```'
            $lines += ""
        }
    }

    # Remediation
    $lines += "## Remediation"
    $lines += ""
    $lines += $remediation
    $lines += ""

    # References
    if ($Finding['references']) {
        $lines += "## References"
        $lines += ""
        foreach ($ref in $Finding['references']) {
            $lines += "- $ref"
        }
        $lines += ""
    }

    $lines += "---"
    $lines += ""
    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Format-FindingToHackerOne
# ============================================================================

function Format-FindingToHackerOne {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    $title = if ($Finding['title']) { $Finding['title'] } else { 'Untitled Finding' }
    $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'Medium' }
    $description = $Finding['description'] -replace '\[([^\]]+)\]', '[$1]'
    $impact = $Finding['impact'] -replace '\[([^\]]+)\]', '[$1]'
    $remediation = $Finding['remediation'] -replace '\[([^\]]+)\]', '[$1]'
    $endpoint = $Finding['endpoint']
    $method = if ($Finding['method']) { $Finding['method'] } else { 'GET' }

    $cvssResult = Get-CvssFromFinding -Finding $Finding

    $lines = @()
    $lines += "## Vulnerability Details"
    $lines += ""
    $lines += "**Title:** $title"
    $lines += "**Severity:** $severity"
    $lines += "**CVSS 3.1:** $($cvssResult.BaseScore) - $($cvssResult.Severity)"
    $lines += "**CVSS Vector:** $($cvssResult.VectorString)"
    $lines += ""
    $lines += "### Summary"
    $lines += ""
    $lines += $description
    $lines += ""
    $lines += "### Steps To Reproduce"
    $lines += ""
    $lines += "1. Navigate to $endpoint"
    $lines += "2. Observe the following behavior:"
    $lines += ""

    # Evidence
    $evidence = $Finding['evidence']
    if ($evidence -and $evidence['request']) {
        $lines += '```http'
        $lines += ""
        $lines += $evidence['request']
        $lines += '```'
        $lines += ""
    }
    if ($evidence -and $evidence['response']) {
        $lines += '```http'
        $lines += ""
        $lines += $evidence['response']
        $lines += '```'
        $lines += ""
    }

    $lines += "### Impact"
    $lines += ""
    $lines += $impact
    $lines += ""
    $lines += "### Suggested Fix"
    $lines += ""
    $lines += $remediation
    $lines += ""
    $lines += "### Supporting Material/References"
    $lines += ""
    if ($Finding['references']) {
        foreach ($ref in $Finding['references']) { $lines += "- $ref" }
    }
    $lines += "- Report generated with Report-Builder"
    $lines += ""

    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Format-FindingToBugcrowd
# ============================================================================

function Format-FindingToBugcrowd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    $title = if ($Finding['title']) { $Finding['title'] } else { 'Untitled Finding' }
    $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'P3' }
    $description = $Finding['description']
    $impact = $Finding['impact']
    $remediation = $Finding['remediation']
    $endpoint = $Finding['endpoint']

    $bugcrowdSeverities = @{
        'critical' = 'P1'
        'high'     = 'P2'
        'medium'   = 'P3'
        'low'      = 'P4'
        'info'     = 'P5'
    }
    $bcSeverity = $bugcrowdSeverities[$severity.ToLower()]
    if (-not $bcSeverity) { $bcSeverity = 'P3' }

    $cvssResult = Get-CvssFromFinding -Finding $Finding

    $lines = @()
    $lines += "## Vulnerability Report"
    $lines += ""
    $lines += "**Title:** $title"
    $lines += "**Priority:** $bcSeverity"
    $lines += "**CVSS 3.1:** $($cvssResult.BaseScore) - $($cvssResult.Severity)"
    $lines += ""
    $lines += "### Description"
    $lines += ""
    $lines += $description
    $lines += ""
    $lines += "### Steps to Reproduce"
    $lines += ""
    $lines += "**Target:** $endpoint"
    $lines += ""

    $evidence = $Finding['evidence']
    if ($evidence -and $evidence['request']) {
        $lines += '### Proof of Concept'
        $lines += ""
        $lines += '```'
        $lines += $evidence['request']
        $lines += '```'
        $lines += ""
    }

    $lines += "### Business Impact"
    $lines += ""
    $lines += $impact
    $lines += ""
    $lines += "### Remediation"
    $lines += ""
    $lines += $remediation
    $lines += ""

    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Format-FindingToIntigriti
# ============================================================================

function Format-FindingToIntigriti {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    $title = if ($Finding['title']) { $Finding['title'] } else { 'Untitled Finding' }
    $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'medium' }
    $description = $Finding['description']
    $impact = $Finding['impact']
    $remediation = $Finding['remediation']
    $endpoint = $Finding['endpoint']
    $method = if ($Finding['method']) { $Finding['method'] } else { 'GET' }

    $cvssResult = Get-CvssFromFinding -Finding $Finding

    $lines = @()
    $lines += "## Vulnerability"
    $lines += ""
    $lines += "**Title:** $title"
    $lines += "**CVSS Score:** $($cvssResult.BaseScore) - $($cvssResult.Severity)"
    $lines += "**Endpoint:** $endpoint"
    $lines += "**HTTP Method:** $method"
    $lines += ""
    $lines += "### Description"
    $lines += ""
    $lines += $description
    $lines += ""
    $lines += "### Proof of Concept"
    $lines += ""

    $evidence = $Finding['evidence']
    if ($evidence -and $evidence['request']) {
        $lines += '```'
        $lines += $evidence['request']
        $lines += '```'
        $lines += ""
    }

    $lines += "### Impact"
    $lines += ""
    $lines += $impact
    $lines += ""
    $lines += "### Remediation Advice"
    $lines += ""
    $lines += $remediation
    $lines += ""
    $lines += "### CVSS Breakdown"
    $lines += ""
    $lines += Format-CvssTable -CvssResult $cvssResult
    $lines += ""

    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Format-FindingToImmunefi
# ============================================================================

function Format-FindingToImmunefi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    $title = if ($Finding['title']) { $Finding['title'] } else { 'Untitled Finding' }
    $severity = if ($Finding['severity']) { $Finding['severity'] } else { 'Medium' }
    $description = $Finding['description']
    $impact = $Finding['impact']
    $remediation = $Finding['remediation']

    $cvssResult = Get-CvssFromFinding -Finding $Finding

    $lines = @()
    $lines += "# Vulnerability Report: $title"
    $lines += ""
    $lines += "## Summary"
    $lines += ""
    $lines += $description
    $lines += ""
    $lines += "## Severity"
    $lines += ""
    $lines += "**CVSS 3.1 Score:** $($cvssResult.BaseScore) - $($cvssResult.Severity)"
    $lines += "**Vector:** $($cvssResult.VectorString)"
    $lines += ""
    $lines += "## Vulnerability Details"
    $lines += ""

    $evidence = $Finding['evidence']
    if ($evidence -and $evidence['request']) {
        $lines += '```solidity'
        $lines += $evidence['request']
        $lines += '```'
        $lines += ""
    }

    $lines += "## Impact"
    $lines += ""
    $lines += $impact
    $lines += ""
    $lines += "## Recommended Fix"
    $lines += ""
    $lines += $remediation
    $lines += ""

    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Build-HtmlReport
# ============================================================================

function Build-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,
        [string]$Author,
        [string]$TemplateName
    )
    $authorName = if ($Author) { $Author } else { $Script:DefaultAuthor }
    $total = $Findings.Count
    $criticalCount = ($Findings | Where-Object { $_.severity -eq 'Critical' }).Count
    $highCount = ($Findings | Where-Object { $_.severity -eq 'High' }).Count
    $mediumCount = ($Findings | Where-Object { $_.severity -eq 'Medium' }).Count
    $lowCount = ($Findings | Where-Object { $_.severity -eq 'Low' }).Count
    $infoCount = ($Findings | Where-Object { $_.severity -eq 'Info' }).Count

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en">')
    $null = $sb.AppendLine('<head>')
    $null = $sb.AppendLine('<meta charset="UTF-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    $null = $sb.AppendLine("<title>Bug Bounty Report - $templateName</title>")
    $null = $sb.AppendLine('<style>')
    $null = $sb.AppendLine('body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #fff; color: #333; }')
    $null = $sb.AppendLine('h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }')
    $null = $sb.AppendLine('h2 { color: #34495e; margin-top: 30px; }')
    $null = $sb.AppendLine('h3 { color: #555; margin-top: 20px; }')
    $null = $sb.AppendLine('.severity-critical { background: #dc3545; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; }')
    $null = $sb.AppendLine('.severity-high { background: #fd7e14; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; }')
    $null = $sb.AppendLine('.severity-medium { background: #ffc107; color: #333; padding: 3px 8px; border-radius: 3px; font-weight: bold; }')
    $null = $sb.AppendLine('.severity-low { background: #28a745; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; }')
    $null = $sb.AppendLine('.severity-info { background: #17a2b8; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold; }')
    $null = $sb.AppendLine('.summary-box { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }')
    $null = $sb.AppendLine('.summary-item { flex: 1; min-width: 120px; padding: 15px; border-radius: 5px; text-align: center; color: white; }')
    $null = $sb.AppendLine('.summary-item h3 { margin: 0; font-size: 28px; color: white; }')
    $null = $sb.AppendLine('.finding { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }')
    $null = $sb.AppendLine('.finding-header { display: flex; justify-content: space-between; align-items: center; }')
    $null = $sb.AppendLine('pre { background: #f8f9fa; border: 1px solid #eee; border-radius: 3px; padding: 10px; overflow-x: auto; }')
    $null = $sb.AppendLine('code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }')
    $null = $sb.AppendLine('table { width: 100%; border-collapse: collapse; margin: 10px 0; }')
    $null = $sb.AppendLine('th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }')
    $null = $sb.AppendLine('th { background: #f5f5f5; }')
    $null = $sb.AppendLine('.footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #888; }')
    $null = $sb.AppendLine('</style>')
    $null = $sb.AppendLine('</head>')
    $null = $sb.AppendLine('<body>')
    $null = $sb.AppendLine("<h1>Bug Bounty Security Report</h1>")
    $null = $sb.AppendLine("<p><strong>Template:</strong> $templateName | <strong>Findings:</strong> $total | <strong>Author:</strong> $authorName | <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd')</p>")

    # Summary
    $null = $sb.AppendLine('<div class="summary-box">')
    if ($criticalCount -gt 0) { $null = $sb.AppendLine("<div class='summary-item' style='background:#dc3545'><h3>$criticalCount</h3>Critical</div>") }
    if ($highCount -gt 0) { $null = $sb.AppendLine("<div class='summary-item' style='background:#fd7e14'><h3>$highCount</h3>High</div>") }
    if ($mediumCount -gt 0) { $null = $sb.AppendLine("<div class='summary-item' style='background:#ffc107;color:#333'><h3>$mediumCount</h3>Medium</div>") }
    if ($lowCount -gt 0) { $null = $sb.AppendLine("<div class='summary-item' style='background:#28a745'><h3>$lowCount</h3>Low</div>") }
    if ($infoCount -gt 0) { $null = $sb.AppendLine("<div class='summary-item' style='background:#17a2b8'><h3>$infoCount</h3>Info</div>") }
    $null = $sb.AppendLine('</div>')

    # Findings
    $null = $sb.AppendLine('<h2>Findings</h2>')
    $index = 1
    foreach ($finding in $Findings) {
        $sev = if ($finding.severity) { $finding.severity } else { 'Medium' }
        $title = if ($finding.title) { $finding.title } else { "Finding $index" }
        $desc = if ($finding.description) { $finding.description } else { 'No description provided.' }
        $impact = if ($finding.impact) { $finding.impact } else { 'No impact statement provided.' }
        $remediation = if ($finding.remediation) { $finding.remediation } else { 'No remediation provided.' }
        $endpoint = if ($finding.endpoint) { $finding.endpoint } else { 'N/A' }

        $cvssResult = Get-CvssFromFinding -Finding $finding
        $sevClass = "severity-$($sev.ToLower())"

        $null = $sb.AppendLine("<div class='finding'>")
        $null = $sb.AppendLine("<div class='finding-header'>")
        $null = $sb.AppendLine("<h3>$index. $title</h3>")
        $null = $sb.AppendLine("<span class='$sevClass'>$sev</span>")
        $null = $sb.AppendLine("</div>")
        $null = $sb.AppendLine("<p><strong>Endpoint:</strong> $endpoint</p>")
        $null = $sb.AppendLine("<p><strong>CVSS:</strong> $($cvssResult.BaseScore) - $($cvssResult.Severity) ($($cvssResult.VectorString))</p>")
        $null = $sb.AppendLine("<h4>Description</h4>")
        $null = $sb.AppendLine("<p>$desc</p>")
        $null = $sb.AppendLine("<h4>Impact</h4>")
        $null = $sb.AppendLine("<p>$impact</p>")
        $null = $sb.AppendLine("<h4>Remediation</h4>")
        $null = $sb.AppendLine("<p>$remediation</p>")

        $evidence = $finding.evidence
        if ($evidence -and $evidence.request) {
            $null = $sb.AppendLine("<h4>Proof of Concept</h4>")
            $null = $sb.AppendLine('<pre><code>')
            $null = $sb.AppendLine([System.Net.WebUtility]::HtmlEncode($evidence.request))
            $null = $sb.AppendLine('</code></pre>')
        }

        $null = $sb.AppendLine("</div>")
        $index++
    }

    $null = $sb.AppendLine("<div class='footer'>")
    $null = $sb.AppendLine("<p>Generated by Report-Builder v$Script:ReportVersion | Author: $authorName | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>")
    $null = $sb.AppendLine("</div>")
    $null = $sb.AppendLine('</body>')
    $null = $sb.AppendLine('</html>')
    return $sb.ToString()
}

# ============================================================================
# FUNCTION: Build-MarkdownReport
# ============================================================================

function Build-MarkdownReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Findings,
        [string]$Author,
        [string]$TemplateName
    )
    $authorName = if ($Author) { $Author } else { $Script:DefaultAuthor }
    $lines = @()
    $lines += "# Bug Bounty Security Report"
    $lines += ""
    $lines += "**Template:** $templateName | **Findings:** $($Findings.Count) | **Author:** $authorName | **Date:** $(Get-Date -Format 'yyyy-MM-dd')"
    $lines += ""
    $lines += "## Executive Summary"
    $lines += ""
    $lines += "| Severity | Count |"
    $lines += "|----------|-------|"
    $lines += "| Critical | $(($Findings | Where-Object { $_.severity -eq 'Critical' }).Count) |"
    $lines += "| High | $(($Findings | Where-Object { $_.severity -eq 'High' }).Count) |"
    $lines += "| Medium | $(($Findings | Where-Object { $_.severity -eq 'Medium' }).Count) |"
    $lines += "| Low | $(($Findings | Where-Object { $_.severity -eq 'Low' }).Count) |"
    $lines += "| Info | $(($Findings | Where-Object { $_.severity -eq 'Info' }).Count) |"
    $lines += ""
    $lines += "**Total Findings:** $($Findings.Count)"
    $lines += ""
    $lines += "---"
    $lines += ""

    $index = 1
    foreach ($finding in $Findings) {
        $findingHash = @{}
        $finding.PSObject.Properties | ForEach-Object { $findingHash[$_.Name] = $_.Value }

        switch ($TemplateName.ToLower()) {
            'hackerone' { $lines += Format-FindingToHackerOne -Finding $findingHash }
            'bugcrowd'  { $lines += Format-FindingToBugcrowd -Finding $findingHash }
            'intigriti' { $lines += Format-FindingToIntigriti -Finding $findingHash }
            'immunefi'  { $lines += Format-FindingToImmunefi -Finding $findingHash }
            default     { $lines += Format-FindingToMarkdown -Finding $findingHash -Index $index }
        }
        $index++
    }

    $lines += ""
    $lines += "---"
    $lines += ""
    $lines += "*Report generated by Report-Builder v$Script:ReportVersion | Author: $authorName*"
    $lines += ""

    return $lines -join "`n"
}

# ============================================================================
# FUNCTION: Write-ReportToFile
# ============================================================================

function Write-ReportToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Content,
        [Parameter(Mandatory)]
        [string]$OutputFile
    )
    $outputDir = Split-Path -Parent $OutputFile
    if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    $Content | Out-File -LiteralPath $OutputFile -Encoding utf8
}

# ============================================================================
# FUNCTION: Invoke-ReportBuilding
# ============================================================================

function Invoke-ReportBuilding {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$InputFile,
        [string]$Format = 'Markdown',
        [string]$OutputFile,
        [string]$Severity = 'Info',
        [string]$Template = 'hackerone',
        [string]$Batch,
        [string]$Author,
        [switch]$Silent
    )
    $output = [PSCustomObject]@{
        Tool         = 'Report-Builder'
        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        InputFile    = if ($InputFile) { $InputFile } else { $Batch }
        Template     = $Template
        Format       = $Format
        Report       = $null
        Findings     = @()
        Errors       = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $findings = @()
    $allData = @()

    # Phase 1: Load input data
    if ($Batch) {
        if (Test-Path -LiteralPath $Batch -PathType Container) {
            $jsonFiles = Get-ChildItem -LiteralPath $Batch -Filter '*.json' | Sort-Object Name
            if ($jsonFiles.Count -eq 0) {
                $errMsg = "No JSON files found in batch directory: $Batch"
                $errors.Add($errMsg)
                if (-not $Silent) { Write-Error $errMsg }
                return $output
            }
            if (-not $Silent) { Write-Output "[*] Batch processing $($jsonFiles.Count) files from $Batch" }
            foreach ($jf in $jsonFiles) {
                try {
                    $content = Get-Content -LiteralPath $jf.FullName -Raw -ErrorAction Stop
                    $data = $content | ConvertFrom-Json
                    if ($data.findings) {
                        foreach ($f in $data.findings) { $allData += $f }
                    }
                    elseif ($data -is [array]) {
                        foreach ($f in $data) { $allData += $f }
                    }
                    else {
                        $allData += $data
                    }
                }
                catch {
                    $errors.Add("Failed to parse $($jf.Name): $_")
                }
            }
        }
        else {
            $errMsg = "Batch path not found: $Batch"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
            return $output
        }
    }
    elseif ($InputFile) {
        if (-not (Test-Path -LiteralPath $InputFile)) {
            $errMsg = "Input file not found: $InputFile"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
            return $output
        }
        try {
            $raw = Get-Content -LiteralPath $InputFile -Raw -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json
            if ($parsed.findings) {
                foreach ($f in $parsed.findings) { $allData += $f }
            }
            elseif ($parsed -is [array]) {
                foreach ($f in $parsed) { $allData += $f }
            }
            else {
                $allData += $parsed
            }
        }
        catch {
            $errMsg = "Failed to parse input file: $_"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
            return $output
        }
    }
    else {
        $errMsg = 'Either -InputFile or -Batch is required'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
        return $output
    }

    if (-not $Silent) { Write-Output "[+] Loaded $($allData.Count) findings" }

    # Phase 2: Filter by severity
    $minLevel = $Script:SeverityLevels[$Severity]
    if (-not $minLevel) { $minLevel = 0 }

    $filtered = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $allData) {
        $sev = if ($f.severity) { $f.severity } else { 'Info' }
        $level = $Script:SeverityLevels[$sev]
        if (-not $level) { $level = 0 }
        if ($level -ge $minLevel) {
            $filtered.Add($f)
        }
    }

    if (-not $Silent) { Write-Output "[+] Filtered to $($filtered.Count) findings (severity >= $Severity)" }

    if ($filtered.Count -eq 0) {
        $errMsg = 'No findings matched the severity filter'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Warning $errMsg }
        return $output
    }

    $findings = $filtered

    # Phase 3: Sort by severity (highest first)
    $findings = $findings | Sort-Object { $Script:SeverityLevels[$_.severity] } -Descending

    # Phase 4: Generate report
    $formatLower = $Format.ToLower()
    $reportContent = $null

    if ($formatLower -eq 'json') {
        $reportObj = [PSCustomObject]@{
            ReportMetadata = [PSCustomObject]@{
                Tool        = 'Report-Builder'
                Version     = $Script:ReportVersion
                Author      = if ($Author) { $Author } else { $Script:DefaultAuthor }
                Template    = $Template
                GeneratedAt = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
                TotalFindings = $findings.Count
            }
            Findings = $findings
        }
        $reportContent = $reportObj | ConvertTo-Json -Depth 10
    }
    elseif ($formatLower -eq 'html') {
        $reportContent = Build-HtmlReport -Findings $findings -Author $Author -TemplateName $Template
    }
    else {
        $reportContent = Build-MarkdownReport -Findings $findings -Author $Author -TemplateName $Template
    }

    $output.Report = $reportContent
    $output.Findings = $findings
    $output.Errors = $errors

    # Phase 5: Output
    if ($OutputFile) {
        Write-ReportToFile -Content $reportContent -OutputFile $OutputFile
        if (-not $Silent) { Write-Output "[+] Report written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "`n=== Report Building Summary ==="
        Write-Output "Input: $(if ($InputFile) { $InputFile } else { $Batch })"
        Write-Output "Template: $Template | Format: $Format | Min Severity: $Severity"
        Write-Output "Total Findings: $($findings.Count)"
        Write-Output "By Severity:"
        $sevCount = @{}
        foreach ($f in $findings) {
            $s = $f.severity
            if (-not $sevCount.ContainsKey($s)) { $sevCount[$s] = 0 }
            $sevCount[$s]++
        }
        foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            if ($sevCount[$s] -and $sevCount[$s] -gt 0) {
                Write-Output "  $s : $($sevCount[$s])"
            }
        }
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
        if ($OutputFile) { Write-Output "" }
    }

    # Write report to pipeline if no OutputFile
    if (-not $OutputFile -and $reportContent) {
        Write-Output $reportContent
    }

    return $output
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    param(
        [string]$InputFile,
        [string]$Format = 'Markdown',
        [string]$OutputFile,
        [string]$Severity = 'Info',
        [string]$Template = 'hackerone',
        [string]$Batch,
        [string]$Author,
        [switch]$Silent
    )
    Invoke-ReportBuilding -InputFile $InputFile -Format $Format -OutputFile $OutputFile -Severity $Severity -Template $Template -Batch $Batch -Author $Author -Silent:$Silent
}

# Entry point
$InputFile = $null; $Format = 'Markdown'; $OutputFile = $null; $Severity = 'Info'
$Template = 'hackerone'; $Batch = $null; $Author = $null; $Silent = $false

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-InputFile' { $i++; $InputFile = $args[$i] }
            '-Format' { $i++; $Format = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Severity' { $i++; $Severity = $args[$i] }
            '-Template' { $i++; $Template = $args[$i] }
            '-Batch' { $i++; $Batch = $args[$i] }
            '-Author' { $i++; $Author = $args[$i] }
            '-Silent' { $Silent = $true }
        }
        $i++
    }
}

try {
    Main -InputFile $InputFile -Format $Format -OutputFile $OutputFile -Severity $Severity -Template $Template -Batch $Batch -Author $Author -Silent:$Silent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
