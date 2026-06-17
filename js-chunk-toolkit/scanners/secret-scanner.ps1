param(
  [Parameter(Mandatory = $true)]
  [string]$InputPath,
  [string]$OutputDir = "",
  [switch]$Recurse = $true,
  [switch]$JSONOutput = $true,
  [switch]$CSVOutput = $true
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Section {
  param([string]$Title)
  Write-Host ""
  Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Write-Finding {
  param([string]$Type, [string]$File, [string]$Value, [string]$Severity)
  $color = switch ($Severity) {
    "CRITICAL" { "Red" }
    "HIGH" { "DarkRed" }
    "MEDIUM" { "DarkYellow" }
    "LOW" { "Gray" }
    default { "White" }
  }
  Write-Host "  [$Severity][$Type] $Value" -ForegroundColor $color
  Write-Host "          in $File" -ForegroundColor Gray
}

function Get-ContextLine {
  param([string]$Content, [int]$Position, [int]$Radius = 40)
  $start = [Math]::Max(0, $Position - $Radius)
  $end = [Math]::Min($Content.Length, $Position + $Radius)
  $ctx = $Content.Substring($start, $end - $start).Replace("`n", " ")
  return $ctx
}

function Get-LineNumber {
  param([string]$Content, [int]$Position)
  return ($Content.Substring(0, $Position).Split("`n").Count)
}

function Test-FalsePositive {
  param([string]$Value, [string]$PatternName)
  $fp = switch ($PatternName) {
    "Generic_32_Plus_Key" { $Value -match '^[a-zA-Z0-9+/=]+$' -and $Value -notmatch 'http|secret|token|key' }
    "Internal_IP_URL" { $Value -match '^127\.|^0\.|^255\.' }
    "JWT_Token" { ($Value.Split('.')[0] -eq 'eyJhbGciOiJub25lIn0' -or $Value -match 'eyJleGFtcGxlI') }
    "Password_Field" { $Value -match '^placeholder|^your_password|^secret$|^password123' }
    "Localhost_URL" { $Value -match 'https?://localhost:0' }
    default { $false }
  }
  return $fp -eq $true
}

function Get-FileSeverityScore {
  param([array]$FileFindings)
  $score = 0
  foreach ($f in $FileFindings) {
    $score += switch ($f.Severity) { "CRITICAL" { 10 } "HIGH" { 5 } "MEDIUM" { 2 } "LOW" { 1 } default { 0 } }
  }
  return $score
}

function Get-PatternHitRate {
  param([array]$AllResults, [array]$AllPatterns)
  $totalFiles = ($AllResults | Select-Object -Property File -Unique).Count
  $stats = @()
  foreach ($p in $AllPatterns) {
    $count = @($AllResults | Where-Object { $_.Type -eq $p.Name }).Count
    if ($count -gt 0) {
      $stats += [PSCustomObject]@{ Pattern = $p.Name; Hits = $count; Files = $totalFiles }
    }
  }
  return $stats | Sort-Object -Property Hits -Descending
}

function Get-CorrelatedFindings {
  param([array]$AllResults)
  $groups = $AllResults | Group-Object -Property File
  $correlated = @()
  foreach ($g in $groups) {
    $types = $g.Group | Select-Object -ExpandProperty Type -Unique
    $criticalCount = @($g.Group | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    if ($types.Count -ge 3 -or $criticalCount -ge 2) {
      $correlated += [PSCustomObject]@{
        File = $g.Name
        FindingTypes = $types.Count
        CriticalCount = $criticalCount
        TotalFindings = $g.Count
      }
    }
  }
  return $correlated
}

function Get-SeverityDistribution {
  param([array]$AllResults)
  $sevs = @{}
  foreach ($r in $AllResults) {
    $sevs[$r.Severity] = if ($sevs.ContainsKey($r.Severity)) { $sevs[$r.Severity] + 1 } else { 1 }
  }
  return $sevs
}

function Get-FileTypeBreakdown {
  param([array]$AllResults)
  $files = @{}
  foreach ($r in $AllResults) {
    if (-not $files.ContainsKey($r.File)) { $files[$r.File] = @() }
    $files[$r.File] += $r
  }
  return $files
}

$output = @()
$results = @()
$patterns = @(
  # Cloud credentials
  @{ Name = "AWS_Access_Key_ID"; Pattern = 'AKIA[A-Z0-9]{16}'; Severity = "CRITICAL" }
  @{ Name = "AWS_Secret_Access_Key"; Pattern = '["\x27]secretAccessKey["\x27]\s*[:=]\s*["\x27]([A-Za-z0-9\/+]{40})["\x27]'; Severity = "CRITICAL" }
  @{ Name = "AWS_Session_Token"; Pattern = '["\x27]sessionToken["\x27]\s*[:=]\s*["\x27]([A-Za-z0-9\/+]{40,})["\x27]'; Severity = "HIGH" }
  @{ Name = "GCP_API_Key"; Pattern = 'AIza[0-9A-Za-z\-_]{35}'; Severity = "CRITICAL" }
  @{ Name = "GCP_Service_Account"; Pattern = '"type":\s*"service_account"'; Severity = "CRITICAL" }
  @{ Name = "Firebase_URL"; Pattern = '[a-z0-9-]+\.firebaseio\.com'; Severity = "MEDIUM" }
  @{ Name = "Firebase_Config"; Pattern = '"apiKey":\s*"AIza[0-9A-Za-z\-_]{35}"'; Severity = "HIGH" }

  # Payment
  @{ Name = "Stripe_Live_Secret_Key"; Pattern = 'sk_live_[A-Za-z0-9]{24,}'; Severity = "CRITICAL" }
  @{ Name = "Stripe_Live_Publishable"; Pattern = 'pk_live_[A-Za-z0-9]{24,}'; Severity = "HIGH" }
  @{ Name = "Stripe_Test_Secret"; Pattern = 'sk_test_[A-Za-z0-9]{24,}'; Severity = "MEDIUM" }
  @{ Name = "Stripe_Webhook_Secret"; Pattern = 'whsec_[A-Za-z0-9]{32,}'; Severity = "HIGH" }

  # Tokens
  @{ Name = "GitHub_PAT"; Pattern = 'gh[psoubr]_[A-Za-z0-9_]{36,}'; Severity = "CRITICAL" }
  @{ Name = "GitHub_OAuth_Secret"; Pattern = '["\x27]client_secret["\x27]\s*[:=]\s*["\x27]([a-f0-9]{40})["\x27]'; Severity = "CRITICAL" }
  @{ Name = "Slack_Bot_Token"; Pattern = 'xoxb-[A-Za-z0-9]{10,}'; Severity = "HIGH" }
  @{ Name = "Slack_User_Token"; Pattern = 'xoxp-[A-Za-z0-9]{10,}'; Severity = "HIGH" }
  @{ Name = "Slack_Webhook"; Pattern = 'xoxr-[A-Za-z0-9]{10,}'; Severity = "HIGH" }
  @{ Name = "Slack_App_Token"; Pattern = 'xapp-[A-Za-z0-9]{10,}'; Severity = "HIGH" }
  @{ Name = "JWT_Token"; Pattern = 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'; Severity = "MEDIUM" }

  # AI / SaaS
  @{ Name = "OpenAI_API_Key"; Pattern = 'sk-[A-Za-z0-9]{20,}'; Severity = "CRITICAL" }
  @{ Name = "Anthropic_API_Key"; Pattern = 'sk-ant-[A-Za-z0-9]{20,}'; Severity = "CRITICAL" }
  @{ Name = "SendGrid_API_Key"; Pattern = 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'; Severity = "HIGH" }
  @{ Name = "Twilio_SID"; Pattern = 'AC[A-Z0-9a-z]{32}'; Severity = "HIGH" }
  @{ Name = "Twilio_Auth_Token"; Pattern = '["\x27]authToken["\x27]\s*[:=]\s*["\x27]([a-f0-9]{32})["\x27]'; Severity = "HIGH" }
  @{ Name = "Mailchimp_API"; Pattern = '[a-f0-9]{32}-us[0-9]{1,2}'; Severity = "MEDIUM" }
  @{ Name = "Mapbox_Token"; Pattern = 'pk\.[A-Za-z0-9]{60,}'; Severity = "MEDIUM" }

  # OAuth
  @{ Name = "Google_OAuth_Client"; Pattern = '[0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com'; Severity = "HIGH" }
  @{ Name = "Auth0_Domain"; Pattern = '[a-zA-Z0-9-]+\.auth0\.com'; Severity = "MEDIUM" }
  @{ Name = "Auth0_ClientID"; Pattern = '["\x27]clientID["\x27]\s*:\s*["\x27]([a-zA-Z0-9_-]{32})["\x27]'; Severity = "HIGH" }

  # Internal
  @{ Name = "Internal_IP_URL"; Pattern = '["\x27](https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::[0-9]+)?[^"\x27]*)["\x27]'; Severity = "HIGH" }
  @{ Name = "Localhost_URL"; Pattern = '["\x27](https?://localhost(?::[0-9]+)?[^"\x27]*)["\x27]'; Severity = "MEDIUM" }
  @{ Name = "Internal_Service_URL"; Pattern = '["\x27](https?://[a-zA-Z0-9-]+(?::[0-9]+)?/(?:internal|service|rpc|thrift|grpc|backend)/[^"\x27]*)["\x27]'; Severity = "HIGH" }
  @{ Name = "Dev_Staging_URL"; Pattern = '["\x27](https?://[^"\x27]*(?:dev|staging|qa|test|uat|sandbox|preprod|integration)[^"\x27]*)["\x27]'; Severity = "MEDIUM" }

  # Routes
  @{ Name = "Admin_Route"; Pattern = '["\x27](/admin(?:istrator)?|/manage(?:ment)?|/dashboard|/console|/panel|/backoffice|/staff|/internal|/ops|/operations|/sysadmin|/debug)[^"\x27]*["\x27]'; Severity = "HIGH" }
  @{ Name = "API_Endpoint"; Pattern = '["\x27](https?://[^"\x27]*/(?:api|v[0-9]+|rest|graphql|internal|backend|admin|private)[a-zA-Z0-9_\-/{}:]*)["\x27]'; Severity = "HIGH" }
  @{ Name = "GraphQL_Endpoint"; Pattern = '["\x27](https?://[^"\x27]*graphql[^"\x27]*)["\x27]'; Severity = "HIGH" }

  # Config
  @{ Name = "Database_Connection_String"; Pattern = '(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^"\x27\s,;]+'; Severity = "CRITICAL" }
  @{ Name = "Sentry_DSN"; Pattern = 'https://[a-f0-9]{32}@[a-f0-9]{16}\.ingest\.sentry\.io/\d+'; Severity = "LOW" }
  @{ Name = "Datadog_App_ID"; Pattern = 'applicationId:\s*["\x27]([a-f0-9-]{36})["\x27]'; Severity = "LOW" }
  @{ Name = "Algolia_API_Key"; Pattern = '["\x27]apiKey["\x27]\s*:\s*["\x27]([a-z0-9]{32})["\x27]'; Severity = "MEDIUM" }

  # Credentials
  @{ Name = "Password_Field"; Pattern = '["\x27](?:password|pass|pwd)["\x27]\s*[:=]\s*["\x27]([^"\x27]{3,})["\x27]'; Severity = "HIGH" }
  @{ Name = "Test_Email"; Pattern = '["\x27]([a-z0-9._%+-]+@(?:test|example|demo|sample|dev|staging|qa)\.(?:com|org|net|local|test))["\x27]'; Severity = "MEDIUM" }

  # Monitoring / Analytics
  @{ Name = "Google_Analytics_ID"; Pattern = 'G-[A-Z0-9]{10,}'; Severity = "LOW" }
  @{ Name = "GA_UA_ID"; Pattern = 'UA-\d{6,}-\d{1,}'; Severity = "LOW" }
  @{ Name = "GTM_ID"; Pattern = 'GTM-[A-Z0-9]{6,}'; Severity = "LOW" }

  # Generic high-entropy
  @{ Name = "Generic_32_Plus_Key"; Pattern = '["\x27]([A-Za-z0-9_\-]{40,64})["\x27]'; Severity = "LOW" }
)

if (-not (Test-Path $InputPath)) {
  Write-Host "[ERROR] Input path not found: $InputPath" -ForegroundColor Red
  exit 1
}

$InputPath = Resolve-Path $InputPath

if (-not $OutputDir) {
  $OutputDir = Join-Path (Split-Path $InputPath -Parent) "scanner_output"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$files = if (Test-Path -Path $InputPath -PathType Container) {
  $params = @{ Path = $InputPath; Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.map") }
  if ($Recurse) { $params.Recurse = $true }
  Get-ChildItem @params | Where-Object { !$_.PSIsContainer }
} else {
  @(Get-Item $InputPath)
}

if ($files.Count -eq 0) {
  Write-Host "[ERROR] No JS files found" -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  JS Secret & Endpoint Scanner" -ForegroundColor Cyan
Write-Host "  Scanning $($files.Count) files across $($patterns.Count) patterns"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$fileIndex = 0
$totalFindings = 0

foreach ($file in $files) {
  $fileIndex++
  $relPath = $file.FullName.Replace($InputPath, "").TrimStart("\")
  if (-not $relPath) { $relPath = $file.Name }

  try {
    $content = Get-Content $file.FullName -Raw -ErrorAction Stop
  } catch {
    Write-Host "  [SKIP] Cannot read $($file.Name)" -ForegroundColor DarkYellow
    continue
  }

  $fileFindings = 0
  foreach ($p in $patterns) {
    try {
      $allMatches = [regex]::Matches($content, $p.Pattern)
      if ($allMatches.Count -gt 0) {
        $seenValues = @{}
        foreach ($m in $allMatches) {
          $value = if ($m.Groups.Count -gt 1 -and $m.Groups[1].Success) {
            $m.Groups[1].Value.Substring(0, [Math]::Min($m.Groups[1].Value.Length, 120))
          } else {
            $m.Value.Substring(0, [Math]::Min($m.Value.Length, 120))
          }

          if ($seenValues.ContainsKey($value)) { continue }
          $seenValues[$value] = $true

          if (Test-FalsePositive -Value $value -PatternName $p.Name) { continue }

          $lineNum = Get-LineNumber -Content $content -Position $m.Index
          $context = Get-ContextLine -Content $content -Position $m.Index

          $result = [PSCustomObject]@{
            File = $relPath
            Type = $p.Name
            Value = $value
            Severity = $p.Severity
            Line = $lineNum
            Context = $context
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
          }
          $results += $result

          if ($fileFindings -eq 0) {
            Write-Host "[$fileIndex/$($files.Count)] $relPath" -ForegroundColor White
          }
          $fileFindings++
          $totalFindings++
        }
      }
    } catch {
      # Regex error, skip this pattern
    }
  }
}

Write-Section "Results Summary"
Write-Host "  Total files scanned: $($files.Count)" -ForegroundColor White
Write-Host "  Total findings: $totalFindings" -ForegroundColor White

$severityDist = Get-SeverityDistribution $results
foreach ($sev in @("CRITICAL","HIGH","MEDIUM","LOW","INFO")) {
  if ($severityDist.ContainsKey($sev)) {
    $color = switch ($sev) { "CRITICAL" { "Red" } "HIGH" { "DarkRed" } "MEDIUM" { "DarkYellow" } default { "Gray" } }
    Write-Host "  $sev`: $($severityDist[$sev])" -ForegroundColor $color
  }
}

$fileBreakdown = Get-FileTypeBreakdown $results
$fileRisk = $fileBreakdown.Keys | ForEach-Object {
  $score = Get-FileSeverityScore $fileBreakdown[$_]
  [PSCustomObject]@{ File = $_; Score = $score; Count = $fileBreakdown[$_].Count }
} | Sort-Object -Property Score -Descending

Write-Section "File Risk Rankings"
$fileRisk | Select-Object -First 10 | ForEach-Object {
  $color = if ($_.Score -ge 20) { "Red" } elseif ($_.Score -ge 10) { "DarkRed" } else { "Gray" }
  Write-Host "  [$($_.Score) pts] $($_.File) ($($_.Count) findings)" -ForegroundColor $color
}

$correlated = Get-CorrelatedFindings $results
if ($correlated.Count -gt 0) {
  Write-Section "Correlated Findings (multi-pattern hits)"
  $correlated | ForEach-Object {
    Write-Host "  $($_.File): $($_.FindingTypes) types, $($_.CriticalCount) critical, $($_.TotalFindings) total" -ForegroundColor DarkYellow
  }
}

$topPatterns = Get-PatternHitRate $results $patterns
if ($topPatterns.Count -gt 0) {
  Write-Section "Most Common Pattern Hits"
  $topPatterns | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.Pattern): $($_.Hits) hits" -ForegroundColor Gray
  }
}

Write-Section "Top Findings by Severity"
$sorted = @()
$sorted += $results | Where-Object { $_.Severity -eq "CRITICAL" }
$sorted += $results | Where-Object { $_.Severity -eq "HIGH" }
$sorted += $results | Where-Object { $_.Severity -eq "MEDIUM" }
$sorted += $results | Where-Object { $_.Severity -eq "LOW" }
$sorted | ForEach-Object {
  Write-Finding -Type $_.Type -File $_.File -Value $_.Value -Severity $_.Severity
}

$remaining = $results.Count - ($sorted.Count)
if ($remaining -gt 0) {
  Write-Host "  ... and $remaining more findings (see output files)" -ForegroundColor Gray
}

if ($JSONOutput) {
  $jsonPath = Join-Path $OutputDir "secrets_report.json"
  $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding utf8
  Write-Host "`n  JSON report: $jsonPath" -ForegroundColor Green
}

if ($CSVOutput) {
  $csvPath = Join-Path $OutputDir "secrets_report.csv"
  $results | Export-Csv -Path $csvPath -NoTypeInformation
  Write-Host "  CSV report:  $csvPath" -ForegroundColor Green
}

$criticalPath = Join-Path $OutputDir "critical_findings.txt"
$results | Where-Object { $_.Severity -eq "CRITICAL" } | ForEach-Object {
  "[$($_.Type)] $($_.Value) in $($_.File)"
} | Out-File -FilePath $criticalPath -Encoding utf8
Write-Host "  Critical only: $criticalPath" -ForegroundColor Green

Write-Section "Scan Complete"
