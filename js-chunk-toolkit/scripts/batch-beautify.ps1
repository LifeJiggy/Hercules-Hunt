param(
  [Parameter(Mandatory = $true)]
  [string]$InputPath,
  [string]$OutputDir = "",
  [switch]$Recurse = $false,
  [switch]$Backup = $false,
  [switch]$KeepOriginals
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Color {
  param([string]$Text, [string]$Color = "White")
  Write-Host $Text -ForegroundColor $Color
}

function Get-FrameworkType {
  param([string]$Content)
  if ($Content -match "webpackJsonp|__webpack_require__") { return "Webpack" }
  if ($Content -match "next\.[0-9]") { return "Next.js" }
  if ($Content -match "createRouter|VueRouter|createApp") { return "Vue.js" }
  if ($Content -match "ngZone|platformBrowserDynamic|Component") { return "Angular" }
  if ($Content -match "createRoot|ReactDOM.render|createElement") { return "React" }
  if ($Content -match "System.register|define\(") { return "SystemJS / AMD" }
  return "Unknown"
}

function Get-MinificationLevel {
  param([string]$Content)
  $lines = $Content -split "`n"
  $avgLen = [math]::Round(($lines | ForEach-Object { $_.Length } | Measure-Object -Average).Average, 1)
  $longLines = @($lines | Where-Object { $_.Length -gt 200 }).Count
  $totalLines = $lines.Count
  $longRatio = if ($totalLines -gt 0) { [math]::Round($longLines / $totalLines * 100) } else { 0 }
  $hasNewlines = $Content -match "`n"
  $funcInline = @($Content | Select-String -Pattern "function\s*\w*\s*\([^)]*\)\s*\{[^\{\}]{1,100}\}" -AllMatches).Matches.Count
  if (-not $hasNewlines -and $Content.Length -gt 10000) { return @{Level="Extreme (single-line)"; Score=10; AvgLen=$avgLen; LongRatio=$longRatio } }
  if ($longRatio -gt 60 -and $avgLen -gt 120) { return @{Level="Heavy"; Score=8; AvgLen=$avgLen; LongRatio=$longRatio } }
  if ($longRatio -gt 30 -or $avgLen -gt 80) { return @{Level="Moderate"; Score=5; AvgLen=$avgLen; LongRatio=$longRatio } }
  if ($longRatio -gt 10) { return @{Level="Light"; Score=3; AvgLen=$avgLen; LongRatio=$longRatio } }
  return @{Level="None (readable)"; Score=1; AvgLen=$avgLen; LongRatio=$longRatio }
}

function Get-SourceMapUrl {
  param([string]$Content)
  $match = [regex]::Match($Content, 'sourceMappingURL=([^\s"'']+)')
  if ($match.Success) { return $match.Groups[1].Value }
  return $null
}

function Get-ModuleWrapperType {
  param([string]$Content)
  if ($Content -match 'define\(["'']\w+["'']\s*,\s*\[') { return 'AMD' }
  if ($Content -match 'System\.register\(["'']') { return 'SystemJS' }
  if ($Content -match 'module\.exports\s*=|exports\.\w+\s*=') { return 'CommonJS' }
  if ($Content -match 'export\s+(default|const|function|class|let|var)\s') { return 'ES Module' }
  if ($Content -match '^!?function\([\w,]*\)\s*\{' -and $Content -match '\}\s*\([\w,]+\)\s*[;]?\s*$') { return 'IIFE' }
  if ($Content -match '^!?function\([\w,]*\)\s*\{' -and $Content -match '\([\w,]+\)\s*[;]?\s*$') { return 'IIFE' }
  if ($Content -match 'return\s+\w+\.\w+\s+in\s+') { return 'UMD' }
  return 'Unknown'
}

function Test-JsSyntax {
  param([string]$FilePath)
  try {
    $result = node --check $FilePath 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) { return $true }
    return $result
  } catch { return "Error: $_" }
}

function Get-FormatStats {
  param([string]$Content)
  $lines = $Content -split "`n"
  $totalLines = $lines.Count
  $emptyLines = @($lines | Where-Object { $_.Trim() -eq "" }).Count
  $maxLineLen = ($lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
  return @{
    TotalChars = $Content.Length
    TotalLines = $totalLines
    EmptyLines = $emptyLines
    MaxLineLen = $maxLineLen
  }
}

function Measure-LineDistribution {
  param([string]$Content)
  $lines = $Content -split "`n"
  $buckets = @{}
  foreach ($l in $lines) {
    $len = $l.Length
    $bucket = if ($len -le 20) { "1-20" } elseif ($len -le 50) { "21-50" } elseif ($len -le 100) { "51-100" } elseif ($len -le 200) { "101-200" } else { "200+" }
    $buckets[$bucket] = if ($buckets.ContainsKey($bucket)) { $buckets[$bucket] + 1 } else { 1 }
  }
  return $buckets
}

function Get-CompressionRatio {
  param([string]$Original, [string]$Beautified)
  if ($Original.Length -eq 0) { return 0 }
  return [math]::Round(($Beautified.Length - $Original.Length) / $Original.Length * 100, 1)
}

function Get-BundleHash {
  param([string]$Content)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $hash = $sha.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-", "").Substring(0, 16).ToLower()
  } catch { return "N/A" }
}

function Get-DiffSummary {
  param([string]$Original, [string]$Beautified)
  $origStats = Get-FormatStats $Original
  $beauStats = Get-FormatStats $Beautified
  return @{
    CharDiff = $beauStats.TotalChars - $origStats.TotalChars
    LineDiff = $beauStats.TotalLines - $origStats.TotalLines
    MaxLineBefore = $origStats.MaxLineLen
    MaxLineAfter = $beauStats.MaxLineLen
    PctChange = if ($origStats.TotalChars -gt 0) { [math]::Round(($beauStats.TotalChars - $origStats.TotalChars) / $origStats.TotalChars * 100, 2) } else { 0 }
  }
}

Write-Color "" "Cyan"
Write-Color "========================================" "Cyan"
Write-Color "  JS Chunk Batch Beautifier" "Cyan"
Write-Color "========================================" "Cyan"
Write-Color "" "Cyan"

if (-not (Test-Path $InputPath)) {
  Write-Color "[ERROR] Input path not found: $InputPath" "Red"
  exit 1
}

if (-not $OutputDir) {
  $OutputDir = Join-Path (Get-Location) "beautified_output"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$params = @{
  Path = $InputPath
  Include = @("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs")
}
if ($Recurse) { $params.Recurse = $true } else { $params.Depth = 0 }

$files = Get-ChildItem @params | Where-Object { !$_.PSIsContainer }

if ($files.Count -eq 0) {
  Write-Color "[ERROR] No JS/TS files found at: $InputPath" "Red"
  exit 1
}

Write-Color "Processing $($files.Count) files..." "Yellow"

$hasPrettier = Get-Command "npx" -ErrorAction SilentlyContinue

$results = @()
foreach ($file in $files) {
  $filename = $file.Name
  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($filename)

  try {
    $content = Get-Content $file.FullName -Raw -ErrorAction Stop
    $sizeKB = [math]::Round($content.Length / 1KB, 1)
    $framework = Get-FrameworkType $content
    $minLevel = Get-MinificationLevel $content
    $wrapperType = Get-ModuleWrapperType $content
    $sourceMap = Get-SourceMapUrl $content
    $origHash = Get-BundleHash $content
    $origStats = Get-FormatStats $content
    $lineDist = Measure-LineDistribution $content
    Write-Color "  [$filename] ($sizeKB KB, $framework, $wrapperType, min=$($minLevel.Score))" "White"

    [string]$syntaxValid = "unknown"
    $syntaxCheck = Test-JsSyntax $file.FullName
    if ($syntaxCheck -eq $true) { $syntaxValid = "pass" }
    elseif ($syntaxCheck -ne $true) { $syntaxValid = "fail" }
    Write-Color "    Syntax: $syntaxValid | Minification: $($minLevel.Level) (score $($minLevel.Score)) | Type: $wrapperType" "Gray"

    if ($sourceMap) { Write-Color "    sourceMappingURL: $sourceMap" "DarkYellow" }

    if ($Backup) {
      $backupDir = Join-Path (Split-Path $file.FullName -Parent) ".backup"
      New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
      Copy-Item $file.FullName (Join-Path $backupDir $filename) -Force
    }

    $outFile = Join-Path $OutputDir $filename

    $beautifySuccess = $false
    if ($hasPrettier) {
      $tempFile = Join-Path $OutputDir "${baseName}_temp.js"
      Copy-Item $file.FullName $tempFile -Force

      $output = npx --yes prettier --parser babel --print-width 120 --tab-width 2 --single-quote --trailing-comma all --bracket-spacing --arrow-parens always "$tempFile" 2>&1

      if (Test-Path $tempFile) {
        Move-Item $tempFile $outFile -Force
        Write-Color "    Beautified with prettier" "Green"
        $beautifySuccess = $true
      }
    }

    if (-not $beautifySuccess) {
      Copy-Item $file.FullName $outFile -Force
      Write-Color "    Copied (no beautifier available)" "DarkYellow"
    }

    $beauContent = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
    $beauHash = if ($beauContent) { Get-BundleHash $beauContent } else { "N/A" }
    $diffSummary = if ($beauContent) { Get-DiffSummary $content $beauContent } else { $null }
    $compressionRatio = if ($beauContent) { Get-CompressionRatio $content $beauContent } else { 0 }

    $status = if ($beautifySuccess) { "beautified" } else { "copied" }
    $results += [PSCustomObject]@{
      File = $filename; SizeKB = $sizeKB; Framework = $framework
      Status = $status; Wrapper = $wrapperType; MinScore = $minLevel.Score
      HashOrig = $origHash; HashBeau = $beauHash
      CompressionPct = $compressionRatio
      SyntaxValid = $syntaxValid; SourceMapUrl = $sourceMap
    }

  } catch {
    Write-Color "  [ERROR] $filename : $_" "Red"
  }
}

Write-Color "" "Yellow"
Write-Color "Summary" "Yellow"
Write-Color "  Files processed: $($results.Count)" "White"
Write-Color "  Output directory: $OutputDir" "White"

$frameworks = $results | Group-Object Framework
foreach ($fw in $frameworks) {
  Write-Color "    $($fw.Name): $($fw.Count) files" "Gray"
}

$wrapperTypes = $results | Group-Object Wrapper
if ($wrapperTypes) {
  Write-Color "  Module types:" "White"
  foreach ($wt in $wrapperTypes) { Write-Color "    $($wt.Name): $($wt.Count)" "Gray" }
}

$minScores = $results | ForEach-Object { $_.MinScore } | Measure-Object -Average
if ($minScores.Count -gt 0) { Write-Color "  Avg minification score: $([math]::Round($minScores.Average, 1))/10" "White" }

$withSourceMaps = @($results | Where-Object { $_.SourceMapUrl })
if ($withSourceMaps.Count -gt 0) { Write-Color "  Files with source maps: $($withSourceMaps.Count)" "DarkYellow" }

$syntaxFails = @($results | Where-Object { $_.SyntaxValid -eq "fail" })
if ($syntaxFails.Count -gt 0) { Write-Color "  [!] Syntax errors: $($syntaxFails.Count)" "Red" }

$totalCompression = ($results | ForEach-Object { $_.CompressionPct } | Measure-Object -Average).Average
if ($totalCompression -ne 0) { Write-Color "  Avg size change: $([math]::Round($totalCompression, 1))%" "White" }

Write-Color "" "Cyan"
Write-Color "Done!" "Cyan"
Write-Color "" "Cyan"
