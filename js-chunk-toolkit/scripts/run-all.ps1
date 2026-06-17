param(
  [Parameter(Mandatory = $true)]
  [string]$Target,

  [string]$OutputDir = "js-analysis-output",
  [switch]$DownloadBundles = $false,
  [switch]$Recurse = $false,
  [switch]$Deobfuscate = $true,
  [switch]$SkipBeautify = $false
)

$ErrorActionPreference = "SilentlyContinue"
$ScriptRoot = Split-Path -Parent $PSCommandPath
$ProjectRoot = Split-Path -Parent $ScriptRoot

function Write-Step {
  param([string]$Num, [string]$Msg)
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Cyan
  Write-Host "  Step ${Num}: $Msg" -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Done {
  param([string]$Msg)
  Write-Host "  [OK] $Msg" -ForegroundColor Green
}

function Write-Warn {
  param([string]$Msg)
  Write-Host "  [!] $Msg" -ForegroundColor DarkYellow
}

function Write-Err {
  param([string]$Msg)
  Write-Host "  [ERROR] $Msg" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  JS Chunk Deobfuscation & Analysis Pipeline" -ForegroundColor Magenta
Write-Host "  Target: $Target" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

$fullOutputDir = Join-Path (Get-Location) $OutputDir
New-Item -ItemType Directory -Path $fullOutputDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $fullOutputDir "reports") -Force | Out-Null

# Determine if Target is a URL or local path
$isUrl = $Target -match '^https?://'
$localPath = if ($isUrl) { Join-Path $fullOutputDir "downloaded_bundles" } else { $Target }

if ($isUrl) {
  if (-not $DownloadBundles) {
    Write-Step "0" "Fetching JS URLs from $Target"
  }

  Write-Step "0a" "Extracting script tags from HTML"
  try {
    $html = (Invoke-WebRequest -Uri $Target -UseBasicParsing -TimeoutSec 15).Content
    $scriptMatches = [regex]::Matches($html, '<script[^>]+src=["'']([^"'']+)["'']')
    $linkPrefetch = [regex]::Matches($html, '<link[^>]+as="script"[^>]+href=["'']([^"'']+)["'']')
    $modulepreload = [regex]::Matches($html, '<link[^>]+rel="modulepreload"[^>]+href=["'']([^"'']+)["'']')

    $rawUrls = @()
    $scriptMatches | ForEach-Object { $rawUrls += $_.Groups[1].Value }
    $linkPrefetch | ForEach-Object { $rawUrls += $_.Groups[1].Value }
    $modulepreload | ForEach-Object { $rawUrls += $_.Groups[1].Value }

    $absoluteUrls = $rawUrls | ForEach-Object {
      $u = $_
      if ($u -match '^//') { "https:$u" }
      elseif ($u -match '^/') {
        $base = $Target -replace '/$', ''
        $base = ($base -split '/')[0..2] -join '/'
        "$base$u"
      }
      elseif ($u -match '^https?://') { $u }
      else { $null }
    } | Where-Object { $_ -ne $null } | Select-Object -Unique

    $jsUrls = $absoluteUrls | Where-Object { $_ -match '\.js' }

    Write-Done "Found $($jsUrls.Count) JS URLs"
    $jsUrls | Out-File (Join-Path $fullOutputDir "js-urls.txt")

    if ($jsUrls.Count -eq 0) {
      Write-Warn "No JS URLs found in HTML. Check the target manually."
      Write-Warn "Common patterns: /static/js/main.*.js, /_next/static/chunks/"
    }
  } catch {
    Write-Err "Failed to fetch HTML: $_"
    $jsUrls = @()
  }

  if ($DownloadBundles -and $jsUrls.Count -gt 0) {
    Write-Step "0b" "Downloading JS bundles"
    New-Item -ItemType Directory -Path $localPath -Force | Out-Null
    $downloaded = 0
    foreach ($url in $jsUrls) {
      $name = [regex]::Match($url, '/([^/?]+\.js)').Groups[1].Value
      if (-not $name) { $name = "chunk_$([guid]::NewGuid().ToString().Substring(0,8)).js" }
      $outPath = Join-Path $localPath $name
      try {
        curl.exe -sL -o $outPath $url
        if ((Get-Item $outPath).Length -gt 100) {
          Write-Done "$name ($((Get-Item $outPath).Length / 1KB, 1) KB)"
          $downloaded++
        } else {
          Remove-Item $outPath -Force
        }
      } catch {}
    }
    Write-Done "Downloaded $downloaded JS bundles to $localPath"
  }

  if ($jsUrls.Count -gt 0 -and (Test-Path $localPath)) {
    $existingFiles = Get-ChildItem $localPath -Filter "*.js"
    if ($existingFiles.Count -eq 0) { $localPath = $null }
  } else {
    $localPath = $null
  }
} else {
  if (-not (Test-Path $Target)) {
    Write-Err "Target path not found: $Target"
    exit 1
  }
  Write-Done "Using local path: $(Resolve-Path $Target)"
}

if (-not $localPath) {
  Write-Warn "No local JS files to analyze. Provide a local path or use -DownloadBundles."
  exit 0
}

# Step 1: Framework Detection
Write-Step "1" "Framework Detection"
$detectScript = @'
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
const results = {};
files.forEach(file => {
  const content = fs.readFileSync(path.join(dir, file), 'utf-8').substring(0, 5000);
  let fw = 'Unknown';
  if (/__webpack_require__/.test(content)) fw = 'Webpack';
  else if (/next\.\d+/.test(content)) fw = 'Next.js';
  else if (/createRouter|VueRouter|createApp/.test(content)) fw = 'Vue.js';
  else if (/ngZone|platformBrowserDynamic/.test(content)) fw = 'Angular';
  else if (/createRoot|ReactDOM\.render/.test(content)) fw = 'React';
  else if (/System\.register/.test(content)) fw = 'SystemJS';
  else if (/define\(["']/.test(content)) fw = 'AMD';
  results[file] = fw;
});
Object.entries(results).forEach(([f, fw]) => console.log(`${f}: ${fw}`));
'@

$detectFile = Join-Path $fullOutputDir "_detect_fw.js"
$detectScript | Out-File -FilePath $detectFile -Encoding utf8

try {
  $detectionOutput = node $detectFile $localPath 2>$null
  if ($detectionOutput) {
    $detectionOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
  }
} catch {
  Write-Warn "Framework detection failed (Node.js required)"
}
Remove-Item $detectFile -Force

# Step 2: Webpack Chunk Analysis
Write-Step "2" "Webpack Chunk Analysis"
$chunkScript = Join-Path $ScriptRoot "webpack-chunk-extractor.js"
if (Test-Path $chunkScript) {
  try {
    $chunkFile = Join-Path (Join-Path $fullOutputDir "reports") "chunk-analysis.txt"
    node $chunkScript $localPath 2>$null | Out-File -FilePath $chunkFile -Encoding utf8
    if (Test-Path $chunkFile) { Write-Done "Chunk analysis complete -> reports/chunk-analysis.txt" }
  } catch {
    Write-Err "Chunk analysis failed: $_"
  }
} else {
  Write-Warn "webpack-chunk-extractor.js not found"
}

# Step 3: Deobfuscation Analysis
Write-Step "3" "Deobfuscation & String Extraction"
$deobfScript = Join-Path $ScriptRoot "deobfuscate.js"
if (Test-Path $deobfScript -and $Deobfuscate) {
  try {
    $deobfFile = Join-Path (Join-Path $fullOutputDir "reports") "deobfuscation-report.txt"
    node $deobfScript $localPath 2>$null | Out-File -FilePath $deobfFile -Encoding utf8
    if (Test-Path $deobfFile -and (Get-Item $deobfFile).Length -gt 0) {
      Write-Done "Deobfuscation analysis complete -> reports/deobfuscation-report.txt"
    }
  } catch {
    Write-Err "Deobfuscation failed: $_"
  }
}

# Step 4: Beautify
if (-not $SkipBeautify) {
  Write-Step "4" "Beautify JS Bundles"
  $beautifyScript = Join-Path $ScriptRoot "batch-beautify.ps1"
  if (Test-Path $beautifyScript) {
    $beautifyDir = Join-Path $fullOutputDir "beautified"
    try {
      & $beautifyScript -InputPath $localPath -OutputDir $beautifyDir -Recurse:$Recurse
      Write-Done "Beautified output -> beautified/"
    } catch {
      Write-Err "Beautification failed: $_"
    }
  }
} else {
  Write-Step "4" "Beautify (skipped via -SkipBeautify)"
}

# Step 5: Source Map Discovery & Restoration
Write-Step "5" "Source Map Discovery"
$sourceMapReport = @()
Get-ChildItem $localPath -Filter "*.js" | ForEach-Object {
  $content = Get-Content $_.FullName -Raw
  $mapUrlMatch = [regex]::Match($content, 'sourceMappingURL=([^\s"\'']+)')
  if ($mapUrlMatch.Success) {
    $sourceMapReport += [PSCustomObject]@{
      File = $_.Name
      MapURL = $mapUrlMatch.Groups[1].Value
    }
  }
}
if ($sourceMapReport.Count -gt 0) {
  $sourceMapReport | Format-Table | Out-String | Write-Host
  $sourceMapReport | Export-Csv (Join-Path (Join-Path $fullOutputDir "reports") "sourcemaps.csv") -NoTypeInformation
  Write-Done "$($sourceMapReport.Count) source maps referenced"

  $triedDownload = 0
  $mapDir = Join-Path $fullOutputDir "sourcemaps"
  New-Item -ItemType Directory -Path $mapDir -Force | Out-Null

  $sourceMapReport | ForEach-Object {
    if ($_.MapURL -match '^https?://') {
      $mapOut = Join-Path $mapDir "$($_.File).map"
      try {
        curl.exe -sL -o $mapOut $_.MapURL
        if ((Get-Item $mapOut).Length -gt 100) {
          Write-Done "Downloaded source map: $($_.MapURL)"
          $triedDownload++
        } else {
          Remove-Item $mapOut -Force
        }
      } catch {}
    }
  }

  if ($triedDownload -gt 0) {
    $restoreScript = Join-Path $ScriptRoot "source-map-restore.js"
    if (Test-Path $restoreScript) {
      Write-Step "5b" "Restoring Source Maps"
      try {
        node $restoreScript $mapDir 2>&1 | Out-File (Join-Path (Join-Path $fullOutputDir "reports") "sourcemap-restore.txt")
        Write-Done "Source map restoration complete -> reports/sourcemap-restore.txt"
      } catch {
        Write-Err "Source map restoration failed: $_"
      }
    }
  }
} else {
  Write-Warn "No sourceMappingURL references found in the JS files"
}

# Step 6: Secret Scanning
Write-Step "6" "Secret & Endpoint Scanning"
$scannerScript = Join-Path (Join-Path $ProjectRoot "scanners") "secret-scanner.ps1"
if (Test-Path $scannerScript) {
  $scanOutDir = Join-Path $fullOutputDir "scanner_reports"
  try {
    & $scannerScript -InputPath $localPath -OutputDir $scanOutDir -Recurse:$Recurse
    Write-Done "Secret scanning complete -> scanner_reports/"
  } catch {
    Write-Err "Secret scanning failed: $_"
  }
} else {
  Write-Warn "secret-scanner.ps1 not found at $scannerScript"
}

# Step 7: Deep Analysis (20 features)
Write-Step "7" "Deep Analysis -- 20 Features"
$deepScript = Join-Path (Join-Path $ProjectRoot "analyzers") "deep-analyzer.js"
$deepReport = Join-Path (Join-Path $fullOutputDir "reports") "deep-analysis.txt"
if (Test-Path $deepScript) {
  try {
    node $deepScript $localPath 2>$null | Out-File -FilePath $deepReport -Encoding utf8
    if (Test-Path $deepReport) { Write-Done "Deep analysis complete -> reports/deep-analysis.txt" }
  } catch { Write-Err "Deep analysis failed: $_" }
}

# Step 7b: JWT Decoder
$jwtScript = Join-Path (Join-Path $ProjectRoot "analyzers") "jwt-decoder.js"
$jwtReport = Join-Path (Join-Path $fullOutputDir "reports") "jwt-analysis.txt"
if (Test-Path $jwtScript) {
  try {
    node $jwtScript $localPath 2>$null | Out-File -FilePath $jwtReport -Encoding utf8
    if (Test-Path $jwtReport) { Write-Done "JWT analysis -> reports/jwt-analysis.txt" }
  } catch {}
}

# Step 7c: Cloud Enumeration
$cloudScript = Join-Path (Join-Path $ProjectRoot "analyzers") "cloud-enum.js"
$cloudReport = Join-Path (Join-Path $fullOutputDir "reports") "cloud-enum.txt"
if (Test-Path $cloudScript) {
  try {
    node $cloudScript $localPath 2>$null | Out-File -FilePath $cloudReport -Encoding utf8
    if (Test-Path $cloudReport) { Write-Done "Cloud enumeration -> reports/cloud-enum.txt" }
  } catch {}
}

# Step 7e: Vulnerability Detection (22+ classes)
$vulnScript = Join-Path (Join-Path $ProjectRoot "analyzers") "vulnerability-analyzer.js"
$vulnReport = Join-Path (Join-Path $fullOutputDir "reports") "vulnerability-analysis.txt"
$vulnJson = Join-Path (Join-Path $fullOutputDir "reports") "vulnerability-analysis.json"
if (Test-Path $vulnScript) {
  try {
    node $vulnScript $localPath --json $vulnJson 2>$null | Out-File -FilePath $vulnReport -Encoding utf8
    if (Test-Path $vulnReport) { Write-Done "Vulnerability analysis -> reports/vulnerability-analysis.txt + .json" }
  } catch { Write-Err "Vulnerability analysis failed: $_" }
}

# Step 7d: GraphQL Finder
$gqlScript = Join-Path (Join-Path $ProjectRoot "analyzers") "graphql-finder.js"
$gqlReport = Join-Path (Join-Path $fullOutputDir "reports") "graphql-analysis.txt"
if (Test-Path $gqlScript) {
  try {
    node $gqlScript $localPath 2>$null | Out-File -FilePath $gqlReport -Encoding utf8
    if (Test-Path $gqlReport) { Write-Done "GraphQL analysis -> reports/graphql-analysis.txt" }
  } catch {}
}

# Step 7f: Function Extraction
$funcScript = Join-Path (Join-Path $ProjectRoot "analyzers") "function-extractor.js"
$funcReport = Join-Path (Join-Path $fullOutputDir "reports") "function-extraction.txt"
if (Test-Path $funcScript) {
  try {
    node $funcScript $localPath 2>$null | Out-File -FilePath $funcReport -Encoding utf8
    if (Test-Path $funcReport) { Write-Done "Function extraction -> reports/function-extraction.txt" }
  } catch { Write-Err "Function extraction failed: $_" }
}

# Step 8: Post-Processing (FP filter + dedup + severity)
$rawFindings = Join-Path (Join-Path $fullOutputDir "reports") "vulnerability-analysis.json"
$finalOutput = Join-Path (Join-Path $fullOutputDir "reports") "final-findings.json"
$postScript = Join-Path (Join-Path $ProjectRoot "utils") "post-processor.js"
if (Test-Path $postScript -and (Test-Path $rawFindings)) {
  try {
    node $postScript $rawFindings --output $finalOutput 2>$null | Out-File -FilePath (Join-Path (Join-Path $fullOutputDir "reports") "post-processing.txt") -Encoding utf8
    if (Test-Path $finalOutput) { Write-Done "Post-processing complete -> reports/final-findings.json" }
  } catch { Write-Err "Post-processing failed: $_" }
}

function Write-Summary {
  param([string]$dir)
  Write-Step "Summary"
  Write-Host -Object "  Output directory: $dir" -ForegroundColor White
  Write-Host ""

  $rDir = Join-Path $dir "reports"
  if (Test-Path $rDir) {
    Write-Host -Object "  Reports:" -ForegroundColor Yellow
    foreach ($f in (Get-ChildItem $rDir)) {
      $fileKb = [math]::Round($f.Length / 1KB, 1)
      $msg = '    ' + $f.Name + '  (' + $fileKb + ' KB)'
      Write-Host -Object $msg -ForegroundColor Gray
    }
  }

  $sDir = Join-Path $dir 'scanner_reports'
  if (Test-Path $sDir) {
    Write-Host -Object '  Scanner Reports:' -ForegroundColor Yellow
    foreach ($f in (Get-ChildItem $sDir)) {
      $fileKb = [math]::Round($f.Length / 1KB, 1)
      $msg = '    ' + $f.Name + '  (' + $fileKb + ' KB)'
      Write-Host -Object $msg -ForegroundColor Gray
    }
  }

  $bDir = Join-Path $dir "beautified"
  if (Test-Path $bDir) {
    $count = (Get-ChildItem $bDir).Count
    Write-Host -Object "  Beautified files: $count" -ForegroundColor Green
  }

  Write-Host ""
  Write-Host -Object "========================================" -ForegroundColor Magenta
  Write-Host -Object "  Pipeline complete!" -ForegroundColor Magenta
  Write-Host -Object "========================================" -ForegroundColor Magenta
  Write-Host ""
}

Write-Summary -dir $fullOutputDir
