param(
  [Parameter(Mandatory = $true)]
  [string]$TargetUrl,
  [string]$OutputDir = "downloaded_js",
  [switch]$ExtractFromHTML,
  [string[]]$CustomPatterns = @(),
  [switch]$SourceMaps = $false,
  [switch]$HARFile = $false
)

$ErrorActionPreference = "SilentlyContinue"

function Get-UrlStatus {
  param([string]$Url)
  try {
    $req = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Head -TimeoutSec 5
    return $req.StatusCode
  } catch { return $null }
}

function Get-ContentHash {
  param([string]$Path)
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($bytes)
    return [BitConverter]::ToString($hash).Replace("-","").Substring(0,16).ToLower()
  } catch { return "N/A" }
}

function Resolve-Uri {
  param([string]$Base, [string]$Relative)
  try { return [System.Uri]::new([System.Uri]$Base, $Relative).AbsoluteUri }
  catch { return $null }
}

function Get-FrameworkPaths {
  param([string]$BaseUrl, [string]$Html)
  $hints = @()
  if ($Html -match 'next\.[a-f0-9]+\.js' -or $Html -match '_next/static') {
    $hints += @("/_next/static/chunks/pages/index.js", "/_next/static/chunks/webpack.js", "/_next/static/chunks/main.js", "/_next/static/chunks/framework.js")
  }
  if ($Html -match 'vue|createApp') { $hints += @("/js/app.js", "/js/chunk-vendors.js") }
  if ($Html -match 'ng-version|angular') { $hints += @("/runtime.js", "/polyfills.js", "/main.js", "/vendor.js") }
  if ($Html -match 'react|createRoot') { $hints += @("/static/js/main.js", "/static/js/bundle.js") }
  return $hints | ForEach-Object { "$($BaseUrl.TrimEnd('/'))$_" }
}

function Get-JsFromInlineScripts {
  param([string]$Html)
  $urls = @()
  $inlinePattern = '<script[^>]*>([\s\S]*?)</script>'
  $allMatches = [regex]::Matches($Html, $inlinePattern)
  foreach ($m in $allMatches) {
    $script = $m.Groups[1].Value
    if ($script -match 'src:\s*["'']([^"'' ]+\.js[^"'']*)["'']') { $urls += $Matches[1] }
    if ($script -match '["'']([^"'' ]+\.(?:js|mjs)[^"'']*)["'']') { $urls += $Matches[1] }
  }
  return $urls
}

function Get-JsFromJsonConfig {
  param([string]$Html)
  $urls = @()
  $configPattern = '"jsUrl"|"bundleUrl"|"chunkUrl"|"scriptUrl"'
  $jsonMatches = [regex]::Matches($Html, "($configPattern)\s*:\s*[""'']([^""'']+)[""'']")
  foreach ($m in $jsonMatches) {
    if ($m.Groups[2].Value -match '\.js') { $urls += $m.Groups[2].Value }
  }
  return $urls
}

function Get-JsFromWebpackJsonp {
  param([string]$Html)
  $urls = @()
  $wpMatch = [regex]::Matches($Html, 'webpackJsonp|__webpack_require__')
  if ($wpMatch.Count -gt 0) {
    $urlMatch = [regex]::Matches($Html, "[""''](https?://[^""'']+\.js(?:%[^""'']*|[^""'']*)?)[""'']")
    foreach ($m in $urlMatch) { $urls += $m.Groups[1].Value }
  }
  return $urls
}

function Add-HttpHeaders {
  param([string]$Url)
  $headers = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"; "Accept" = "*/*" }
  $headers["Referer"] = $TargetUrl
  try {
    $origin = [System.Uri]$TargetUrl
    $headers["Origin"] = $origin.GetLeftPart([System.UriPartial]::Authority)
  } catch {}
  return $headers
}

function Write-DownloadManifest {
  param([string]$OutputDir, [array]$Entries)
  $manifest = Join-Path $OutputDir "_manifest.txt"
  $Entries | ForEach-Object {
    "$($_.Url) -> $($_.File) | $($_.SizeKB) KB | Hash: $($_.Hash) | $($_.Status)"
  } | Out-File -FilePath $manifest -Encoding utf8
}

function Get-PageMetadata {
  param([string]$Html)
  $meta = @{}
  $titleMatch = [regex]::Match($Html, '<title>([^<]+)</title>')
  if ($titleMatch.Success) { $meta["Title"] = $titleMatch.Groups[1].Value }
  $q = '"'
  $descPattern = "<meta[^>]+name=[$q']description[$q'][^>]+content=[$q']([^$q']+)[$q']"
  $descMatch = [regex]::Match($Html, $descPattern)
  if ($descMatch.Success) { $meta["Description"] = $descMatch.Groups[1].Value }
  $reactMatch = [regex]::Match($Html, 'react|__NEXT_DATA__|createRoot')
  if ($reactMatch.Success) { $meta["Framework"] = "React" }
  $vueMatch = [regex]::Match($Html, 'vue|createApp|__VUE__')
  if ($vueMatch.Success) { $meta["Framework"] = "Vue" }
  $angularMatch = [regex]::Match($Html, 'ng-version|angular')
  if ($angularMatch.Success) { $meta["Framework"] = "Angular" }
  return $meta
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$jsUrls = @()

if ($ExtractFromHTML) {
  Write-Host "[*] Fetching HTML: $TargetUrl" -ForegroundColor Cyan
  try {
    $html = (Invoke-WebRequest -Uri $TargetUrl -UseBasicParsing -TimeoutSec 15).Content
  } catch {
    Write-Host "[!] Invoke-WebRequest failed, trying curl.exe..." -ForegroundColor DarkYellow
    $tempFile = Join-Path $OutputDir "_page.html"
    curl.exe -sL -o $tempFile $TargetUrl
    $html = Get-Content $tempFile -Raw
    Remove-Item $tempFile -Force
  }

  if (-not $html) {
    Write-Host "[ERROR] Could not fetch HTML from $TargetUrl" -ForegroundColor Red
    exit 1
  }

  $q = '"'
  $pattern = "<script[^>]+src=[$q']([^$q']+)[$q']"
  $scriptMatches = [regex]::Matches($html, $pattern)
  $scriptMatches | ForEach-Object { $jsUrls += $_.Groups[1].Value }

  $preloadPattern = "<link[^>]+rel=[$q'](?:preload|modulepreload)[$q']+[^>]+href=[$q']([^$q']+)[$q']"
  $preloadMatches = [regex]::Matches($html, $preloadPattern)
  $preloadMatches | ForEach-Object { $jsUrls += $_.Groups[1].Value }

  $importMapPattern = "<script[^>]+type=[$q']importmap[$q']+[^>]*>([\s\S]*?)</script>"
  $importMapMatches = [regex]::Matches($html, $importMapPattern)
  $importMapMatches | ForEach-Object {
    $json = $_.Groups[1].Value
    $urls = [regex]::Matches($json, "[$q']([^$q']+\.js[^$q']*)[$q']")
    $urls | ForEach-Object { $jsUrls += $_.Groups[1].Value }
  }
}

if ($CustomPatterns.Count -gt 0) {
  $CustomPatterns | ForEach-Object {
    $allMatches = [regex]::Matches($html, $_)
    $allMatches | ForEach-Object { $jsUrls += $_.Groups[1].Value }
  }
}

$baseUri = [System.Uri]$TargetUrl
$resolvedUrls = $jsUrls | ForEach-Object {
  $u = $_.Trim()
  if ($u -match '^//') { "https:$u" }
  elseif ($u -match '^/') { "$($baseUri.GetLeftPart([System.UriPartial]::Authority))$u" }
  elseif ($u -match '^https?://') { $u }
  elseif ($u -match '^(\.\./|\./)') { Resolve-Uri -Base $TargetUrl -Relative $u }
  elseif ($u -match '^[a-zA-Z0-9]') {
    $base = $TargetUrl.TrimEnd('/')
    "$base/$u"
  }
  else { $null }
} | Where-Object { $_ -ne $null } | Select-Object -Unique

$jsOnlyUrls = $resolvedUrls | Where-Object { $_ -match '\.js' }

if ($jsOnlyUrls.Count -eq 0) {
  Write-Host "[!] No JS URLs found via HTML extraction" -ForegroundColor DarkYellow
  Write-Host "[*] Trying framework-aware paths..." -ForegroundColor Cyan

  $meta = if ($html) { Get-PageMetadata $html } else { @{} }
  $hints = Get-FrameworkPaths -BaseUrl $TargetUrl -Html $html
  if ($meta.ContainsKey("Framework")) { Write-Host "  Detected: $($meta['Framework']) app" -ForegroundColor Green }

  foreach ($testUrl in $hints) {
    $status = Get-UrlStatus $testUrl
    if ($status -eq 200) {
      $jsOnlyUrls += $testUrl
      Write-Host "  Found: $testUrl" -ForegroundColor Green
    }
  }
}

$jsOnlyUrls = $jsOnlyUrls | Select-Object -Unique
Write-Host "[*] Total JS URLs: $($jsOnlyUrls.Count)" -ForegroundColor White

if ($jsOnlyUrls.Count -eq 0) {
  Write-Host "[ERROR] No JS files discovered. Try a different URL or use -CustomPatterns." -ForegroundColor Red
  exit 1
}

$downloaded = 0
$manifestEntries = @()
$maxRetries = 3

foreach ($url in $jsOnlyUrls) {
  $filename = [regex]::Match($url, '/([^/?]+\.js)').Groups[1].Value
  if (-not $filename) {
    $hash = [guid]::NewGuid().ToString().Substring(0, 8)
    $filename = "chunk_$hash.js"
  }
  $outPath = Join-Path $OutputDir $filename

  Write-Host "  Downloading: $filename" -ForegroundColor Gray

  $success = $false
  for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
    try {
      $origin = ([System.Uri]$TargetUrl).GetLeftPart([System.UriPartial]::Authority)
      $null = & curl.exe -sL --retry 2 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -H "Referer: $TargetUrl" -H "Origin: $origin" -o $outPath $url

      if ((Get-Item $outPath).Length -gt 100) {
        $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
        $contentHash = Get-ContentHash $outPath

        $status = "OK"
        if ($attempt -gt 1) { $status = "OK (retry $attempt)" }
        Write-Host "    $sizeKB KB - $status [hash: $contentHash]" -ForegroundColor Green
        $downloaded++
        $success = $true

        $manifestEntries += @{ Url = $url; File = $filename; SizeKB = $sizeKB; Hash = $contentHash; Status = "downloaded" }

        if ($SourceMaps) {
          $mapUrl = $url + ".map"
          $mapPath = $outPath + ".map"
          curl.exe -sL -o $mapPath $mapUrl 2>$null
          if ((Get-Item $mapPath).Length -gt 100) {
            $mapKB = [math]::Round((Get-Item $mapPath).Length / 1KB, 1)
            $mapHash = Get-ContentHash $mapPath
            Write-Host "    Source map: $mapKB KB [hash: $mapHash]" -ForegroundColor Green
            $manifestEntries += @{ Url = $mapUrl; File = "$filename.map"; SizeKB = $mapKB; Hash = $mapHash; Status = "sourcemap" }
          } else {
            Remove-Item $mapPath -Force -ErrorAction SilentlyContinue
          }
        }
        break
      } else {
        Remove-Item $outPath -Force -ErrorAction SilentlyContinue
        if ($attempt -lt $maxRetries) { Start-Sleep -Milliseconds 500 }
      }
    } catch {
      if ($attempt -lt $maxRetries) { Start-Sleep -Milliseconds 1000 }
    }
  }

  if (-not $success) {
    Write-Host "    Failed after $maxRetries attempts" -ForegroundColor DarkYellow
    $manifestEntries += @{ Url = $url; File = $filename; SizeKB = 0; Hash = "N/A"; Status = "failed" }
  }
}

Write-DownloadManifest -OutputDir $OutputDir -Entries $manifestEntries

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Download complete" -ForegroundColor Cyan
Write-Host "  Downloaded: $downloaded / $($jsOnlyUrls.Count)" -ForegroundColor White
Write-Host "  Output: $OutputDir" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
