<#
.SYNOPSIS
    Evidence collection and sanitization toolkit for bug bounty report submissions.
.DESCRIPTION
    Suite of functions for capturing HTTP evidence, redacting sensitive data
    (cookies, auth headers, PII), generating HAR files, building finding records,
    and packaging evidence for Bugcrowd / HackerOne / Intigriti submissions.

    *** CREDENTIAL SAFETY WARNING ***
    These functions handle raw HTTP traffic that may contain session cookies,
    authorization tokens, API keys, and other secrets. Always review redacted
    output manually before submission. Never commit raw unredacted evidence to
    version control. Redaction regex patterns are heuristic and may miss edge
    cases. Run with -Verbose to audit what was redacted.

    Author:   Bug Bounty Toolkit
    Version:  1.0.0
    Requires: PowerShell 5.1+

    .USAGE
    # Load the module
    . .\evidence-toolkit.ps1

    # Quick one-shot: capture, redact, save, validate, and zip
    $result = Invoke-FullEvidencePipeline `
        -RequestText $req -ResponseText $resp `
        -Url "https://api.target.com/vulnerable" `
        -FindingId "IDOR-001" -BaseDir "evidence" `
        -Severity "High" -VulnerabilityClass "IDOR" -Compress

    # Manual workflow for more control:
    $dirs = New-EvidenceFolder -BaseDir "evidence" -FindingId "XSS-001" -PassThru
    $saved = Save-RequestResponse -RequestText $req -ResponseText $resp `
        -Name "xss-poc" -OutDir $dirs.RawDir
    Redact-Cookies -Path $saved.RequestFile, $saved.ResponseFile -InPlace
    Redact-AuthHeaders -Path $saved.RequestFile, $saved.ResponseFile -InPlace
    Redact-Pii -Path $saved.RequestFile, $saved.ResponseFile -InPlace
    ConvertTo-Har -RequestText $req -ResponseText $resp -Url $url -OutFile (Join-Path $dirs.HarDir "xss.har")
    Sanitize-HarFile -Path (Join-Path $dirs.HarDir "xss.har") -InPlace
    Test-EvidencePackage -FindingRecordPath (Join-Path $dirs.ReportDir "finding-record.json")
    Compress-EvidencePackage -FindingDir $dirs.FindingDir
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest

function Invoke-CurlCapture {
    <#
    .SYNOPSIS
        Captures a full curl request/response with timestamps and saves to a structured file.
    .DESCRIPTION
        Uses curl.exe to execute an HTTP request and captures the full request and response
        details including method, URL, headers, status code, timing, content type, and body.
        The output is saved to a structured text file with clear section markers suitable
        for later redaction or direct use as evidence. The file format is designed to be
        human-readable and machine-parseable.

        The captured output includes:
          - Start and end timestamps (ISO 8601 format)
          - Request method, URL, and custom headers
          - Request body (for POST/PUT/PATCH)
          - Response HTTP status code
          - Response content type and size
          - Round-trip time in seconds
          - Full response body
    .PARAMETER Method
        HTTP method for the request. Supported: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.
    .PARAMETER Uri
        Target URI for the request. Must be a valid URL including scheme.
    .PARAMETER Headers
        Optional hashtable of custom HTTP headers to include with the request.
    .PARAMETER Body
        Request body content. Required for POST, PUT, and PATCH methods.
    .PARAMETER OutFile
        Path where the captured output file will be saved. Parent directory created if needed.
    .PARAMETER ContentType
        Value for the Content-Type header. Default: application/json.
    .PARAMETER VerboseOutput
        Switch to include verbose connection details in capture output.
    .EXAMPLE
        Invoke-CurlCapture -Uri "https://api.target.com/user/profile" -OutFile "captures\profile.txt"
    .EXAMPLE
        Invoke-CurlCapture -Method POST -Uri "https://api.target.com/api/data" `
            -Headers @{"X-Custom"="value"} -Body '{"id":1}' -OutFile "captures\data.txt"
    .LINK
        https://curl.se/docs/manpage.html
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS')][string]$Method='GET',
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers=@{}, [string]$Body='',
        [Parameter(Mandatory)][string]$OutFile,
        [string]$ContentType='application/json', [switch]$VerboseOutput
    )
    $st=Get-Date; $pd=Split-Path $OutFile-Parent
    if($pd-and-not(Test-Path $pd)){New-Item-ItemType Directory-Path $pd-Force|Out-Null}
    $ca=@('-s','-S','-w',"`n---CURL_METRICS---`n%{http_code}||%{time_total}||%{size_download}||%{content_type}",'-o',$OutFile)
    if($Method-ne'GET'){$ca+='-X',$Method}
    foreach($kv in $Headers.GetEnumerator()){$ca+='-H',"$($kv.Key): $($kv.Value)"}
    if($Method-in@('POST','PUT','PATCH')-and$Body){$ca+='-H',"Content-Type: $ContentType";$ca+='--data-raw',$Body}
    try { $mr=&'curl.exe'$ca 2>&1 } catch { Write-Warning "[Invoke-CurlCapture] curl.exe failed: $_"; return $null }; $et=Get-Date
    $ml=$mr-split"`n"|Where-Object{$_-match'^\d{3}\|\|'}|Select-Object-First 1
    $hc='';$tt='';$sd='';$rct=''
    if($ml){$p=$ml-split'\|\|';$hc=$p[0];$tt=$p[1];$sd=$p[2];$rct=$p[3]}
    $cb=if(Test-Path $OutFile){Get-Content $OutFile-Raw}else{''}
    $s=[System.Text.StringBuilder]::new()
    [void]$s.AppendLine("#"*72);[void]$s.AppendLine("# EVIDENCE CAPTURE - $(Get-Date-Format'yyyy-MM-dd HH:mm:ss')");[void]$s.AppendLine("#"*72)
    [void]$s.AppendLine("`n## REQUEST`n  Start: $($st.ToString('o'))`n  Method: $Method`n  URL: $Uri")
    if($Headers.Count-gt0){[void]$s.AppendLine("  Headers:");foreach($kv in $Headers.GetEnumerator()){[void]$s.AppendLine("    $($kv.Key): $($kv.Value)")}}
    if($Body){[void]$s.AppendLine("  Body:`n$Body")}
    [void]$s.AppendLine("`n## RESPONSE`n  End: $($et.ToString('o'))`n  Status: $hc`n  Content-Type: $rct`n  Size: $sd B`n  Time: $tt s`n`n## RESPONSE BODY`n$($cb)`n`n### END OF CAPTURE ###")
    $s.ToString()|Out-File $OutFile-Encoding utf8
    Write-Verbose"Captured $Method $Uri -> HTTP $hc ($tt s) -> $OutFile"
    return@{File=$OutFile;Method=$Method;Uri=$Uri;StatusCode=$hc;TimeTotal=$tt;StartTime=$st;EndTime=$et}
}

function Save-RequestResponse {
    <#
    .SYNOPSIS
        Saves HTTP request and response as separate text files with metadata.
    .DESCRIPTION
        Takes raw HTTP request and response text and saves them as individual .req.txt and
        .resp.txt files along with a .meta.json metadata file. Each file includes a header
        with capture timestamp, name, and redaction status. The metadata JSON contains the
        name, timestamps, file paths, and any additional metadata provided via the
        -Metadata parameter. This is the foundation for building an organized evidence tree.
    .PARAMETER RequestText
        Full raw HTTP request text including request line, headers, and body.
    .PARAMETER ResponseText
        Full raw HTTP response text including status line, headers, and body.
    .PARAMETER Name
        Base name for output files. Must match pattern: ^[a-zA-Z0-9_-]+$.
        Files will be named <Name>.req.txt, <Name>.resp.txt, <Name>.meta.json.
    .PARAMETER OutDir
        Directory where files will be saved. Created automatically if it does not exist.
    .PARAMETER Metadata
        Optional hashtable of additional metadata to include in the JSON file.
        Common keys: Url, VulnerabilityClass, Method, StatusCode.
    .EXAMPLE
        Save-RequestResponse -RequestText $req -ResponseText $resp -Name "idor-001" -OutDir "evidence\FIND-001\raw"
    .EXAMPLE
        Save-RequestResponse -RequestText $req -ResponseText $resp -Name "auth-bypass" `
            -OutDir "evidence\FIND-002\raw" -Metadata @{Url="https://api.target.com/admin";Method="GET"}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$RequestText,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResponseText,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Name,
        [Parameter(Mandatory)][ValidateScript({if(-not(Test-Path $_)){New-Item-ItemType Directory-Path $_-Force|Out-Null};$true})][string]$OutDir,
        [hashtable]$Metadata=@{}
    )
    if(-not(Test-Path $OutDir)){New-Item-ItemType Directory-Path $OutDir-Force|Out-Null}
    $ts=Get-Date-Format'yyyy-MM-dd HH:mm:ss.fff'
    $rq=Join-Path $OutDir"$Name.req.txt";$rp=Join-Path $OutDir"$Name.resp.txt";$mf=Join-Path $OutDir"$Name.meta.json"
    "# Request at $ts`r`n# Name: $Name`r`n# Redacted: NO`r`n$('-'*60)`r`n$RequestText"|Set-Content $rq-Encoding utf8-NoNewline
    "# Response at $ts`r`n# Name: $Name`r`n# Redacted: NO`r`n$('-'*60)`r`n$ResponseText"|Set-Content $rp-Encoding utf8-NoNewline
    $meta=@{Name=$Name;CapturedAt=$ts;RequestFile=$rq;ResponseFile=$rp}
    foreach($kv in $Metadata.GetEnumerator()){$meta[$kv.Key]=$kv.Value}
    $meta|ConvertTo-Json|Set-Content $mf-Encoding utf8
    Write-Verbose"Saved '$Name' to $OutDir"; return@{Name=$Name;RequestFile=$rq;ResponseFile=$rp;MetaFile=$mf}
}

function Redact-Cookies {
    <#
    .SYNOPSIS
        Removes or sanitizes cookie values from request/response files while preserving
        the HTTP header structure.
    .DESCRIPTION
        Processes evidence files and replaces cookie values with a configurable
        replacement string (default: [REDACTED]). Preserves the HTTP structure so that
        Cookie header names and Set-Cookie attribute names (Path, Domain, Secure, etc.)
        remain intact. Specifically:

          Request:  Cookie: session=abc123; csrf=xyz -> Cookie: session=[REDACTED]; csrf=[REDACTED]
          Response: Set-Cookie: token=secret; Path=/; HttpOnly -> Set-Cookie: token=[REDACTED]; Path=/; HttpOnly

        By default creates .redacted copies. Use -InPlace to overwrite originals
        (not recommended before review). Use -PassThru to pipe redacted content.
    .PARAMETER Path
        File path, array of paths, or wildcard pattern (e.g., "evidence\*.txt").
    .PARAMETER ReplaceWith
        Replacement string for cookie values. Default: [REDACTED].
    .PARAMETER InPlace
        Modify files in-place. By default, .redacted copies are created.
    .PARAMETER PassThru
        Output redacted content to the pipeline for further processing.
    .EXAMPLE
        Redact-Cookies -Path "evidence\FIND-001\raw\*.txt"
    .EXAMPLE
        Redact-Cookies -Path "capture.req.txt" -InPlace -PassThru | Set-Content "sanitized.txt"
    .INPUTS
        System.String[] - pipeline input of file paths
    .OUTPUTS
        System.String - redacted file content when -PassThru is specified
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string[]]$Path,
        [string]$ReplaceWith='[REDACTED]',[switch]$InPlace,[switch]$PassThru
    )
    process {
        foreach($item in $Path){
            $r=(Resolve-Path $item).Path;$c=Get-Content $r-Raw
            $c=[regex]::Replace($c,'(?im)^Cookie:\s*.+$',{$a=($_.Value-replace'(?im)^Cookie:\s*','').Trim();if(-not$a){return$_.Value};"Cookie: $(($a-split';\s*'|ForEach-Object{if($_-match'^([a-zA-Z0-9_%.-]+)=.*'){"$($matches[1])=$ReplaceWith"}else{$_}})-join'; ')"})
            $c=[regex]::Replace($c,'(?im)^Set-Cookie:\s*.+$',{$p=(($_.Value-replace'(?im)^Set-Cookie:\s*','').Trim())-split';\s*';"Set-Cookie: $(($p|ForEach-Object{if($_-match'^([a-zA-Z0-9_%.-]+)=(.+)$'){if($matches[1].ToLowerInvariant()-in@('path','domain','max-age','expires','samesite','secure','httponly')){$_}else{"$($matches[1])=$ReplaceWith"}}else{$_}})-join'; ')"})
            if($InPlace){$c|Set-Content $r-Encoding utf8-NoNewline}else{$o=[System.IO.Path]::ChangeExtension($r,'')+'.redacted'+[System.IO.Path]::GetExtension($r);$c|Set-Content $o-Encoding utf8-NoNewline}
            if($PassThru){$c}
        }
    }
}

function Redact-AuthHeaders {
    <#
    .SYNOPSIS
        Removes or sanitizes authentication/credential headers from evidence files.
    .DESCRIPTION
        Scans files for common authentication header patterns and replaces their values
        with [REDACTED] (or a custom replacement). Handles the following header names
        regardless of case: Authorization, X-Authorization, X-API-Key, Api-Key, ApiKey,
        X-Auth-Token, Auth-Token, Proxy-Authorization, Token, Bearer, JWT, Access-Token,
        X-Session-Token, Session-Token.

        By default creates .sanitized copies. Use -InPlace to overwrite originals.
    .PARAMETER Path
        File path, array of paths, or wildcard pattern.
    .PARAMETER InPlace
        Modify files in-place. By default, .sanitized copies are created.
    .PARAMETER PassThru
        Output redacted content to the pipeline.
    .PARAMETER ReplaceWith
        Replacement text for credential values. Default: [REDACTED].
    .EXAMPLE
        Redact-AuthHeaders -Path "evidence\*\raw\*.txt"
    .EXAMPLE
        Get-ChildItem "evidence\FIND-001\raw\*.txt" | Redact-AuthHeaders -InPlace -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string[]]$Path,
        [switch]$InPlace,[switch]$PassThru,[string]$ReplaceWith='[REDACTED]'
    )
    begin{$pats=@('(?im)^(Authorization|X-Authorization):\s*.+$','(?im)^(X-API-Key|Api-Key|API-Key|Apikey):\s*.+$','(?im)^(X-Auth-Token|Auth-Token):\s*.+$','(?im)^(Proxy-Authorization):\s*.+$','(?im)^(Token|Bearer):\s*.+$','(?im)^(X-Session-Token|Session-Token):\s*.+$','(?im)^(JWT|Access-Token):\s*.+$')}
    process {
        foreach($item in $Path){
            $r=(Resolve-Path $item).Path;$c=Get-Content $r-Raw
            foreach($pat in $pats){$c=[regex]::Replace($c,$pat,{"$(($_.Value-split':')[0]): $ReplaceWith"})}
            if($InPlace){$c|Set-Content $r-Encoding utf8-NoNewline}else{$o=[System.IO.Path]::ChangeExtension($r,'')+'.sanitized'+[System.IO.Path]::GetExtension($r);$c|Set-Content $o-Encoding utf8-NoNewline}
            if($PassThru){$c}
        }
    }
}

function Redact-Pii {
    <#
    .SYNOPSIS
        Masks personally identifiable information (PII) from evidence files.
    .DESCRIPTION
        Scans evidence files for common PII patterns and replaces them with masked
        equivalents. Helps ensure compliance with Bugcrowd/HackerOne PII redaction
        requirements before submission. Each masking category can be independently
        enabled or disabled.

        Email masking:  user@domain.com -> u***@domain.com (preserves first and last char of local part)
        Phone masking:  +1 (555) 123-4567 -> +*-***-***-4567 (preserves last 4 digits)
        IP masking:     192.168.1.1 -> [REDACTED-IP] (RFC 1918, loopback, link-local only)
        CC masking:     4111-1111-1111-1111 -> 4111-****-****-1111 (preserves first 4 and last 4)
        SSN masking:    123-45-6789 -> ***-**-6789 (preserves last 4 digits)
    .PARAMETER Path
        File path(s) — accepts wildcards.
    .PARAMETER InPlace
        Modify files in-place. Default creates .pii-redacted copies.
    .PARAMETER PassThru
        Output redacted content to pipeline.
    .PARAMETER MaskEmail
        Mask email addresses. Enabled by default.
    .PARAMETER MaskPhone
        Mask phone numbers. Enabled by default.
    .PARAMETER MaskInternalIP
        Mask internal IPs (RFC 1918, loopback, link-local). Enabled by default.
    .PARAMETER MaskCC
        Mask credit card numbers. Enabled by default.
    .PARAMETER MaskSSN
        Mask US Social Security Numbers. Enabled by default.
    .EXAMPLE
        Redact-Pii -Path "evidence\*\raw\*.txt"
    .EXAMPLE
        Redact-Pii -Path "capture.txt" -InPlace -MaskSSN $false -MaskCC $false
    .INPUTS
        System.String[]
    .OUTPUTS
        System.String when -PassThru is used
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string[]]$Path,
        [switch]$InPlace,[switch]$PassThru,
        [bool]$MaskEmail=$true,[bool]$MaskPhone=$true,[bool]$MaskInternalIP=$true,
        [bool]$MaskCC=$true,[bool]$MaskSSN=$true
    )
    process {
        foreach($item in $Path){
            $r=(Resolve-Path $item).Path;$c=Get-Content $r-Raw
            if($MaskEmail){$c=[regex]::Replace($c,'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',{$e=$_.Value;$i=$e.IndexOf('@');if($i-gt0){$e[0]+('*'*[math]::Max(0,$i-2))+$e[$i-1]+$e.Substring($i)}else{'[REDACTED-EMAIL]'}})}
            if($MaskPhone){$c=[regex]::Replace($c,'(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}(?:\s*(?:ext|x|xtn)\s*\d{1,5})?',{$p=$_.Value.Trim();if($p-match'\d{4}$'){$p.Substring(0,$p.Length-4)-replace'\d','*'+$matches[0]}else{'[REDACTED-PHONE]'}})}
            if($MaskInternalIP){$ips=@('\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b','\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b','\b192\.168\.\d{1,3}\.\d{1,3}\b','\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b','\b169\.254\.\d{1,3}\.\d{1,3}\.\d{1,3}\b');foreach($ip in $ips){$c=[regex]::Replace($c,$ip,'[REDACTED-IP]')}}
            if($MaskCC){$c=[regex]::Replace($c,'\b(?:\d{4}[-\s]?){3}\d{4}\b',{$d=$_.Value-replace'[-\s]','';if($d.Length-eq16){$d.Substring(0,4)+'-****-****-'+$d.Substring(12,4)}else{'[REDACTED-CC]'}})}
            if($MaskSSN){$c=[regex]::Replace($c,'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',{'***-**-'+$_.Value.Split('-')[2]})}
            if($InPlace){$c|Set-Content $r-Encoding utf8-NoNewline}else{$o=[System.IO.Path]::ChangeExtension($r,'')+'.pii-redacted'+[System.IO.Path]::GetExtension($r);$c|Set-Content $o-Encoding utf8-NoNewline}
            if($PassThru){$c}
        }
    }
}

function ConvertTo-Har {
    <#
    .SYNOPSIS
        Converts raw HTTP request/response text to HAR (HTTP Archive) format.
    .DESCRIPTION
        Parses raw HTTP request and response text strings and produces a valid HAR
        (HTTP Archive) JSON file. The HAR format is the preferred evidence format for
        both Bugcrowd and HackerOne submissions. Includes automatic parsing of the
        HTTP method and status code from the request/response lines if not explicitly
        provided.

        The generated HAR includes a single page + entry with full headers, body content,
        and timing information. Use Sanitize-HarFile afterwards to strip sensitive
        headers before submission.
    .PARAMETER RequestText
        Raw HTTP request text including the request line, headers, and body.
    .PARAMETER ResponseText
        Raw HTTP response text including the status line, headers, and body.
    .PARAMETER Url
        Full URL of the request (required for HAR format specification).
    .PARAMETER OutFile
        Path to save the generated .har file. Parent directory created if needed.
    .PARAMETER Method
        HTTP method. Auto-parsed from RequestText if omitted.
    .PARAMETER ResponseCode
        HTTP status code. Auto-parsed from ResponseText if 0.
    .PARAMETER StartTime
        Optional start timestamp for the request. Defaults to current time.
    .PARAMETER EndTime
        Optional end timestamp for the response. Defaults to current time.
    .EXAMPLE
        ConvertTo-Har -RequestText $req -ResponseText $resp -Url "https://api.target.com/user" -OutFile "evidence\capture.har"
    .EXAMPLE
        Get-Content "raw.req.txt" -Raw | ConvertTo-Har -ResponseText $resp -Url $url -OutFile "evidence\capture.har"
    .OUTPUTS
        Hashtable representing the full HAR structure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string]$RequestText,
        [Parameter(Mandatory)][string]$ResponseText,[Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile,[string]$Method='',[int]$ResponseCode=0,
        [datetime]$StartTime=(Get-Date),[datetime]$EndTime=(Get-Date)
    )
    $rl=$RequestText-split"`r`n|`n";$rs=$ResponseText-split"`r`n|`n"
    if(-not$Method-and$rl.Count-gt0-and$rl[0]-match'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s'){$Method=$matches[1]}
    if($ResponseCode-eq0-and$rs.Count-gt0-and$rs[0]-match'HTTP/[\d.]+ (\d{3})'){$ResponseCode=[int]$matches[1]}
    function ph($l){$h=@();$b=$false;for($i=1;$i-lt$l.Count;$i++){if(-not$l[$i].Trim()){$b=$true;continue}if(-not$b-and$l[$i]-match'^([^:]+):\s*(.*)'){$h+=@{name=$matches[1];value=$matches[2]}}};return$h}
    function pb($l){$b='';$x=$false;for($i=1;$i-lt$l.Count;$i++){if(-not$l[$i].Trim()){$x=$true;continue}if($x){$b+="$($l[$i])`r`n"}};return$b.TrimEnd("`r`n")}
    $qh=ph $rl;$rh=ph $rs;$qb=pb $rl;$rb=pb $rs;$bs=if($qb){[Text.Encoding]::UTF8.GetByteCount($qb)}else{0};$rbs=if($rb){[Text.Encoding]::UTF8.GetByteCount($rb)}else{0}
    $ct=($qh|Where-Object{$_.name-eq'Content-Type'}).value;$rct=($rh|Where-Object{$_.name-ieq'Content-Type'}).value
    $od=Split-Path $OutFile-Parent;if($od-and-not(Test-Path $od)){New-Item-ItemType Directory-Path $od-Force|Out-Null}
    $pdObj=if($bs-gt0){@{mimeType=if($ct){$ct}else{'application/octet-stream'};text=$qb}}else{$null}
    $stText=if($rs.Count-gt0){($rs[0]-split' ',3)[2]}else{''}
    $rctVal=if($rct){$rct}else{'application/octet-stream'}
    $timings=@{send=0;wait=[math]::Max(0,($EndTime-$StartTime).TotalMilliseconds);receive=0}
    $reqObj=@{method=$Method;url=$Url;httpVersion='HTTP/1.1';headers=$qh;queryString=@();cookies=@();headersSize=-1;bodySize=$bs;postData=$pdObj}
    $respObj=@{status=$ResponseCode;statusText=$stText;httpVersion='HTTP/1.1';headers=$rh;cookies=@();content=@{size=$rbs;mimeType=$rctVal;text=$rb};redirectURL='';headersSize=-1;bodySize=$rbs}
    $entryObj=@{pageref='page_1';startedDateTime=$StartTime.ToString('o');time=[math]::Max(0,($EndTime-$StartTime).TotalMilliseconds);request=$reqObj;response=$respObj;cache=@{};timings=$timings}
    $pageObj=@{startedDateTime=$StartTime.ToString('o');id='page_1';title='Evidence';pageTimings=@{onContentLoad=-1;onLoad=-1}}
    $har=@{log=@{version='1.2';creator=@{name='evidence-toolkit';version='1.0.0'};pages=@($pageObj);entries=@($entryObj)}}
    $har|ConvertTo-Json-Depth 10|Set-Content $OutFile-Encoding utf8;Write-Verbose"HAR: $OutFile";return$har
}

function New-EvidenceFolder {
    <#
    .SYNOPSIS
        Creates standardized evidence folder structure: raw/ redacted/ screenshots/ har/ report/.
    .PARAMETER BaseDir Root directory for evidence.
    .PARAMETER FindingId Unique identifier (e.g., "FIND-001").
    .PARAMETER PassThru Return folder paths as hashtable.
    .EXAMPLE
        New-EvidenceFolder -BaseDir "evidence" -FindingId "FIND-001" -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$FindingId,
        [switch]$PassThru
    )
    $fd=Join-Path $BaseDir $FindingId
    $dirs=@{RawDir=Join-Path $fd 'raw';RedactedDir=Join-Path $fd 'redacted';ScreenshotsDir=Join-Path $fd 'screenshots';HarDir=Join-Path $fd 'har';ReportDir=Join-Path $fd 'report'}
    New-Item-ItemType Directory-Path $fd-Force|Out-Null
    foreach($d in $dirs.Values){New-Item-ItemType Directory-Path $d-Force|Out-Null}
"# Evidence Folder: $FindingId
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
- raw/          Unredacted captures (DO NOT commit/upload)
- redacted/     Redacted evidence for submission
- screenshots/  PNG screenshots
- har/          HAR format files
- report/       Finding records and reports
"|Set-Content(Join-Path $fd 'README.md')-Encoding utf8
    Write-Verbose "Created $fd"
    if($PassThru){$dirs.FindingDir=$fd;return$dirs}
}

function Save-Screenshot {
    <#
    .SYNOPSIS
        Organizes screenshot with naming: <FindingId>_<Step>_<Description>.png.
    .PARAMETER SourcePath Source screenshot file.
    .PARAMETER EvidenceDir Screenshots directory.
    .PARAMETER FindingId Finding ID prefix.
    .PARAMETER StepNumber Sequential step (default: 1).
    .PARAMETER Description Short kebab-case description.
    .PARAMETER Move Move instead of copy.
    .EXAMPLE
        Save-Screenshot -SourcePath "C:\temp\s1.png" -EvidenceDir "ev\FIND-001\screenshots" -FindingId "FIND-001" -Step 1 -Description "burp-request"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,[Parameter(Mandatory)][string]$EvidenceDir,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$FindingId,
        [ValidateRange(1,999)][int]$StepNumber=1,
        [ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$Description='screenshot',[switch]$Move
    )
    $ext=[System.IO.Path]::GetExtension($SourcePath);if(-not$ext){$ext='.png'}
    $dest=Join-Path $EvidenceDir"${FindingId}_${StepNumber}_${Description}$ext"
    if($Move){Move-Item $SourcePath $dest-Force}else{Copy-Item $SourcePath $dest-Force}
    Write-Verbose"Screenshot -> $dest";return$dest
}

function New-FindingRecord {
    <#
    .SYNOPSIS
        Creates a finding record JSON with all metadata for submission reference.
    .DESCRIPTION
        Generates a structured JSON record containing all metadata about a finding:
        identifier, title, description, severity, CVSS score, affected endpoints,
        evidence file references, timestamps, and submission status. This record serves
        as the single source of truth for the finding's evidence trail and is consumed
        by Export-FindingReport and Test-EvidencePackage for validation and reporting.

        The output JSON includes:
          - FindingId, Title, Severity, CvssScore
          - Description, AffectedEndpoints, VulnerabilityClass
          - EvidenceFiles array with paths to all related files
          - Status (defaults to "unsubmitted")
          - CreatedAt and UpdatedAt timestamps
          - Toolkit and version tracking
          - Any additional metadata provided via -AdditionalMetadata
    .PARAMETER FindingId
        Unique identifier for the finding. Must match: ^[a-zA-Z0-9_-]+$.
    .PARAMETER Title
        Short descriptive title of the vulnerability (e.g., "IDOR in User Profile Endpoint").
    .PARAMETER Severity
        CVSS severity rating: Critical, High, Medium, Low, or Info.
    .PARAMETER CvssScore
        CVSS 3.1 vector string or numeric score (e.g., "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N").
    .PARAMETER Description
        Detailed description of the finding including impact and vulnerable functionality.
    .PARAMETER AffectedEndpoint
        One or more affected URL strings.
    .PARAMETER VulnerabilityClass
        Vulnerability classification (e.g., IDOR, XSS, SSRF, SQLi, RCE, AuthBypass).
    .PARAMETER EvidenceFiles
        Array of file paths to evidence files. Supports both absolute and relative paths.
    .PARAMETER OutFile
        Full path to save the JSON finding record file.
    .PARAMETER AdditionalMetadata
        Optional hashtable of custom metadata fields to include in the record.
    .EXAMPLE
        New-FindingRecord -FindingId "IDOR-001" -Title "IDOR in User Profile" `
            -Severity High -OutFile "evidence\IDOR-001\report\finding-record.json"
    .EXAMPLE
        New-FindingRecord -FindingId "XSS-002" -Title "Stored XSS in Comment Field" `
            -Severity Medium -CvssScore "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N" `
            -AffectedEndpoint "POST /api/comments" -VulnerabilityClass "XSS" `
            -EvidenceFiles @("raw1.req.txt","raw2.req.txt") -OutFile "record.json" `
            -AdditionalMetadata @{Subdomain="app.target.com";WafDetected=$false}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$FindingId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [string]$CvssScore='',[string]$Description='',[string[]]$AffectedEndpoint=@(),
        [string]$VulnerabilityClass='',[string[]]$EvidenceFiles=@(),
        [Parameter(Mandatory)][string]$OutFile,[hashtable]$AdditionalMetadata=@{}
    )
    $r=@{FindingId=$FindingId;Title=$Title;Severity=$Severity;CvssScore=$CvssScore;Description=$Description
        AffectedEndpoints=$AffectedEndpoint;VulnerabilityClass=$VulnerabilityClass;EvidenceFiles=$EvidenceFiles
        Status='unsubmitted';CreatedAt=(Get-Date-Format'yyyy-MM-dd HH:mm:ss.fff');UpdatedAt=(Get-Date-Format'yyyy-MM-dd HH:mm:ss.fff')
        Toolkit='evidence-toolkit.ps1';ToolkitVersion='1.0.0'}
    foreach($kv in $AdditionalMetadata.GetEnumerator()){$r[$kv.Key]=$kv.Value}
    $p=Split-Path $OutFile-Parent;if($p-and-not(Test-Path $p)){New-Item-ItemType Directory-Path $p-Force|Out-Null}
    $r|ConvertTo-Json-Depth 5|Set-Content $OutFile-Encoding utf8;Write-Verbose"Record: $OutFile";return$r
}

function Export-FindingReport {
    <#
    .SYNOPSIS
        Generates finding report markdown from record JSON and evidence files.
    .PARAMETER FindingRecordPath Path to finding-record.json.
    .PARAMETER OutFile Output .md path.
    .PARAMETER IncludeRawEvidence Inline raw evidence in report.
    .EXAMPLE
        Export-FindingReport -FindingRecordPath "evidence\FIND-001\report\finding-record.json" -OutFile "evidence\FIND-001\report\report.md"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FindingRecordPath,
        [Parameter(Mandatory)][string]$OutFile,[switch]$IncludeRawEvidence
    )
    $rec=Get-Content $FindingRecordPath-Raw|ConvertFrom-Json;$fd=Split-Path(Split-Path $FindingRecordPath-Parent)-Parent
    $ev='';$ct=1
    $ef=if($rec.EvidenceFiles-is[array]){$rec.EvidenceFiles}elseif($rec.EvidenceFiles){@($rec.EvidenceFiles)}else{@()}
    foreach($f in $ef){
        $fp=if([System.IO.Path]::IsPathRooted($f)){$f}else{Join-Path $fd $f}
        $n=Split-Path $f-Leaf
        if(Test-Path $fp){
            $ev+="$ct. **$n** - $f`r`n"
            if($IncludeRawEvidence){
                $c=Get-Content $fp-Raw
                if($c.Length-gt5000){$ev+="   ($($c.Length) bytes, truncated)`r`n"}
                else{$ev+="   ```r`n$c`r`n   ```r`n"}
            }
        }else{$ev+="$ct. **$f** - (missing)`r`n"}
        $ct++
    }
    $ss=Join-Path $fd 'screenshots'
    if(Test-Path $ss){Get-ChildItem $ss-Filter'*.png'|ForEach-Object{$ev+="$ct. Screenshot: $($_.Name)`r`n";$ct++}}
    $ep=if($rec.AffectedEndpoints-is[array]){$rec.AffectedEndpoints -join ', '}else{$rec.AffectedEndpoints}
    $r=@"
# $($rec.Title)
## Summary
- **ID:** $($rec.FindingId) | **Severity:** $($rec.Severity) | **CVSS:** $($rec.CvssScore)
- **Class:** $($rec.VulnerabilityClass) | **Endpoints:** $ep | **Status:** $($rec.Status)
## Description
$($rec.Description)
## Steps to Reproduce
1. Authenticate as a standard user. 2. Navigate to the affected endpoint.
3. Capture the request and modify parameters as described. 4. Observe the response confirming the vulnerability.
## Impact
An attacker could exploit this vulnerability to compromise confidentiality, integrity, or availability.
## Remediation
Implement proper access controls, validate user-supplied input, and follow security best practices.
## Evidence
$ev
"@
    $od=Split-Path $OutFile-Parent;if($od-and-not(Test-Path $od)){New-Item-ItemType Directory-Path $od-Force|Out-Null}
    $r|Set-Content $OutFile-Encoding utf8;Write-Verbose"Report: $OutFile";return$r
}

function Test-EvidencePackage {
    <#
    .SYNOPSIS
        Verifies an evidence package: checks all files exist, scans for unredacted secrets,
        validates HAR format and PNG integrity.
    .DESCRIPTION
        Runs comprehensive validation on an evidence package before submission. The function
        reads the finding record JSON and walks all referenced evidence files plus any
        additional files found in the har/ and redacted/ subdirectories. For each file it:

          - Checks the file exists on disk
          - Validates HAR files are valid JSON with proper structure (log.entries)
          - Scans for unredacted Cookie values using heuristic pattern matching
          - Scans for unredacted Authorization, X-Auth-Token, X-API-Key headers
          - Scans for unredacted email addresses (PII)
          - Validates PNG files using magic byte signature (89 50 4E 47)

        Returns a detailed results object when -PassThru is specified, with separate
        Issues (blocking) and Warnings (advisory) arrays.
    .PARAMETER FindingRecordPath
        Path to the finding record JSON file created by New-FindingRecord.
    .PARAMETER PassThru
        Switch to return a detailed results object with Issues, Warnings, and file counts.
    .EXAMPLE
        Test-EvidencePackage -FindingRecordPath "evidence\FIND-001\report\finding-record.json" -Verbose
    .EXAMPLE
        $results = Test-EvidencePackage -FindingRecordPath "evidence\FIND-001\report\finding-record.json" -PassThru
        if ($results.Issues.Count -gt 0) { $results.Issues | ForEach-Object { Write-Error $_ } }
    .OUTPUTS
        Hashtable with keys: Passed (bool), FindingId, FilesChecked, Issues (string[]), Warnings (string[])
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateScript({Test-Path $_})][string]$FindingRecordPath,[switch]$PassThru
    )
    $res=@{Passed=$true;FindingId='';FilesChecked=0;Issues=@();Warnings=@()}
    $rec=Get-Content $FindingRecordPath-Raw|ConvertFrom-Json;$res.FindingId=$rec.FindingId
    $fd=Split-Path(Split-Path $FindingRecordPath-Parent)-Parent
    $ef=if($rec.EvidenceFiles-is[array]){$rec.EvidenceFiles}elseif($rec.EvidenceFiles){@($rec.EvidenceFiles)}else{@()}
    $hd=Join-Path $fd 'har';if(Test-Path $hd){$ef+=(Get-ChildItem $hd-Filter'*.har').FullName}
    $rd=Join-Path $fd 'redacted';if(Test-Path $rd){$ef+=(Get-ChildItem $rd-File).FullName}
    foreach($f in $ef){$fp=if([System.IO.Path]::IsPathRooted($f)){$f}else{Join-Path $fd $f};$res.FilesChecked++
        if(-not(Test-Path $fp)){$res.Passed=$false;$res.Issues+="[MISSING] $f";continue}
        $c=Get-Content $fp-Raw;if(-not$c){continue}
        $ext=[System.IO.Path]::GetExtension($fp).ToLowerInvariant()
        if($ext-eq'.har'){try{$h=$c|ConvertFrom-Json;if(-not$h.log-or-not$h.log.entries){$res.Warnings+="[HAR-INVALID] $f"}}catch{$res.Passed=$false;$res.Issues+="[HAR-JSON] ${f}: $($_.Exception.Message)"}}
        if($c-match'(?i)Cookie:\s*[a-zA-Z0-9_%.-]+=[^R][^E][^D][^A][^C][^T][^E][^D]'){$res.Warnings+="[COOKIE] $f"}
        if($c-match'(?im)^(Authorization|X-Auth-Token|X-API-Key|Api-Key):\s*(?!\[REDACTED\])\S+'){$res.Warnings+="[AUTH] $f"}
        if($c-match'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'){$res.Warnings+="[PII-EMAIL] $f"}
        if($ext-in'.png','.PNG'){$b=[System.IO.File]::ReadAllBytes($fp);if($b.Length-lt8-or$b[0]-ne0x89-or$b[1]-ne0x50-or$b[2]-ne0x4E-or$b[3]-ne0x47){$res.Warnings+="[PNG] $f"}}}
    if($res.Issues.Count-eq0-and$res.Warnings.Count-eq0){Write-Verbose"PASSED for $($rec.FindingId)"}
    elseif($res.Issues.Count-eq0){Write-Warning"PASSED with $($res.Warnings.Count) warnings for $($rec.FindingId)"}
    else{Write-Warning"FAILED with $($res.Issues.Count) issues for $($rec.FindingId)"}
    if($PassThru){return$res}
}

function Compress-EvidencePackage {
    <#
    .SYNOPSIS
        ZIPs evidence folder for upload, excluding raw/ by default.
    .PARAMETER FindingDir Finding evidence folder path.
    .PARAMETER OutFile Output ZIP path (default: <parent>\<FindingDir>-submission.zip).
    .PARAMETER IncludeRaw Include raw unredacted files.
    .PARAMETER Level Compression level 0-9 (default 5).
    .EXAMPLE
        Compress-EvidencePackage -FindingDir "evidence\FIND-001"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FindingDir,[string]$OutFile='',
        [switch]$IncludeRaw,[ValidateRange(0,9)][int]$Level=5
    )
    if(-not$OutFile){$OutFile=Join-Path(Split-Path $FindingDir-Parent)"$(Split-Path $FindingDir-Leaf)-submission.zip"}
    if(Test-Path $OutFile){Remove-Item $OutFile-Force}
    $excl=if(-not$IncludeRaw){@((Join-Path $FindingDir'raw')+'\*')}else{@()}
    if($PSVersionTable.PSVersion.Major-ge5){Compress-Archive-Path $FindingDir-DestinationPath $OutFile-CompressionLevel $Level-ExcludePath $excl}
    else{
        Add-Type-AssemblyName System.IO.Compression.FileSystem
        $z=[System.IO.Compression.ZipFile]::Open($OutFile,[System.IO.Compression.ZipArchiveMode]::Create)
        try{Get-ChildItem $FindingDir-Recurse-File|Where-Object{$_.DirectoryName-notmatch'\\raw(\\|$)'}|ForEach-Object{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z,$_.FullName,$_.FullName.Substring($FindingDir.Length+1),$Level)|Out-Null}}finally{$z.Dispose()}}
    $zi=Get-Item $OutFile;Write-Verbose"Package: $OutFile ($($zi.Length) bytes)";return$zi
}

function New-CurlToHar {
    <#
    .SYNOPSIS
        Parses a curl command string and converts it to a HAR format entry.
    .DESCRIPTION
        Takes a curl command string (e.g., from Burp or browser dev tools "Copy as cURL")
        and generates a corresponding HAR entry JSON file. Useful for documenting
        proof-of-concept curl commands in reports where a full request/response capture
        is unnecessary.

        Supports parsing: -X/--request, -H/--header, -d/--data, --data-raw, -b/--cookie,
        --cookie, -u/--user, -A/--user-agent, -F/--form, and the URL as a positional argument.
        Includes optional response body and headers to create a complete HAR entry.
    .PARAMETER CurlCommand
        The curl command string to parse (e.g., 'curl -X POST -H "Content-Type: application/json" -d "{}" https://api.example.com/endpoint').
    .PARAMETER OutFile
        Path to save the generated HAR entry JSON file.
    .PARAMETER Url
        Optional explicit URL override. If not provided, extracted from the curl command.
    .PARAMETER Method
        Optional explicit HTTP method override. Auto-detected from -X flag if not provided.
    .PARAMETER StatusCode
        Expected or observed HTTP status code for the response. Default: 200.
    .PARAMETER ResponseBody
        Optional response body text to include in the HAR entry.
    .PARAMETER ResponseHeaders
        Optional raw response headers string to include in the HAR entry.
    .EXAMPLE
        New-CurlToHar -CurlCommand 'curl -X POST -H "Authorization: Bearer token" -d "{\"user\":\"1\"}" https://api.target.com/admin' -OutFile "poc.har"
    .EXAMPLE
        New-CurlToHar -CurlCommand 'curl "https://api.target.com/public"' -OutFile "simple.har" -StatusCode 200 -ResponseBody '{"ok":true}'
    .OUTPUTS
        Hashtable representing the full HAR structure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CurlCommand,[Parameter(Mandatory)][string]$OutFile,
        [string]$Url='',[string]$Method='GET',[int]$StatusCode=200,
        [string]$ResponseBody='',[string]$ResponseHeaders=''
    )
    $hdr=@();$bd='';$ck='';$tks=@();$cur='';$sq=$false;$dq=$false
    $cmd=$CurlCommand.Trim()-replace'^curl\s+',''
    for($i=0;$i-lt$cmd.Length;$i++){$ch=$cmd[$i];if($ch-eq"'"-and-not$dq){$sq=-not$sq;continue}if($ch-eq'"'-and-not$sq){$dq=-not$dq;continue}if($ch-match'\s'-and-not$sq-and-not$dq){if($cur){$tks+=$cur;$cur=''};continue}$cur+=$ch}
    if($cur){$tks+=$cur}
    for($i=0;$i-lt$tks.Count;$i++){$t=$tks[$i];$l=$t.ToLowerInvariant()
        if($l-in@('-x','--request')){$i++;$Method=$tks[$i]}
        elseif($l-in@('-h','--header')){$i++;if($tks[$i]-match'^([^:]+):\s*(.*)'){$hdr+=@{name=$matches[1];value=$matches[2]}}}
        elseif($l-in@('-d','--data','--data-raw')){$i++;$bd=$tks[$i]}
        elseif($l-in@('-b','--cookie')){$i++;$ck=$tks[$i]}
        elseif($t-notlike'-*'-and$t-match'^https?://'){$Url=$t}}
    if($ck-and-not($hdr|Where-Object{$_.name-ieq'Cookie'})){$hdr+=@{name='Cookie';value=$ck}}
    $bs=if($bd){[Text.Encoding]::UTF8.GetByteCount($bd)}else{0};if($bd-and$Method-eq'GET'){$Method='POST'}
    $rh=@();if($ResponseHeaders){($ResponseHeaders-split"`r`n|`n")|Where-Object{$_-match'^([^:]+):\s*(.*)'}|ForEach-Object{$rh+=@{name=$matches[1];value=$matches[2]}}}
    $now=(Get-Date).ToString('o')
    $p=Split-Path $OutFile-Parent;if($p-and-not(Test-Path $p)){New-Item-ItemType Directory-Path $p-Force|Out-Null}
    $ctVal=if($hdr|Where-Object{$_.name-eq'Content-Type'}){($hdr|Where-Object{$_.name-eq'Content-Type'}).value}else{'application/octet-stream'}
    $rctVal=if($rh|Where-Object{$_.name-ieq'Content-Type'}){($rh|Where-Object{$_.name-ieq'Content-Type'}).value}else{'application/octet-stream'}
    $respSize=if($ResponseBody){[Text.Encoding]::UTF8.GetByteCount($ResponseBody)}else{0}
    $pdObj=if($bs-gt0){@{mimeType=$ctVal;text=$bd}}else{$null}
    $reqObj=@{method=$Method;url=$Url;httpVersion='HTTP/1.1';headers=$hdr;queryString=@();cookies=@();headersSize=-1;bodySize=$bs;postData=$pdObj}
    $respContent=@{size=$respSize;mimeType=$rctVal;text=$ResponseBody}
    $respObj=@{status=$StatusCode;statusText='';httpVersion='HTTP/1.1';headers=$rh;cookies=@();content=$respContent;redirectURL='';headersSize=-1;bodySize=$respSize}
    $entryObj=@{pageref='page_1';startedDateTime=$now;time=0;request=$reqObj;response=$respObj;cache=@{};timings=@{send=0;wait=0;receive=0}}
    $pageObj=@{startedDateTime=$now;id='page_1';title='Curl PoC';pageTimings=@{onContentLoad=-1;onLoad=-1}}
    $har=@{log=@{version='1.2';creator=@{name='evidence-toolkit';version='1.0.0'};pages=@($pageObj);entries=@($entryObj)}}
    $har|ConvertTo-Json-Depth 10|Set-Content $OutFile-Encoding utf8;Write-Verbose"Curl->HAR: $OutFile";return$har
}

function Sanitize-HarFile {
    <#
    .SYNOPSIS
        Reads a HAR file and strips Cookie, Set-Cookie, Authorization, and other
        sensitive headers, then outputs a sanitized version.
    .DESCRIPTION
        Processes a HAR JSON file by walking all entries and replacing sensitive header
        and cookie values with [REDACTED]. This is the recommended way to prepare HAR
        files for Bugcrowd/HackerOne submission. The JSON structure is preserved.

        Stripped request headers: Cookie, Authorization, Proxy-Authorization, X-API-Key,
        Api-Key, X-Auth-Token, Token, Bearer.
        Stripped response headers: Set-Cookie, Set-Cookie2, Authorization,
        WWW-Authenticate, Proxy-Authenticate.
        All cookie objects in both request and response have their value field redacted.
    .PARAMETER Path
        Path to the HAR file to sanitize.
    .PARAMETER OutFile
        Path to save the sanitized HAR file. If not specified, uses <name>.sanitized.har.
    .PARAMETER InPlace
        Switch to overwrite the original file (not recommended; use -OutFile instead).
    .PARAMETER PassThru
        Switch to return the sanitized JSON content as a string.
    .EXAMPLE
        Sanitize-HarFile -Path "evidence\capture.har" -OutFile "evidence\capture.sanitized.har"
    .EXAMPLE
        Sanitize-HarFile -Path "evidence\capture.har" -InPlace -PassThru | Out-File "backup.txt"
    .OUTPUTS
        System.String (JSON) when -PassThru is specified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline)][string]$Path,
        [string]$OutFile='',[switch]$InPlace,[switch]$PassThru
    )
    $har=Get-Content $Path-Raw|ConvertFrom-Json
    foreach($e in $har.log.entries){
        if($e.request.headers){foreach($h in $e.request.headers){if($h.name.ToLowerInvariant()-in@('cookie','authorization','proxy-authorization','x-api-key','api-key','x-auth-token','token','bearer')){$h.value='[REDACTED]'}}}
        if($e.request.cookies){foreach($c in $e.request.cookies){$c.value='[REDACTED]'}}
        if($e.response.headers){foreach($h in $e.response.headers){if($h.name.ToLowerInvariant()-in@('set-cookie','set-cookie2','authorization','www-authenticate','proxy-authenticate')){$h.value='[REDACTED]'}}}
        if($e.response.cookies){foreach($c in $e.response.cookies){$c.value='[REDACTED]'}}}
    $json=$har|ConvertTo-Json-Depth 10
    if($InPlace){$json|Set-Content $Path-Encoding utf8;Write-Verbose"In-place: $Path"}
    elseif($OutFile){$d=Split-Path $OutFile-Parent;if($d-and-not(Test-Path $d)){New-Item-ItemType Directory-Path $d-Force|Out-Null};$json|Set-Content $OutFile-Encoding utf8;Write-Verbose"-> $OutFile"}
    else{$o=[System.IO.Path]::GetFileNameWithoutExtension($Path)+'.sanitized.har';$json|Set-Content(Join-Path(Split-Path $Path-Parent)$o)-Encoding utf8;Write-Verbose"-> $o"}
    if($PassThru){return$json}
}

function Generate-PoCDescription {
    <#
    .SYNOPSIS
        Reads request and response evidence files and generates a human-readable
        proof-of-concept description for inclusion in bug bounty reports.
    .DESCRIPTION
        Analyzes HTTP request and response files and produces a structured markdown
        description including the HTTP method, path, status code, and vulnerability
        context. The description is tailored to the specified vulnerability type with
        appropriate language (e.g., "by modifying an identifier to access another
        user's resource" for IDOR). Optionally includes the response body (truncated).

        The output contains these sections:
          - Proof of Concept (with vulnerability-type-specific explanation)
          - Request details (method and path)
          - Response details (HTTP status code)
          - Response body (optional, with configurable max length)
          - Analysis of the observed behavior
    .PARAMETER RequestFile
        Path to the HTTP request text file (.req.txt).
    .PARAMETER ResponseFile
        Path to the HTTP response text file (.resp.txt).
    .PARAMETER VulnerabilityType
        Type of vulnerability. Supported: IDOR, XSS, SSRF, SQLi, RCE, LFI,
        AuthBypass, CSRF, SSTI, OpenRedirect, Other.
    .PARAMETER IncludeBody
        Switch to include the response body in the description.
    .PARAMETER MaxBodyLength
        Maximum characters of the response body to include. Default: 500.
    .EXAMPLE
        $desc = Generate-PoCDescription -RequestFile "raw\id1.req.txt" -ResponseFile "raw\id1.resp.txt" -VulnerabilityType "IDOR"
    .EXAMPLE
        Generate-PoCDescription -RequestFile "xss.req.txt" -ResponseFile "xss.resp.txt" -VulnerabilityType "XSS" -IncludeBody 300
    .OUTPUTS
        Hashtable with keys: Description (markdown string), Method, Path, StatusCode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RequestFile,[Parameter(Mandatory)][string]$ResponseFile,
        [ValidateSet('IDOR','XSS','SSRF','SQLi','RCE','LFI','AuthBypass','CSRF','SSTI','OpenRedirect','Other')][string]$VulnerabilityType='Other',
        [switch]$IncludeBody,[ValidateRange(50,10000)][int]$MaxBodyLength=500
    )
    $rl=Get-Content $RequestFile-Raw;$rs=Get-Content $ResponseFile-Raw
    $reqL=(($rl-split"`r`n|`n")|Where-Object{$_-match'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+'}|Select-Object-First 1)
    $m='';$p='';if($reqL-match'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)'){$m=$matches[1];$p=$matches[2]}
    $st=(($rs-split"`r`n|`n")|Where-Object{$_-match'^HTTP/'}|Select-Object-First 1);$c=if($st-match'HTTP/[\d.]+\s+(\d{3})'){$matches[1]}else{''}
    $acts=@{IDOR='by modifying an identifier to access another user resource';XSS='by injecting a script payload into the browser';SSRF='by making the server request internal addresses';SQLi='by injecting SQL commands';RCE='by executing commands on the server';LFI='by reading arbitrary server files';AuthBypass='by bypassing authentication controls';CSRF='by forging a cross-site request';SSTI='by injecting template expressions';OpenRedirect='by redirecting users to an attacker domain';Other='by exploiting a security vulnerability'}
    $act=if($acts.ContainsKey($VulnerabilityType)){$acts[$VulnerabilityType]}else{$acts['Other']}
    $sb=[System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("## Proof of Concept`nThe vulnerability is demonstrated $act.:`n### Request`n**$m $p**`n### Response`n**Status:** $c`n")
    if($IncludeBody){$ib=$false;$bp=@();foreach($l in($rs-split"`r`n|`n")){if($ib){$bp+=$l}elseif($l.Trim()-eq''){$ib=$true}};$b=$bp-join"`r`n";if($b.Length-gt$MaxBodyLength){$b=$b.Substring(0,$MaxBodyLength)+"... (truncated)"};[void]$sb.AppendLine("Response body:`n````n$b`n````n")}
    [void]$sb.AppendLine("### Analysis`nThe $m request to `$p` returned HTTP $c, confirming the vulnerability.")
    return@{Description=$sb.ToString();Method=$m;Path=$p;StatusCode=$c}
}

function Invoke-FullEvidencePipeline {
    <#
    .SYNOPSIS
        Runs the full evidence pipeline: save raw -> generate HAR -> redact -> create
        finding record -> validate -> (optional) compress.
    .DESCRIPTION
        Orchestrates the complete evidence workflow for a finding in a single call.
        Given raw request and response text, the pipeline:

          1. Creates standardized folder structure (raw/, redacted/, har/, report/, screenshots/)
          2. Saves raw request/response as .req.txt / .resp.txt / .meta.json
          3. Generates a HAR file from the request/response pair
          4. Redacts cookies, auth headers, and PII from all files (unless -SkipRedact)
          5. Sanitizes the HAR file (strips Cookie/Set-Cookie/Authorization headers)
          6. Creates a finding record JSON with all metadata
          7. Validates the entire evidence package
          8. Optionally compresses to ZIP for upload

        This is the primary entry point for most workflows. For finer control over
        individual steps, use the component functions directly.
    .PARAMETER RequestText
        Raw HTTP request text. Should include request line, headers, and body.
    .PARAMETER ResponseText
        Raw HTTP response text. Should include status line, headers, and body.
    .PARAMETER Url
        Full URL of the request (required for HAR generation).
    .PARAMETER FindingId
        Unique identifier for this finding. Must match: ^[a-zA-Z0-9_-]+$.
    .PARAMETER BaseDir
        Base directory for evidence storage. Finding subfolder created automatically.
    .PARAMETER Title
        Optional title for the finding record. Auto-generated if omitted.
    .PARAMETER Severity
        Severity rating. Default: Medium.
    .PARAMETER VulnerabilityClass
        Vulnerability classification (e.g., IDOR, XSS, SSRF, SQLi).
    .PARAMETER Compress
        Switch to create a ZIP archive of the evidence folder after processing.
    .PARAMETER SkipRedact
        Switch to skip automatic redaction (not recommended for submission-ready packages).
    .EXAMPLE
        $result = Invoke-FullEvidencePipeline -RequestText $req -ResponseText $resp `
            -Url "https://api.target.com/data" -FindingId "IDOR-002" `
            -BaseDir "evidence" -Severity "High" -VulnerabilityClass "IDOR" -Compress
    .EXAMPLE
        $req = Get-Content "request.txt" -Raw
        $resp = Get-Content "response.txt" -Raw
        Invoke-FullEvidencePipeline -RequestText $req -ResponseText $resp `
            -Url "https://example.com/api/admin" -FindingId "XSS-001" -BaseDir "evidence" -Compress
    .OUTPUTS
        Hashtable with keys: FindingId, EvidenceDirs, SavedFiles, HarFile, RecordFile, Validation[, ZipFile]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$RequestText,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResponseText,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Url,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$FindingId,
        [Parameter(Mandatory)][string]$BaseDir,
        [string]$Title='',[ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity='Medium',
        [string]$VulnerabilityClass='',[switch]$Compress,[switch]$SkipRedact
    )
    Write-Host"=== Pipeline: $FindingId ==="-ForegroundColor Cyan
    $dirs=New-EvidenceFolder-BaseDir $BaseDir-FindingId $FindingId-PassThru
    Write-Host"[1/5] Saving raw..."-ForegroundColor Yellow
    $saved=Save-RequestResponse-RequestText $RequestText-ResponseText $ResponseText-Name "${FindingId}_capture"-OutDir $dirs['RawDir']-Metadata@{Url=$Url;VulnerabilityClass=$VulnerabilityClass}
    Write-Host"[2/5] Generating HAR..."-ForegroundColor Yellow
    $har=Join-Path $dirs['HarDir']"${FindingId}.har"
    ConvertTo-Har-RequestText $RequestText-ResponseText $ResponseText-Url $Url-OutFile $har
    if(-not$SkipRedact){
        Write-Host"[3/5] Redacting sensitive data..."-ForegroundColor Yellow
        $redactFiles=@($saved.RequestFile,$saved.ResponseFile,$har)
        foreach($t in $redactFiles){if(-not(Test-Path $t)){continue}
            $ext=[System.IO.Path]::GetExtension($t);$rc=if($t-eq$har){Join-Path $dirs['RedactedDir']"${FindingId}.redacted.har"}else{Join-Path $dirs['RedactedDir']"${FindingId}_capture.redacted$ext"}
            Copy-Item $t $rc-Force;Redact-Cookies $rc-InPlace;Redact-AuthHeaders $rc-InPlace;Redact-Pii $rc-InPlace}
        Sanitize-HarFile(Join-Path $dirs['RedactedDir']"${FindingId}.redacted.har")-InPlace
        Write-Host"      Redacted copies in $($dirs['RedactedDir'])"-ForegroundColor Gray
    }else{Write-Host"[3/5] SKIPPING redaction (as requested)"-ForegroundColor Yellow
        $copyFiles=@($saved.RequestFile,$saved.ResponseFile)
        foreach($t in $copyFiles){Copy-Item $t (Join-Path $dirs['RedactedDir'](Split-Path $t-Leaf))-Force}
        Copy-Item $har (Join-Path $dirs['RedactedDir']"${FindingId}.har")-Force}
    Write-Host"[4/5] Creating finding record..."-ForegroundColor Yellow
    $rf=Join-Path $dirs['ReportDir']'finding-record.json'
    if(-not$Title){$Title="$VulnerabilityClass vulnerability in $Url"}
    New-FindingRecord-FindingId $FindingId-Title $Title-Severity $Severity-VulnerabilityClass $VulnerabilityClass-AffectedEndpoint@($Url)-EvidenceFiles@($saved.RequestFile,$saved.ResponseFile,$har)-OutFile $rf
    Write-Host"[5/5] Validating evidence package..."-ForegroundColor Yellow
    $v=Test-EvidencePackage-FindingRecordPath $rf-PassThru
    if($v.Passed){Write-Host"      PASSED ($($v.FilesChecked) files checked)"-ForegroundColor Green}else{Write-Host"      FAILED ($($v.Issues.Count) issues)"-ForegroundColor Red;foreach($x in$v.Issues){Write-Host"        - $x"-ForegroundColor Red}}
    $res=@{FindingId=$FindingId;EvidenceDirs=$dirs;SavedFiles=$saved;HarFile=$har;RecordFile=$rf;Validation=$v}
    if($Compress){Write-Host"[EXTRA] Compressing evidence package..."-ForegroundColor Yellow;$res.ZipFile=(Compress-EvidencePackage-FindingDir $dirs['FindingDir']).FullName;Write-Host"      -> $($res.ZipFile)"-ForegroundColor Gray}
    Write-Host"=== Pipeline complete for $FindingId ==="-ForegroundColor Cyan;return$res
}

function Out-EvidenceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive markdown summary of all evidence collected for a finding.
    .DESCRIPTION
        Walks the evidence folder tree and produces a structured markdown report with
        overview statistics (file counts, total size, category breakdowns), finding
        details from the finding record (ID, title, severity, class), and a complete
        file listing with sizes and modification dates. Optionally includes a Unicode
        directory tree visualization for a quick overview of the evidence structure.

        The report sections include:
          - Overview: total files, size, breakdown by category (raw, redacted, screenshots, HAR)
          - Finding Details: ID, title, severity, vulnerability class (from finding-record.json)
          - Files by Category: sorted listing with relative paths, sizes, and timestamps
          - Directory Tree: optional ASCII tree view with unicode box-drawing characters
    .PARAMETER FindingDir
        Path to the finding's evidence folder containing raw/, redacted/, etc.
    .PARAMETER OutFile
        Path to save the generated markdown summary file.
    .PARAMETER IncludeTree
        Switch to include a directory tree visualization in the report.
    .EXAMPLE
        Out-EvidenceReport -FindingDir "evidence\FIND-001" -OutFile "evidence\FIND-001\report\evidence-summary.md"
    .EXAMPLE
        Out-EvidenceReport -FindingDir "evidence\IDOR-003" -OutFile "summary.md" -IncludeTree
    .OUTPUTS
        System.String (markdown content of the report).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FindingDir,
        [Parameter(Mandatory)][string]$OutFile,[switch]$IncludeTree
    )
    function fs($b){if($b-ge1TB){"{0:N2} TB"-f($b/1TB)}elseif($b-ge1GB){"{0:N2} GB"-f($b/1GB)}elseif($b-ge1MB){"{0:N2} MB"-f($b/1MB)}elseif($b-ge1KB){"{0:N2} KB"-f($b/1KB)}else{"$b B"}}
    function dt($p,$pre=''){$l=@();$items=Get-ChildItem $p|Sort-Object{$_.PSIsContainer-eq$false},Name;for($i=0;$i-lt$items.Count;$i++){$it=$items[$i];$lst=($i-eq$items.Count-1);$con=if($lst){'└── '}else{'├── '};$sub=if($lst){'    '}else{'│   '};if($it.PSIsContainer){$l+="$pre$con$($it.Name)/";$l+=dt $it.FullName "$pre$sub"}else{$l+="$pre$con$($it.Name)"}};return$l}
    $name=Split-Path $FindingDir-Leaf
    $rf=Join-Path $FindingDir'report\finding-record.json';$rec=if(Test-Path $rf){Get-Content $rf-Raw|ConvertFrom-Json}else{$null}
    $all=Get-ChildItem $FindingDir-Recurse-File|Sort-Object FullName;$ts=($all|Measure-Object-Property Length-Sum).Sum;$fc=$all.Count
    $rc=($all|Where-Object{$_.FullName-match'\\raw\\'}).Count;$rdc=($all|Where-Object{$_.FullName-match'\\(redacted|sanitized|pii-redacted)\\'}).Count
    $sc=($all|Where-Object{$_.FullName-match'\\screenshots\\'-and$_.Extension-match'\.(png|jpg|jpeg|gif)$'}).Count;$hc=($all|Where-Object{$_.Extension-eq'.har'}).Count
    $sb=[System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Evidence Summary: $name`n**Generated:** $(Get-Date-Format'yyyy-MM-dd HH:mm:ss')`n## Overview`n| Metric | Value |`n|--------|-------|`n| Total Files | $fc |`n| Total Size | $(fs $ts) |`n| Raw | $rc |`n| Redacted | $rdc |`n| Screenshots | $sc |`n| HAR | $hc |`n")
    if($rec){[void]$sb.AppendLine("## Finding`n| Field | Value |`n|-------|-------|`n| ID | $($rec.FindingId) |`n| Title | $($rec.Title) |`n| Severity | $($rec.Severity) |`n| Class | $($rec.VulnerabilityClass) |`n")}
    [void]$sb.AppendLine("## Files`n| File | Size | Modified |`n|------|------|----------|")
    foreach($f in$all){$rel=$f.FullName.Substring($FindingDir.Length+1);[void]$sb.AppendLine("| `$rel` | $(fs $f.Length) | $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) |")}
    if($IncludeTree){[void]$sb.AppendLine("`n## Directory Tree`n```");foreach($l in(dt $FindingDir)){[void]$sb.AppendLine($l)};[void]$sb.AppendLine("```")}
    $d=Split-Path $OutFile-Parent;if($d-and-not(Test-Path $d)){New-Item-ItemType Directory-Path $d-Force|Out-Null}
    $sb.ToString()|Set-Content $OutFile-Encoding utf8;Write-Verbose"Summary: $OutFile";return$sb.ToString()
}

Export-ModuleMember -Function Invoke-CurlCapture, Save-RequestResponse, Redact-Cookies, Redact-AuthHeaders, Redact-Pii
Export-ModuleMember -Function ConvertTo-Har, New-EvidenceFolder, Save-Screenshot, New-FindingRecord, Export-FindingReport
Export-ModuleMember -Function Test-EvidencePackage, Compress-EvidencePackage, New-CurlToHar, Sanitize-HarFile
Export-ModuleMember -Function Generate-PoCDescription, Invoke-FullEvidencePipeline, Out-EvidenceReport

Write-Verbose "evidence-toolkit.ps1 loaded. 18 functions available."
