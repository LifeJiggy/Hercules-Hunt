<#
.SYNOPSIS
    Extract-Functionalities — User Functionality Extraction Tool for Bug Bounty Reconnaissance

.DESCRIPTION
    Discovers all user-interactive elements from HTML content including forms, buttons,
    links, inputs, selects, textareas, and JavaScript event handlers. Maps user workflows
    and state transitions between pages to understand application attack surface.

    Features:
      - Form detection with method, action, and all input field enumeration
      - Input field analysis (type, name, value, placeholder, pattern, required, disabled)
      - Select/option dropdown enumeration with all options and values
      - Textarea discovery with maxlength, placeholder, and row/column attributes
      - Button analysis (submit, reset, button types with onclick handlers)
      - Link discovery with href, rel, target, and onClick attributes
      - JavaScript event handler extraction (onclick, onsubmit, onchange, onload, onfocus, onblur)
      - Hidden field enumeration with default values
      - User workflow state transition mapping between pages
      - AJAX/API endpoint consumption mapping from JavaScript
      - CSRF token detection in forms and meta tags
      - Client-side validation rule extraction (pattern, min, max, minlength, maxlength, required)
      - Data attribute extraction (data-* attributes on interactive elements)
      - Structured JSON output for pipeline integration

    Output fields per functionality element:
      - ElementType (form, input, button, link, select, textarea, script, meta)
      - ElementId and ElementName
      - FormAction, FormMethod, FormEnctype (for forms)
      - InputType, InputName, InputValue, InputPlaceholder (for inputs)
      - SelectOptions (array of option objects with value and text)
      - EventHandlers (array of {event, handler} objects)
      - DataAttributes (hashtable of data-* attributes)
      - CrsfToken (detected CSRF token name and value)
      - ParentFormId (for inputs, links to parent form)
      - WorkflowState (state transition mapping)

.PARAMETER Url
    Target URL to analyze for user functionalities. Can be a base domain or specific page.

.PARAMETER FilePath
    Local HTML file path to analyze instead of fetching from URL. Supports .html, .htm files.

.PARAMETER OutputFile
    Path to write structured results (JSON format). If omitted, results go to pipeline.

.PARAMETER Depth
    Crawling depth for recursive functionality discovery. Default: 1, Range: 1-3.

.PARAMETER IncludeHidden
    Include hidden input fields in the output. Default: $true.

.PARAMETER FollowRedirects
    Follow HTTP redirects when fetching URLs. Default: $true.

.PARAMETER Timeout
    HTTP request timeout in seconds. Default: 30

.PARAMETER UserAgent
    Custom User-Agent string for HTTP requests.

.PARAMETER RateLimit
    Minimum milliseconds between requests. Default: 200

.PARAMETER Silent
    Suppress all non-data output.

.EXAMPLE
    .\extract-functionalities.ps1 -Url "https://target.com/login"

    Analyzes the login page, discovers all forms, inputs, buttons, and JS handlers.

.EXAMPLE
    .\extract-functionalities.ps1 -Url "https://target.com" -Depth 2 -OutputFile "functionalities.json"

    Deep crawl to depth 2, discover all interactive elements, write to JSON file.

.EXAMPLE
    .\extract-functionalities.ps1 -FilePath ".\page.html" -IncludeHidden:$false

    Analyze local HTML file excluding hidden inputs from output.

.EXAMPLE
    .\extract-functionalities.ps1 -Url "https://target.com" -Depth 3 -FollowRedirects:$false

    Deep crawl without following redirects.

.NOTES
    Version     : 1.0.0
    Requires    : PowerShell 5.1+, Windows 10/11 or Windows Server 2016+
    Author      : Hercules-Hunt Toolchain
    Details     : Uses regex-based HTML parsing for compatibility. No browser or DOM
                  engine required. For complex JS-rendered pages, pair with browser-automator.

.LINK
    https://opencode.ai
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================================
# GLOBAL CONSTANTS
# ============================================================================

$Script:DefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'

$Script:InputTypes = @(
    'text', 'password', 'email', 'number', 'tel', 'url', 'search', 'date',
    'time', 'datetime-local', 'month', 'week', 'color', 'range', 'file',
    'hidden', 'checkbox', 'radio', 'submit', 'reset', 'button', 'image'
)

$Script:EventHandlerAttributes = @(
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
    'onmouseout', 'onmousemove', 'onkeydown', 'onkeypress', 'onkeyup',
    'onsubmit', 'onreset', 'onchange', 'onselect', 'onblur', 'onfocus',
    'onload', 'onunload', 'onscroll', 'onresize', 'onabort', 'onerror',
    'oncontextmenu', 'ontouchstart', 'ontouchend', 'ontouchmove',
    'onsubmit', 'oninput', 'oninvalid', 'onformdata'
)

$Script:FormMethodPatterns = @('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'DIALOG')

$Script:CsrfTokenNames = @(
    'csrf_token', 'csrfmiddlewaretoken', '_csrf', 'csrf', 'xsrf-token',
    'xsrf_token', '__csrf', 'csrfToken', 'csrf-token', 'authenticity_token',
    '_token', '__token', 'csrf_name', 'csrf_value', 'csrfKey', 'csrf_key',
    'nonce', '_nonce', 'request_verification_token', '__RequestVerificationToken',
    'form_token', 'form_key', 'security_token', 'token'
)

# ============================================================================
# FUNCTION: Invoke-WebRequestSafe
# ============================================================================

function Invoke-WebRequestSafe {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType,
        [int]$TimeoutSec = 30,
        [string]$UserAgent,
        [switch]$ReturnRaw,
        [hashtable]$Headers,
        [switch]$FollowRedirects
    )
    $ua = if ($UserAgent) { $UserAgent } else { $Script:DefaultUserAgent }
    $params = @{
        Uri             = $Uri
        Method          = $Method
        TimeoutSec      = $TimeoutSec
        UserAgent       = $ua
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if (-not $FollowRedirects) {
        $params['MaximumRedirection'] = 0
    }
    if ($Body) { $params['Body'] = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }
    if ($Headers) { $params['Headers'] = $Headers }

    try {
        $response = Invoke-WebRequest @params
        $content = if ($response.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($response.Content)
        } else { $response.Content }

        $result = [PSCustomObject]@{
            StatusCode    = [int]$response.StatusCode
            Content       = $content
            ContentType   = $response.Headers.'Content-Type' -join ', '
            Headers       = $response.Headers
            Raw           = if ($ReturnRaw) { $response } else { $null }
            Success       = $true
            ErrorMessage  = $null
            FinalUri      = $response.BaseResponse.ResponseUri.AbsoluteUri
        }
        return $result
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        $result = [PSCustomObject]@{
            StatusCode    = $statusCode
            Content       = $null
            ContentType   = $null
            Headers       = $null
            Raw           = $null
            Success       = $false
            ErrorMessage  = $_.Exception.Message
            FinalUri      = $null
        }
        return $result
    }
}

# ============================================================================
# FUNCTION: Get-AttributeValue
# ============================================================================

function Get-AttributeValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ElementHtml,
        [Parameter(Mandatory)]
        [string]$AttributeName
    )
    $pattern = "$AttributeName\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))"
    $match = [regex]::Match($ElementHtml, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) {
        return ($match.Groups[1].Value, $match.Groups[2].Value, $match.Groups[3].Value) -ne '' | Select-Object -First 1
    }
    return $null
}

# ============================================================================
# FUNCTION: Get-DataAttributes
# ============================================================================

function Get-DataAttributes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ElementHtml
    )
    $dataPattern = 'data-([a-zA-Z][\w-]*)\s*=\s*(?:""([^""]*)""|''([^'']*)''|([^\s>]+))'
    $matches = [regex]::Matches($ElementHtml, $dataPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $dataAttrs = @{}
    foreach ($m in $matches) {
        $key = $m.Groups[1].Value
        $value = ($m.Groups[2].Value, $m.Groups[3].Value, $m.Groups[4].Value) -ne '' | Select-Object -First 1
        if ($key) {
            $dataAttrs["data-$key"] = $value
        }
    }
    return $dataAttrs
}

# ============================================================================
# FUNCTION: Get-EventHandlers
# ============================================================================

function Get-EventHandlers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ElementHtml
    )
    $handlers = [System.Collections.Generic.List[object]]::new()
    foreach ($eventAttr in $Script:EventHandlerAttributes) {
        $value = Get-AttributeValue -ElementHtml $ElementHtml -AttributeName $eventAttr
        if ($value) {
            $handlers.Add([PSCustomObject]@{
                EventType = $eventAttr
                Handler   = $value.Trim()
            })
        }
    }
    return $handlers
}

# ============================================================================
# FUNCTION: Extract-Forms
# ============================================================================

function Extract-Forms {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html,
        [switch]$IncludeHidden
    )
    $forms = [System.Collections.Generic.List[object]]::new()
    $formPattern = '<form\s[^>]*>([\s\S]*?)</form>'
    $formMatches = [regex]::Matches($Html, $formPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($fm in $formMatches) {
        $formHtml = $fm.Value
        $formContent = $fm.Groups[1].Value
        $formId = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'id'
        $formName = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'name'
        $formAction = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'action'
        $formMethod = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'method'
        $formEnctype = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'enctype'
        $formNovalidate = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'novalidate'
        $formTarget = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'target'
        $formAutocomplete = Get-AttributeValue -ElementHtml $formHtml -AttributeName 'autocomplete'

        if (-not $formMethod) { $formMethod = 'GET' }
        $formMethod = $formMethod.ToUpper()

        $inputs = [System.Collections.Generic.List[object]]::new()
        $buttons = [System.Collections.Generic.List[object]]::new()
        $selects = [System.Collections.Generic.List[object]]::new()
        $textareas = [System.Collections.Generic.List[object]]::new()
        $csrfs = [System.Collections.Generic.List[object]]::new()

        # Extract inputs
        $inputPattern = '<input\s[^>]*/?>'
        $inputMatches = [regex]::Matches($formContent, $inputPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($im in $inputMatches) {
            $inputHtml = $im.Value
            $inputType = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'type'
            if (-not $inputType) { $inputType = 'text' }
            $inputLower = $inputType.ToLower()

            if (-not $IncludeHidden -and $inputLower -eq 'hidden') { continue }

            $input = [PSCustomObject]@{
                Type        = $inputLower
                Name        = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'name'
                Id          = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'id'
                Value       = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'value'
                Placeholder = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'placeholder'
                Required    = ($inputHtml -match '\brequired\b')
                Disabled    = ($inputHtml -match '\bdisabled\b')
                Readonly    = ($inputHtml -match '\breadonly\b|\breadonly\s*=\s*["'']?readonly["'']?')
                MaxLength   = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'maxlength'
                MinLength   = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'minlength'
                Pattern     = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'pattern'
                Min         = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'min'
                Max         = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'max'
                Step        = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'step'
                Autocomplete = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'autocomplete'
                Class       = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'class'
                Multiple    = ($inputHtml -match '\bmultiple\b')
                Accept      = Get-AttributeValue -ElementHtml $inputHtml -AttributeName 'accept'
                EventHandlers = Get-EventHandlers -ElementHtml $inputHtml
                DataAttributes = Get-DataAttributes -ElementHtml $inputHtml
            }
            if ($inputLower -eq 'hidden' -or $inputLower -eq 'submit') {
                $inputs.Add($input)
            }
            else {
                $inputs.Add($input)
            }

            # Check CSRF patterns
            $inputName = $input.Name
            if ($inputName) {
                foreach ($csrfPattern in $Script:CsrfTokenNames) {
                    if ($inputName -like "*$csrfPattern*") {
                        $csrfs.Add([PSCustomObject]@{
                            TokenName  = $inputName
                            TokenValue = $input.Value
                            TokenType  = 'input'
                        })
                    }
                }
            }
        }

        # Extract buttons
        $btnPattern = '<button\s[^>]*>[\s\S]*?</button>'
        $btnMatches = [regex]::Matches($formContent, $btnPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($bm in $btnMatches) {
            $btnHtml = $bm.Value
            $btnType = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'type'
            if (-not $btnType) { $btnType = 'submit' }

            $button = [PSCustomObject]@{
                Type           = $btnType.ToLower()
                Name           = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'name'
                Id             = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'id'
                Value          = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'value'
                Disabled       = ($btnHtml -match '\bdisabled\b')
                FormAction     = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'formaction'
                FormMethod     = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'formmethod'
                FormTarget     = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'formtarget'
                FormNoValidate = ($btnHtml -match '\bformnovalidate\b')
                Label          = ($bm.Groups[1].Value -replace '<[^>]+>', '').Trim()
                EventHandlers  = Get-EventHandlers -ElementHtml $btnHtml
                DataAttributes = Get-DataAttributes -ElementHtml $btnHtml
            }
            $buttons.Add($button)
        }

        # Extract selects
        $selectPattern = '<select\s[^>]*>([\s\S]*?)</select>'
        $selectMatches = [regex]::Matches($formContent, $selectPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($sm in $selectMatches) {
            $selectHtml = $sm.Value
            $selectContent = $sm.Groups[1].Value
            $options = [System.Collections.Generic.List[object]]::new()

            $optPattern = '<option\s[^>]*>([\s\S]*?)</option>'
            $optMatches = [regex]::Matches($selectContent, $optPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($om in $optMatches) {
                $optHtml = $om.Value
                $optText = ($om.Groups[1].Value -replace '<[^>]+>', '').Trim()
                $options.Add([PSCustomObject]@{
                    Value    = Get-AttributeValue -ElementHtml $optHtml -AttributeName 'value'
                    Text     = $optText
                    Selected = ($optHtml -match '\bselected\b')
                    Disabled = ($optHtml -match '\bdisabled\b')
                    Label    = Get-AttributeValue -ElementHtml $optHtml -AttributeName 'label'
                })
            }

            # Also handle optgroup
            $optgroupPattern = '<optgroup\s[^>]*>([\s\S]*?)</optgroup>'
            $optgroupMatches = [regex]::Matches($selectContent, $optgroupPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($ogm in $optgroupMatches) {
                $ogHtml = $ogm.Value
                $ogLabel = Get-AttributeValue -ElementHtml $ogHtml -AttributeName 'label'
                $ogContent = $ogm.Groups[1].Value
                $igOptMatches = [regex]::Matches($ogContent, $optPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($iom in $igOptMatches) {
                    $ioptHtml = $iom.Value
                    $ioptText = ($iom.Groups[1].Value -replace '<[^>]+>', '').Trim()
                    $options.Add([PSCustomObject]@{
                        Value    = Get-AttributeValue -ElementHtml $ioptHtml -AttributeName 'value'
                        Text     = $ioptText
                        Selected = ($ioptHtml -match '\bselected\b')
                        Disabled = ($ioptHtml -match '\bdisabled\b')
                        Label    = "$ogLabel / $ioptText"
                    })
                }
            }

            $select = [PSCustomObject]@{
                Name           = Get-AttributeValue -ElementHtml $selectHtml -AttributeName 'name'
                Id             = Get-AttributeValue -ElementHtml $selectHtml -AttributeName 'id'
                Required       = ($selectHtml -match '\brequired\b')
                Disabled       = ($selectHtml -match '\bdisabled\b')
                Multiple       = ($selectHtml -match '\bmultiple\b')
                Size           = Get-AttributeValue -ElementHtml $selectHtml -AttributeName 'size'
                Autocomplete   = Get-AttributeValue -ElementHtml $selectHtml -AttributeName 'autocomplete'
                Options        = $options
                OptionCount    = $options.Count
                EventHandlers  = Get-EventHandlers -ElementHtml $selectHtml
                DataAttributes = Get-DataAttributes -ElementHtml $selectHtml
            }
            $selects.Add($select)
        }

        # Extract textareas
        $textareaPattern = '<textarea\s[^>]*>([\s\S]*?)</textarea>'
        $textareaMatches = [regex]::Matches($formContent, $textareaPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($tm in $textareaMatches) {
            $textareaHtml = $tm.Value
            $textareaContent = $tm.Groups[1].Value.Trim()
            $textarea = [PSCustomObject]@{
                Name           = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'name'
                Id             = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'id'
                Placeholder    = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'placeholder'
                Rows           = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'rows'
                Cols           = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'cols'
                MaxLength      = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'maxlength'
                MinLength      = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'minlength'
                Required       = ($textareaHtml -match '\brequired\b')
                Disabled       = ($textareaHtml -match '\bdisabled\b')
                Readonly       = ($textareaHtml -match '\breadonly\b')
                Wrap           = Get-AttributeValue -ElementHtml $textareaHtml -AttributeName 'wrap'
                DefaultValue   = $textareaContent
                EventHandlers  = Get-EventHandlers -ElementHtml $textareaHtml
                DataAttributes = Get-DataAttributes -ElementHtml $textareaHtml
            }
            $textareas.Add($textarea)
        }

        # Check for CSRF in meta tags within the form
        $metaCsrfPattern = '<meta\s[^>]*name\s*=\s*["''](?:csrf-token|csrf-param|_csrf)["''][^>]*>'
        $metaCsrfMatches = [regex]::Matches($formContent, $metaCsrfPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($mcm in $metaCsrfMatches) {
            $metaHtml = $mcm.Value
            $metaContent = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'content'
            $metaName = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'name'
            $csrfs.Add([PSCustomObject]@{
                TokenName  = $metaName
                TokenValue = $metaContent
                TokenType  = 'meta'
            })
        }

        $formResult = [PSCustomObject]@{
            ElementType   = 'form'
            FormId        = $formId
            FormName      = $formName
            FormAction    = $formAction
            FormMethod    = $formMethod
            FormEnctype   = $formEnctype
            FormTarget    = $formTarget
            Novalidate    = ($formNovalidate -ne $null)
            Autocomplete  = $formAutocomplete
            Inputs        = $inputs
            InputCount    = $inputs.Count
            Buttons       = $buttons
            ButtonCount   = $buttons.Count
            Selects       = $selects
            SelectCount   = $selects.Count
            Textareas     = $textareas
            TextareaCount = $textareas.Count
            CsrfTokens    = $csrfs
            EventHandlers = Get-EventHandlers -ElementHtml $formHtml
            DataAttributes = Get-DataAttributes -ElementHtml $formHtml
        }
        $forms.Add($formResult)
    }
    return $forms
}

# ============================================================================
# FUNCTION: Extract-Links
# ============================================================================

function Extract-Links {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html,
        [string]$BaseUrl
    )
    $links = [System.Collections.Generic.List[object]]::new()
    $linkPattern = '<a\s[^>]*href\s*=\s*["'']([^"''\s>]+)["''][^>]*>([\s\S]*?)</a>'
    $linkMatches = [regex]::Matches($Html, $linkPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($lm in $linkMatches) {
        $linkHtml = $lm.Value
        $href = $lm.Groups[1].Value.Trim()
        $linkText = ($lm.Groups[2].Value -replace '<[^>]+>', '').Trim()

        if ($href -like '#'* -or $href -like 'javascript:*' -or $href -like 'mailto:*' -or $href -like 'tel:*') {
            continue
        }

        $resolvedHref = $href
        if ($resolvedHref -notmatch '^https?://' -and $BaseUrl) {
            try {
                $baseUri = [System.Uri]$BaseUrl
                if ($resolvedHref -match '^/') {
                    $resolvedHref = "$($baseUri.Scheme)://$($baseUri.Host)$resolvedHref"
                }
                else {
                    $basePath = $BaseUrl.TrimEnd('/')
                    $lastSlash = $basePath.LastIndexOf('/')
                    if ($lastSlash -gt 8) { $basePath = $basePath.Substring(0, $lastSlash) }
                    $resolvedHref = "$basePath/$resolvedHref"
                }
            }
            catch {
                $resolvedHref = $href
            }
        }

        $link = [PSCustomObject]@{
            ElementType    = 'link'
            Href           = $href
            ResolvedUrl    = $resolvedHref
            Text           = $linkText
            Id             = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'id'
            Class          = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'class'
            Target         = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'target'
            Rel            = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'rel'
            Download       = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'download'
            Ping           = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'ping'
            Type           = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'type'
            Hreflang       = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'hreflang'
            Media          = Get-AttributeValue -ElementHtml $linkHtml -AttributeName 'media'
            EventHandlers  = Get-EventHandlers -ElementHtml $linkHtml
            DataAttributes = Get-DataAttributes -ElementHtml $linkHtml
        }
        $links.Add($link)
    }
    return $links
}

# ============================================================================
# FUNCTION: Extract-Buttons
# ============================================================================

function Extract-Buttons {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $buttons = [System.Collections.Generic.List[object]]::new()
    # Buttons outside forms
    $btnPattern = '<button\s[^>]*>([\s\S]*?)</button>'
    $btnMatches = [regex]::Matches($Html, $btnPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($bm in $btnMatches) {
        $btnHtml = $bm.Value
        $btnType = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'type'
        if (-not $btnType) { $btnType = 'submit' }

        # Skip if inside a form (already captured)
        $preContext = $Html.Substring(0, [Math]::Max(0, $bm.Index - 500))
        $lastFormOpen = $preContext.LastIndexOf('<form')
        $lastFormClose = $preContext.LastIndexOf('</form>')
        if ($lastFormOpen -gt $lastFormClose) { continue }

        $button = [PSCustomObject]@{
            ElementType    = 'button'
            Type           = $btnType.ToLower()
            Name           = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'name'
            Id             = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'id'
            Value          = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'value'
            Disabled       = ($btnHtml -match '\bdisabled\b')
            Label          = ($bm.Groups[1].Value -replace '<[^>]+>', '').Trim()
            Popovertarget  = Get-AttributeValue -ElementHtml $btnHtml -AttributeName 'popovertarget'
            EventHandlers  = Get-EventHandlers -ElementHtml $btnHtml
            DataAttributes = Get-DataAttributes -ElementHtml $btnHtml
        }
        $buttons.Add($button)
    }
    return $buttons
}

# ============================================================================
# FUNCTION: Extract-Scripts
# ============================================================================

function Extract-Scripts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $scripts = [System.Collections.Generic.List[object]]::new()
    $inlineScriptPattern = '<script[^>]*>([\s\S]*?)</script>'
    $scriptMatches = [regex]::Matches($Html, $inlineScriptPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($sm in $scriptMatches) {
        $scriptHtml = $sm.Value
        $scriptContent = $sm.Groups[1].Value.Trim()
        $src = Get-AttributeValue -ElementHtml $scriptHtml -AttributeName 'src'
        $scriptType = Get-AttributeValue -ElementHtml $scriptHtml -AttributeName 'type'
        $async = ($scriptHtml -match '\basync\b')
        $defer = ($scriptHtml -match '\bdefer\b')
        $nomodule = ($scriptHtml -match '\bnomodule\b')
        $crossorigin = Get-AttributeValue -ElementHtml $scriptHtml -AttributeName 'crossorigin'
        $integrity = Get-AttributeValue -ElementHtml $scriptHtml -AttributeName 'integrity'

        # Analyze inline script for AJAX calls
        $ajaxPatterns = '(\b(?:fetch|axios|ajax|\$\.(?:get|post|ajax|getJSON)|XMLHttpRequest|new\s+Request|fetch\s*\()\s*\(?["'']?([^"'',)]+)["'']?)'
        $ajaxMatches = [regex]::Matches($scriptContent, $ajaxPatterns, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $ajaxUrls = [System.Collections.Generic.List[string]]::new()
        foreach ($am in $ajaxMatches) {
            $ajaxUrl = $am.Groups[2].Value -replace '["'']', ''
            if ($ajaxUrl -and $ajaxUrl -notmatch '^\s*$' -and $ajaxUrl -notlike '*function*') {
                $ajaxUrls.Add($ajaxUrl.Trim())
            }
        }

        # Detect event listeners using addEventListener
        $listenerPattern = '(?:addEventListener|on)\s*\(\s*["''](\w+)["'']\s*,'
        $listenerMatches = [regex]::Matches($scriptContent, $listenerPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $eventListeners = [System.Collections.Generic.List[string]]::new()
        foreach ($lm in $listenerMatches) {
            $eventListeners.Add($lm.Groups[1].Value)
        }

        $script = [PSCustomObject]@{
            ElementType      = 'script'
            Src              = $src
            Type             = if ($scriptType) { $scriptType } else { 'text/javascript' }
            Async            = $async
            Defer            = $defer
            Nomodule         = $nomodule
            Crossorigin      = $crossorigin
            Integrity        = $integrity
            InlineContent    = if ($src) { $null } else { $scriptContent }
            InlineLength     = if ($src) { 0 } else { $scriptContent.Length }
            AjaxUrlsDetected = $ajaxUrls
            EventListeners   = $eventListeners
            DataAttributes   = Get-DataAttributes -ElementHtml $scriptHtml
        }
        $scripts.Add($script)
    }
    return $scripts
}

# ============================================================================
# FUNCTION: Extract-MetaTags
# ============================================================================

function Extract-MetaTags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $metas = [System.Collections.Generic.List[object]]::new()
    $metaPattern = '<meta\s[^>]*/?>'
    $metaMatches = [regex]::Matches($Html, $metaPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $csrfMetas = [System.Collections.Generic.List[object]]::new()

    foreach ($mm in $metaMatches) {
        $metaHtml = $mm.Value
        $metaName = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'name'
        $metaContent = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'content'
        $metaHttpEquiv = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'http-equiv'
        $metaProperty = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'property'
        $metaCharset = Get-AttributeValue -ElementHtml $metaHtml -AttributeName 'charset'

        # Check CSRF meta tags
        if ($metaName) {
            foreach ($csrfPattern in $Script:CsrfTokenNames) {
                if ($metaName -like "*$csrfPattern*") {
                    $csrfMetas.Add([PSCustomObject]@{
                        TokenName  = $metaName
                        TokenValue = $metaContent
                        TokenType  = 'meta'
                    })
                }
            }
        }

        $meta = [PSCustomObject]@{
            ElementType = 'meta'
            Name        = $metaName
            Content     = $metaContent
            HttpEquiv   = $metaHttpEquiv
            Property    = $metaProperty
            Charset     = $metaCharset
            DataAttributes = Get-DataAttributes -ElementHtml $metaHtml
        }
        $metas.Add($meta)
    }
    return @{ Metas = $metas; CsrfMetas = $csrfMetas }
}

# ============================================================================
# FUNCTION: Build-WorkflowMap
# ============================================================================

function Build-WorkflowMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Forms,
        [object[]]$Links,
        [string]$CurrentUrl
    )
    $workflows = [System.Collections.Generic.List[object]]::new()

    # Map form submissions as state transitions
    foreach ($form in $Forms) {
        $action = $form.FormAction
        if ($action) {
            $resolvedAction = if ($action -match '^https?://') { $action }
            elseif ($CurrentUrl -and $action -match '^/') {
                try {
                    $uri = [System.Uri]$CurrentUrl
                    "$($uri.Scheme)://$($uri.Host)$action"
                } catch { $action }
            }
            elseif ($CurrentUrl) {
                try {
                    $uri = [System.Uri]$CurrentUrl
                    "$($uri.Scheme)://$($uri.Host)/$($action.TrimStart('/'))"
                } catch { $action }
            }
            else { $action }

            $fromState = $CurrentUrl
            $toState = $resolvedAction
            $via = "form_submit_$($form.FormMethod)"

            $workflow = [PSCustomObject]@{
                TransitionType = 'form_submit'
                FromState      = $fromState
                ToState        = $toState
                Method         = $form.FormMethod
                Enctype        = $form.FormEnctype
                Parameters     = ($form.Inputs | Where-Object { $_.Type -ne 'submit' } | ForEach-Object { $_.Name })
                Trigger        = "form_$($form.FormName ?? $form.FormId ?? 'unnamed')"
            }
            $workflows.Add($workflow)
        }
    }

    # Map links as navigation transitions
    foreach ($link in $Links) {
        if ($link.Href -match '^https?://' -or $link.Href -match '^/') {
            $workflow = [PSCustomObject]@{
                TransitionType = 'navigation'
                FromState      = $CurrentUrl
                ToState        = $link.ResolvedUrl
                Method         = 'GET'
                Enctype        = $null
                Parameters     = @()
                Trigger        = "link_$($link.Text -replace '\s+', '_')"
            }
            $workflows.Add($workflow)
        }
    }

    return $workflows
}

# ============================================================================
# FUNCTION: Detect-CsrfMechanism
# ============================================================================

function Detect-CsrfMechanism {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $csrfFindings = [System.Collections.Generic.List[object]]::new()

    # Check meta tags
    $metaPattern = '<meta\s[^>]*name\s*=\s*["'']([^"'']+)["''][^>]*content\s*=\s*["'']([^"'']+)["'']'
    $metaMatches = [regex]::Matches($Html, $metaPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($mm in $metaMatches) {
        $name = $mm.Groups[1].Value
        $content = $mm.Groups[2].Value
        foreach ($csrfPattern in $Script:CsrfTokenNames) {
            if ($name -like "*$csrfPattern*") {
                $csrfFindings.Add([PSCustomObject]@{
                    DetectionType = 'meta_tag'
                    TokenName     = $name
                    TokenValue    = $content
                    TokenLocation = 'html_head'
                })
            }
        }
    }

    # Check cookie-based CSRF
    $cookiePattern = '(?:Set-Cookie|document\.cookie)\s*[^;]*[''"]([^"'']*(?:csrf|xsrf|token)[^"'']*)[''"]'
    $cookieMatches = [regex]::Matches($Html, $cookiePattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($cm in $cookieMatches) {
        $csrfFindings.Add([PSCustomObject]@{
            DetectionType = 'cookie_header'
            TokenName     = $cm.Groups[1].Value
            TokenValue    = 'present'
            TokenLocation = 'cookie'
        })
    }

    # Check header-based CSRF
    $headerPattern = '(?:X-CSRF-Token|X-CSRFToken|X-XSRF-TOKEN|X-CSRF-TOKEN)[:\s]+[^"''\r\n]+'
    $headerMatches = [regex]::Matches($Html, $headerPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($hm in $headerMatches) {
        $csrfFindings.Add([PSCustomObject]@{
            DetectionType = 'header'
            TokenName     = ($hm.Value -split ':' | Select-Object -First 1).Trim()
            TokenValue    = ($hm.Value -split ':' | Select-Object -Last 1).Trim()
            TokenLocation = 'request_header'
        })
    }

    return $csrfFindings
}

# ============================================================================
# FUNCTION: Classify-FormByPurpose
# ============================================================================

function Classify-FormByPurpose {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Form
    )
    $action = $Form.FormAction
    if (-not $action) { return 'unknown' }

    $lower = $action.ToLower()

    if ($lower -match 'login|signin|auth|authenticate') { return 'login' }
    if ($lower -match 'register|signup|sign-up|create') { return 'registration' }
    if ($lower -match 'reset|forgot|recover|password') { return 'password_reset' }
    if ($lower -match 'search|find|query') { return 'search' }
    if ($lower -match 'contact|feedback|support') { return 'contact' }
    if ($lower -match 'checkout|cart|order|purchase|pay') { return 'checkout' }
    if ($lower -match 'upload|import|attach') { return 'upload' }
    if ($lower -match 'delete|remove|cancel|unsubscribe') { return 'destructive' }
    if ($lower -match 'edit|update|profile|settings|account') { return 'profile' }
    if ($lower -match 'comment|post|reply|submit') { return 'content_submission' }
    if ($lower -match 'subscribe|newsletter|notif') { return 'subscription' }
    if ($lower -match 'api/|/api/|rest|graphql') { return 'api' }

    # Check field patterns
    $inputNames = $Form.Inputs | ForEach-Object { $_.Name }
    $inputNamesStr = ($inputNames) -join ' '
    if ($inputNamesStr -match 'password|passwd|pwd') { return 'authentication' }
    if ($inputNamesStr -match 'email|mail') { return 'email_form' }
    if ($inputNamesStr -match 'credit|card|cvv|cc-number') { return 'payment' }
    if ($inputNamesStr -match 'search|q\b|query') { return 'search' }
    if ($inputNamesStr -match 'file|upload') { return 'upload' }

    if ($Form.FormMethod -eq 'GET' -and $Form.InputCount -le 3) { return 'filter' }

    return 'unknown'
}

# ============================================================================
# FUNCTION: Get-InteractiveStatistics
# ============================================================================

function Get-InteractiveStatistics {
    [CmdletBinding()]
    param(
        [object[]]$Forms,
        [object[]]$Links,
        [object[]]$Buttons,
        [object[]]$Scripts,
        [object[]]$Metas
    )
    $totalInputs = 0
    $totalButtons = 0
    $totalSelects = 0
    $totalTextareas = 0
    $hiddenCount = 0
    $fileUploads = 0
    $passwordFields = 0
    $eventHandlersCount = 0
    $csrfTokens = 0

    foreach ($form in $Forms) {
        $totalInputs += $form.InputCount
        $totalButtons += $form.ButtonCount
        $totalSelects += $form.SelectCount
        $totalTextareas += $form.TextareaCount
        $csrfTokens += $form.CsrfTokens.Count
        foreach ($input in $form.Inputs) {
            if ($input.Type -eq 'hidden') { $hiddenCount++ }
            if ($input.Type -eq 'file') { $fileUploads++ }
            if ($input.Type -eq 'password') { $passwordFields++ }
            $eventHandlersCount += $input.EventHandlers.Count
        }
        foreach ($button in $form.Buttons) {
            $eventHandlersCount += $button.EventHandlers.Count
        }
        foreach ($select in $form.Selects) {
            $eventHandlersCount += $select.EventHandlers.Count
        }
    }

    $externalLinks = ($Links | Where-Object { $_.Href -match '^https?://' -and $_.ResolvedUrl -ne $_.Href }).Count
    $internalLinks = $Links.Count - $externalLinks
    $ajaxCallCount = 0
    foreach ($script in $Scripts) {
        $ajaxCallCount += $script.AjaxUrlsDetected.Count
    }

    return [PSCustomObject]@{
        TotalForms           = $Forms.Count
        TotalLinks           = $Links.Count
        InternalLinks        = $internalLinks
        ExternalLinks        = $externalLinks
        TotalButtons         = $Buttons.Count
        TotalScripts         = $Scripts.Count
        TotalMetas           = $Metas.Count
        TotalInputs          = $totalInputs
        HiddenInputs         = $hiddenCount
        FileUploadInputs     = $fileUploads
        PasswordFields       = $passwordFields
        TotalSelects         = $totalSelects
        TotalTextareas       = $totalTextareas
        EventHandlersFound   = $eventHandlersCount
        AjaxCallsDetected    = $ajaxCallCount
        CsrfTokensDetected   = $csrfTokens
    }
}

# ============================================================================
# FUNCTION: Get-JavaScriptFrameworkInfo
# ============================================================================

function Get-JavaScriptFrameworkInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Html
    )
    $frameworks = [System.Collections.Generic.List[string]]::new()

    if ($Html -match 'react|React\.|react\.|createElement|__REACT_DEVTOOLS') { $frameworks.Add('React') }
    if ($Html -match 'angular|ng-|ng-app|ng-controller|ng-model|ng-repeat|NgModule|Component\(') { $frameworks.Add('Angular') }
    if ($Html -match 'vue|Vue\.|v-model|v-bind|v-if|v-for|v-show|createApp') { $frameworks.Add('Vue.js') }
    if ($Html -match 'jQuery|\$\.|\$\(|jquery') { $frameworks.Add('jQuery') }
    if ($Html -match 'svelte|Svelte|createSvelte') { $frameworks.Add('Svelte') }
    if ($Html -match 'next\.js|Next\.js|next/') { $frameworks.Add('Next.js') }
    if ($Html -match 'nuxt|Nuxt|nuxt/') { $frameworks.Add('Nuxt.js') }
    if ($Html -match 'gatsby|Gatsby') { $frameworks.Add('Gatsby') }
    if ($Html -match 'django|Django|csrfmiddlewaretoken|djDT') { $frameworks.Add('Django (Python)') }
    if ($Html -match 'laravel|Laravel|Livewire|csrf-token.*csrf-token-meta') { $frameworks.Add('Laravel (PHP)') }
    if ($Html -match 'rails|Rails|data-remote|data-confirm|authenticity_token') { $frameworks.Add('Ruby on Rails') }
    if ($Html -match 'asp\.net|__VIEWSTATE|__EVENTVALIDATION|ASP\.NET_SessionId') { $frameworks.Add('ASP.NET') }
    if ($Html -match 'spring|Spring|th:') { $frameworks.Add('Spring (Java)') }
    if ($Html -match 'alpine|Alpine|x-data|x-init|x-on|x-bind') { $frameworks.Add('Alpine.js') }
    if ($Html -match 'htmx|hx-get|hx-post|hx-put|hx-delete|hx-target|hx-swap') { $frameworks.Add('HTMX') }
    if ($Html -match 'turbo|Turbo|turbo-frame|turbo-stream|Turbo\.visit') { $frameworks.Add('Turbo/Hotwire') }
    if ($Html -match 'stimulus|Stimulus|data-controller|data-action|data-target') { $frameworks.Add('Stimulus') }
    if ($Html -match 'bootstrap|Bootstrap|col-|row|container-fluid|navbar') { $frameworks.Add('Bootstrap') }
    if ($Html -match 'tailwind|Tailwind|tw-') { $frameworks.Add('Tailwind CSS') }

    return $frameworks
}

# ============================================================================
# FUNCTION: Invoke-UserFunctionalityDiscovery
# ============================================================================

function Invoke-UserFunctionalityDiscovery {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$OutputFile,
        [int]$Depth = 1,
        [switch]$IncludeHidden,
        [switch]$FollowRedirects,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 200,
        [switch]$Silent
    )
    $output = [PSCustomObject]@{
        Tool            = 'Extract-Functionalities'
        Timestamp       = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        Target          = if ($Url) { $Url } else { $FilePath }
        PageInfo        = $null
        Forms           = @()
        Links           = @()
        Buttons         = @()
        Scripts         = @()
        MetaTags        = @()
        CsrfFindings    = @()
        Workflows       = @()
        Statistics      = $null
        Frameworks      = @()
        Errors          = @()
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $htmlContent = $null
    $baseUrl = $null
    $pageTitle = $null

    # Phase 1: Source content
    if ($Url) {
        if (-not $Silent) { Write-Output "[*] Fetching URL: $Url" }
        $response = Invoke-WebRequestSafe -Uri $Url -TimeoutSec $Timeout -UserAgent $UserAgent -FollowRedirects:$FollowRedirects
        if ($response.Success) {
            $htmlContent = $response.Content
            $baseUrl = $response.FinalUri
            if (-not $Silent) { Write-Output "[+] Fetched $($htmlContent.Length) bytes from $baseUrl" }
        }
        else {
            $errMsg = "Failed to fetch URL: $Url - $($response.ErrorMessage)"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Warning $errMsg }
        }
    }

    if ($FilePath) {
        if (Test-Path -LiteralPath $FilePath) {
            if (-not $Silent) { Write-Output "[*] Reading file: $FilePath" }
            $htmlContent = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
            if (-not $baseUrl) { $baseUrl = $FilePath }
            if (-not $Silent) { Write-Output "[+] Read $($htmlContent.Length) bytes from $FilePath" }
        }
        else {
            $errMsg = "File not found: $FilePath"
            $errors.Add($errMsg)
            if (-not $Silent) { Write-Error $errMsg }
        }
    }

    if (-not $htmlContent) {
        $errMsg = 'No content available to analyze'
        $errors.Add($errMsg)
        if (-not $Silent) { Write-Error $errMsg }
        return $output
    }

    # Extract page title
    $titleMatch = [regex]::Match($htmlContent, '<title[^>]*>([\s\S]*?)</title>', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($titleMatch.Success) {
        $pageTitle = $titleMatch.Groups[1].Value.Trim()
    }

    # Phase 2: Extract interactive elements
    if (-not $Silent) { Write-Output "[*] Extracting forms..." }
    $forms = Extract-Forms -Html $htmlContent -IncludeHidden:$IncludeHidden
    if (-not $Silent) { Write-Output "[+] Found $($forms.Count) forms" }

    if (-not $Silent) { Write-Output "[*] Extracting links..." }
    $links = Extract-Links -Html $htmlContent -BaseUrl $baseUrl
    if (-not $Silent) { Write-Output "[+] Found $($links.Count) links" }

    if (-not $Silent) { Write-Output "[*] Extracting standalone buttons..." }
    $buttons = Extract-Buttons -Html $htmlContent
    if (-not $Silent) { Write-Output "[+] Found $($buttons.Count) standalone buttons" }

    if (-not $Silent) { Write-Output "[*] Extracting scripts..." }
    $scripts = Extract-Scripts -Html $htmlContent
    if (-not $Silent) { Write-Output "[+] Found $($scripts.Count) script blocks" }

    if (-not $Silent) { Write-Output "[*] Extracting meta tags..." }
    $metaResult = Extract-MetaTags -Html $htmlContent
    $metas = $metaResult.Metas
    $csrfMetas = $metaResult.CsrfMetas
    if (-not $Silent) { Write-Output "[+] Found $($metas.Count) meta tags, $($csrfMetas.Count) CSRF meta tokens" }

    # Phase 3: CSRF detection
    if (-not $Silent) { Write-Output "[*] Detecting CSRF mechanisms..." }
    $csrfFindings = Detect-CsrfMechanism -Html $htmlContent

    # Phase 4: Classify forms by purpose
    if (-not $Silent) { Write-Output "[*] Classifying forms by purpose..." }
    $classifiedForms = [System.Collections.Generic.List[object]]::new()
    $formTypeCounts = @{}
    foreach ($form in $forms) {
        $purpose = Classify-FormByPurpose -Form $form
        $formWithPurpose = $form | Select-Object *
        $formWithPurpose | Add-Member -MemberType NoteProperty -Name 'FormPurpose' -Value $purpose -Force
        $classifiedForms.Add($formWithPurpose)
        if (-not $formTypeCounts.ContainsKey($purpose)) { $formTypeCounts[$purpose] = 0 }
        $formTypeCounts[$purpose]++
    }

    # Phase 5: Build workflow map
    if (-not $Silent) { Write-Output "[*] Building workflow state transitions..." }
    $workflows = Build-WorkflowMap -Forms $forms -Links $links -CurrentUrl $baseUrl

    # Phase 6: Detect frameworks
    if (-not $Silent) { Write-Output "[*] Detecting JavaScript frameworks..." }
    $frameworks = Get-JavaScriptFrameworkInfo -Html $htmlContent

    # Phase 7: Statistics
    $statistics = Get-InteractiveStatistics -Forms $forms -Links $links -Buttons $buttons -Scripts $scripts -Metas $metas

    # Page info
    $pageInfo = [PSCustomObject]@{
        Title        = $pageTitle
        ContentLength = $htmlContent.Length
        ContentType  = if ($Url) { $response.ContentType } else { 'file' }
        BaseUrl      = $baseUrl
    }

    $output.PageInfo = $pageInfo
    $output.Forms = $classifiedForms
    $output.Links = $links
    $output.Buttons = $buttons
    $output.Scripts = $scripts
    $output.MetaTags = $metas
    $output.CsrfFindings = $csrfFindings
    $output.Workflows = $workflows
    $output.Statistics = $statistics
    $output.Frameworks = $frameworks
    $output.FormTypeBreakdown = $formTypeCounts
    $output.Errors = $errors

    # Phase 8: Deep crawl if requested
    if ($Depth -gt 1 -and $baseUrl -match '^https?://') {
        if (-not $Silent) { Write-Output "[*] Deep crawling with depth $Depth..." }
        $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $queue = [System.Collections.Generic.Queue[string]]::new()
        $queue.Enqueue($baseUrl)
        $currentDepth = 0

        while ($queue.Count -gt 0 -and $currentDepth -lt $Depth) {
            $levelSize = $queue.Count
            for ($i = 0; $i -lt $levelSize; $i++) {
                $crawlUrl = $queue.Dequeue()
                if ($visited.Contains($crawlUrl)) { continue }
                $null = $visited.Add($crawlUrl)

                if (-not $Silent) { Write-Output "[*] Crawling: $crawlUrl" }
                Start-Sleep -Milliseconds $RateLimit

                $crawlResponse = Invoke-WebRequestSafe -Uri $crawlUrl -TimeoutSec $Timeout -UserAgent $UserAgent -FollowRedirects:$FollowRedirects
                if (-not $crawlResponse.Success) { continue }

                $crawlHtml = $crawlResponse.Content
                $crawlLinks = Extract-Links -Html $crawlHtml -BaseUrl $crawlUrl

                if ($currentDepth -lt ($Depth - 1)) {
                    foreach ($cl in $crawlLinks) {
                        if ($cl.ResolvedUrl -match '^https?://' -and -not $visited.Contains($cl.ResolvedUrl)) {
                            try {
                                $clUri = [System.Uri]$cl.ResolvedUrl
                                $baseUri = [System.Uri]$baseUrl
                                if ($clUri.Host -eq $baseUri.Host) {
                                    $queue.Enqueue($cl.ResolvedUrl)
                                }
                            }
                            catch {}
                        }
                    }
                }
            }
            $currentDepth++
        }
    }

    # Phase 9: Output
    if ($OutputFile) {
        $outputDir = Split-Path -Parent $OutputFile
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $output | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputFile -Encoding utf8
        if (-not $Silent) { Write-Output "[+] Results written to $OutputFile" }
    }

    if (-not $Silent) {
        Write-Output "`n=== Functionality Extraction Summary ==="
        Write-Output "Page Title: $($pageInfo.Title)"
        Write-Output "Forms: $($statistics.TotalForms) | Links: $($statistics.TotalLinks) | Buttons: $($statistics.TotalButtons)"
        Write-Output "Inputs: $($statistics.TotalInputs) (Hidden: $($statistics.HiddenInputs), Password: $($statistics.PasswordFields), File: $($statistics.FileUploadInputs))"
        Write-Output "Selects: $($statistics.TotalSelects) | Textareas: $($statistics.TotalTextareas)"
        Write-Output "Scripts: $($statistics.TotalScripts) | AJAX Calls: $($statistics.AjaxCallsDetected)"
        Write-Output "Event Handlers: $($statistics.EventHandlersFound) | CSRF Tokens: $($statistics.CsrfTokensDetected)"
        Write-Output "Frameworks: $(if ($frameworks.Count -gt 0) { $frameworks -join ', ' } else { 'None detected' })"
        Write-Output "Workflow Transitions: $($workflows.Count)"
        if ($formTypeCounts.Keys.Count -gt 0) {
            Write-Output "Form Purpose Breakdown:"
            foreach ($key in $formTypeCounts.Keys | Sort-Object) {
                Write-Output "  $key : $($formTypeCounts[$key])"
            }
        }
        if ($errors.Count -gt 0) { Write-Output "Errors: $($errors.Count)" }
    }

    return $output
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$OutputFile,
        [int]$Depth = 1,
        [switch]$IncludeHidden,
        [switch]$FollowRedirects,
        [int]$Timeout = 30,
        [string]$UserAgent,
        [int]$RateLimit = 200,
        [switch]$Silent
    )
    $IncludeHidden = if ($PSBoundParameters.ContainsKey('IncludeHidden')) { $IncludeHidden } else { $true }
    $FollowRedirects = if ($PSBoundParameters.ContainsKey('FollowRedirects')) { $FollowRedirects } else { $true }

    Invoke-UserFunctionalityDiscovery -Url $Url -FilePath $FilePath -OutputFile $OutputFile -Depth $Depth -IncludeHidden:$IncludeHidden -FollowRedirects:$FollowRedirects -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit -Silent:$Silent
}

# Entry point
$Url = $null; $FilePath = $null; $OutputFile = $null; $Depth = 1; $IncludeHidden = $true
$FollowRedirects = $true; $Silent = $false; $Timeout = 30; $UserAgent = $null; $RateLimit = 200

if ($args.Count -gt 0) {
    $i = 0; while ($i -lt $args.Count) {
        switch -Wildcard ($args[$i]) {
            '-Url' { $i++; $Url = $args[$i] }
            '-FilePath' { $i++; $FilePath = $args[$i] }
            '-OutputFile' { $i++; $OutputFile = $args[$i] }
            '-Depth' { $i++; $Depth = [int]$args[$i] }
            '-IncludeHidden' { $IncludeHidden = [bool]::Parse($args[$i + 1]); $i++ }
            '-FollowRedirects' { $FollowRedirects = [bool]::Parse($args[$i + 1]); $i++ }
            '-Silent' { $Silent = $true }
            '-Timeout' { $i++; $Timeout = [int]$args[$i] }
            '-UserAgent' { $i++; $UserAgent = $args[$i] }
            '-RateLimit' { $i++; $RateLimit = [int]$args[$i] }
        }
        $i++
    }
}

try {
    Main -Url $Url -FilePath $FilePath -OutputFile $OutputFile -Depth $Depth -IncludeHidden:$IncludeHidden -FollowRedirects:$FollowRedirects -Timeout $Timeout -UserAgent $UserAgent -RateLimit $RateLimit -Silent:$Silent
}
catch {
    Write-Error "Unhandled exception: $($_.Exception.Message)"
    exit 1
}
