# JS Analysis — Comprehensive Rules

## Table of Contents

1. [Overview & Philosophy](#1-overview--philosophy)
2. [Endpoint Extraction Patterns](#2-endpoint-extraction-patterns)
3. [Secret / Key Regex Catalog](#3-secret--key-regex-catalog)
4. [Feature Flag Mining](#4-feature-flag-mining)
5. [Source Map Analysis](#5-source-map-analysis)
6. [Internal Route Discovery](#6-internal-route-discovery)
7. [Config Leaks](#7-config-leaks)
8. [Hardcoded Credentials](#8-hardcoded-credentials)
9. [Third-Party Integration Keys](#9-third-party-integration-keys)
10. [Bundle Diffing Over Time](#10-bundle-diffing-over-time)
11. [Windows / PowerShell Workflow](#11-windows--powershell-workflow)
12. [Automated Extraction Scripts](#12-automated-extraction-scripts)
13. [Output Prioritization](#13-output-prioritization)

---

## 1. Overview & Philosophy

JavaScript bundles are the single richest source of unintentional information disclosure in modern web applications. Every framework, every CDN, every SPA ships compiled or minified JS that contains:

- API endpoints the developers forgot to gate behind authentication
- Internal hostnames and IP addresses
- Hardcoded API keys, secrets, tokens
- Feature flags that unlock hidden functionality
- Third-party service integration keys
- Source maps that reveal full original source
- Configuration objects with environment-specific values
- Internal route paths, parameter names, and data structures

### Core Principles

1. **Every JS file is a target.** Do not skip files based on size, domain, or perceived importance.
2. **Regex is a starting point, not an ending point.** Manual review of extracted strings catches what automation misses.
3. **Context matters.** A string that looks like an API key but appears in a test file is lower priority than one in a production bundle.
4. **Source maps are the jackpot.** Always check for .map files before deep-diving into minified JS.
5. **Diff over time.** Re-fetch bundles weekly and diff against previous versions to catch newly-introduced secrets.
6. **Prioritize by impact.** Cloud provider keys > JWT secrets > internal endpoints > feature flags > config values.

### Workflow Overview

```
1. Discover JS URLs (waybackurls, gau, katana, manual browser)
2. Fetch all JS files (curl, wget, or Invoke-WebRequest)
3. Check for source maps (append .map to each URL)
4. Run automated regex extraction (grep/Select-String)
5. Manual review of high-value candidates
6. Diff against previous snapshot if available
7. Report findings sorted by impact
```

---

## 2. Endpoint Extraction Patterns

### 2.1 API Route Patterns

Modern SPAs define API routes as string constants or in router configurations. These patterns cover the vast majority of endpoint disclosures.

#### Generic URL/String Extraction

```
Pattern:    (https?://[a-zA-Z0-9./?=_%:-]+)
Target:     Any absolute URL in a JS bundle
Example:    "https://api.target.com/v2/users/1234/profile"
PowerShell: Select-String -Path *.js -Pattern 'https?://[a-zA-Z0-9./?=_%-]+' | %{ $_.Matches.Value } | Sort-Object -Unique
```

```
Pattern:    (["'`])(/[a-zA-Z0-9_/{}.\-]+)\1
Target:     Relative API paths with route parameters
Example:    '/api/v2/users/${userId}/orders'
PowerShell: Select-String -Path *.js -Pattern '["''](/(api|v[0-9]|internal|private|admin|graphql|rest|service|backend|gateway)[a-zA-Z0-9_/{}\.-]*)\1'
```

#### Common API Prefixes

Extract any string matching these path prefixes:

```
/api/, /v1/, /v2/, /v3/, /graphql, /rest/, /internal/
/private/, /admin/, /service/, /gateway/, /backend/
/rpc/, /jsonrpc/, /soap/, /odata/, /mobile/, /app/
/webhook/, /callback/, /events/, /stream/, /ws/, /wss/
/socket.io/, /signalr/, /hub/
```

#### Full Regex for API Endpoint Extraction

```
# Absolute URLs with common API patterns
https?://[a-zA-Z0-9.-]+/(api|v[0-9]|graphql|rest|internal|private|admin|gateway|service|backend|rpc|jsonrpc|odata|webhook|callback|events|stream|ws)[a-zA-Z0-9/._?=%&-]*

# Relative paths that look like API routes
["'`](/api/[a-zA-Z0-9_/.-]*)["'`]

# Paths with route parameters (express-style)
["'`](/[a-zA-Z0-9_]+/:[a-zA-Z0-9_]+)["'`]   (colon-style params)
["'`](/[a-zA-Z0-9_]+/\$\{[a-zA-Z0-9_]+\})["'`]  (template literal params)
```

#### PowerShell Extraction Commands

```powershell
# Extract all absolute URLs
Select-String -Path "*.js" -Pattern 'https?://[^"'`\s>]+' |
    Select-Object -ExpandProperty Matches |
    Select-Object -ExpandProperty Value |
    Sort-Object -Unique |
    Out-File -FilePath "absolute-urls.txt"

# Extract relative API paths
Select-String -Path "*.js" -Pattern "['`](/api/[^'`\s]+)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique |
    Out-File -FilePath "api-paths.txt"

# Extract paths with version numbers
Select-String -Path "*.js" -Pattern "['`](/v[0-9]+/[^'`\s]+)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique |
    Out-File -FilePath "versioned-paths.txt"
```

### 2.2 GraphQL Endpoint Discovery

GraphQL endpoints are frequently exposed but undocumented.

```
# Standard GraphQL paths
/graphql, /graphql/v1, /gql, /query, /graph, /api/graphql
/graphiql, /voyager, /playground

# Regex patterns
Pattern:  (["'`])(/?(graphql|gql|graphiql|voyager|playground)[a-zA-Z0-9/._-]*)\1
Example:  "https://api.target.com/graphql"

# Schema discovery paths (append to base URL)
/graphql?sdl, /graphql/schema, /graphql/schema.json, /graphql.json
```

#### GraphQL Introspection Probe

```powershell
$body = @{query = "query { __schema { types { name } } }"} | ConvertTo-Json
Invoke-RestMethod -Uri "https://target.com/graphql" -Method Post -ContentType "application/json" -Body $body
```

### 2.3 WebSocket Endpoint Discovery

WebSocket connections are often used for real-time features and may expose internal channels.

```
Pattern:  (["'`])(wss?://[a-zA-Z0-9./?=_%:-]+)\1
Example:  "wss://ws.target.com/socket.io/?EIO=4&transport=websocket"

# WebSocket path patterns
/ws, /wss, /socket.io/, /signalr, /hub, /events, /stream, /realtime, /live
```

### 2.4 Internal/Private Path Discovery

Paths containing keywords that suggest internal-only or admin functionality.

```
# Keywords suggesting restricted access
/internal, /private, /admin, /dashboard, /manage, /console
/ops, /operations, /debug, /dev, /staging, /test, /intranet
/corp, /employee, /staff, /moderator, /backoffice, /cms, /management

# Regex
Pattern:  (["'`])(/[a-zA-Z0-9_/]*(internal|private|admin|console|ops|debug|dev|staging|backoffice|cms)[a-zA-Z0-9_/.-]*)\1

PowerShell:
Select-String -Path "*.js" -Pattern "['`](/(?:internal|private|admin|console|ops|debug|dev|staging|backoffice|cms)[^'`\s]*)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique
```

### 2.5 Parameter Name Extraction

Parameter and variable names often reveal undocumented API functionality.

```
# Common parameter patterns
Pattern:  (["'`])([a-zA-Z0-9_]+(?:_id|_uuid|_token|_key|_secret|_hash|_sig|Id|Uuid|Token|Key|Secret))\1
Example:  "organization_id", "access_token", "webhook_secret"

# Extended parameter list
user_id, userId, user_uuid, account_id, org_id
organization_id, team_id, workspace_id, project_id
customer_id, client_id, session_id, request_id
trace_id, correlation_id, access_token, refresh_token
api_token, auth_token, webhook_url, callback_url
redirect_url, api_key, api_secret, app_key, app_secret
signature, hash, hmac, nonce, timestamp, page, limit
offset, cursor, sort, filter, include, expand, fields, embed, depth
```

### 2.6 Fetch/XHR/Axios Call Pattern Extraction

Modern JS makes HTTP calls using fetch, axios, XMLHttpRequest, or wrapper libraries.

```javascript
// Libraries to search for
fetch(
axios.
$.ajax(
XMLHttpRequest
superagent
request(
got(
ky.
httpClient.
apiClient.
client.
```

#### Regex Patterns for API Call Extraction

```
# fetch() calls -- extract the URL argument
Pattern:  fetch\s*\(\s*["'`]([^"'`]+)["'`]
Example:  fetch('https://api.target.com/v2/users')

# axios calls
Pattern:  (axios|apiClient|httpClient)\.(get|post|put|patch|delete|request)\s*\(\s*["'`]([^"'`]+)["'`]
Example:  axios.get('/api/v2/users')

# $.ajax / $.get / $.post
Pattern:  \$\.(ajax|get|post|getJSON)\s*\(\s*["'`]([^"'`]+)["'`]

# Template literal URLs in fetch
Pattern:  fetch\s*\(\s*[^)]+\)
Example:  fetch(`https://api.target.com/v2/users/${userId}`)
```

#### PowerShell Extraction Commands

```powershell
# Extract fetch() URLs
Select-String -Path "*.js" -Pattern "fetch\s*\(\s*['`]([^'`]+)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique

# Extract axios calls with URL
Select-String -Path "*.js" -Pattern "(?:axios|httpClient|apiClient)\.(?:get|post|put|patch|delete|request)\s*\(\s*['`]([^'`]+)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique

# Extract all HTTP method calls
Select-String -Path "*.js" -Pattern "\.(?:get|post|put|patch|delete|options|head)\s*\(\s*['`]([^'`]+)['`]" |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique
```

### 2.7 URL Building Patterns

Many applications construct URLs programmatically.

```
# String concatenation
Pattern:  ["'`]([a-zA-Z0-9_/.-]+)["'`]\s*\+\s*["'`]([a-zA-Z0-9_/.-]+)["'`]
Example:  '/api/v2/' + userId + '/profile'

# Template literals
Pattern:  `/[a-zA-Z0-9_/.-]*\$\{[^}]+\}[a-zA-Z0-9_/.-]*`
Example:  `/api/v2/users/${userId}/orders/${orderId}`

# .replace() URL construction
Pattern:  ["'`]([^"'`]+)["'`]\.replace\(["'`]([^"'`]+)["'`],\s*["'`]([^"'`]+)["'`]
```

### 2.8 Hardcoded IPs and Hostnames

Internal IP addresses and hostnames reveal network topology.

```
# IPv4 addresses
Pattern:  (?:[0-9]{1,3}\.){3}[0-9]{1,3}
Example:  10.0.1.45, 192.168.1.100, 172.16.0.50

# Private IP ranges (higher priority)
10\.\d{1,3}\.\d{1,3}\.\d{1,3}
172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}
192\.168\.\d{1,3}\.\d{1,3}

# Internal hostnames
Pattern:  ([a-zA-Z0-9-]+\.internal|[a-zA-Z0-9-]+\.local|[a-zA-Z0-9-]+\.corp|[a-zA-Z0-9-]+\.intranet|[a-zA-Z0-9-]+\.private)
Example:  db-01.internal, mail.corp, jenkins.intranet

# Internal domain suffixes
.internal, .local, .corp, .intranet, .private
.cloud, .ec2.internal, compute.amazonaws.com
rds.amazonaws.com, elasticbeanstalk.com
```

#### PowerShell Extraction for Internal IPs

```powershell
# Extract all IP addresses
Select-String -Path "*.js" -Pattern '(?:\d{1,3}\.){3}\d{1,3}' |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Where-Object { $_ -notmatch '^(?:127\.|0\.|255\.)' } |
    Out-File -FilePath "ip-addresses.txt"

# Extract private IPs specifically
Select-String -Path "*.js" -Pattern '(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})' |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "private-ips.txt"
```


---

## 3. Secret / Key Regex Catalog

### 3.1 Cloud Provider Keys

#### AWS Access Keys

```
# AWS Access Key ID + Secret Access Key (often together)
Pattern:  (?:AKIA|ASIA)[A-Z0-9]{16}
Example:  AKIAIOSFODNN7EXAMPLE

# AWS Secret Access Key (40 chars base64)
Pattern:  (?:"|'|`)[A-Za-z0-9/+=]{40}(?:"|'|`)
Example:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AWS session token (temporary credentials) -- 100+ chars
Pattern:  (?:"|'|`)[A-Za-z0-9/+=]{100,}(?:"|'|`)
```

PowerShell extraction:
```powershell
Select-String -Path "*.js" -Pattern '(?:AKIA|ASIA)[A-Z0-9]{16}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "aws-keys.txt"
```

#### GCP Service Account Keys

```
# GCP Service Account Private Key (JSON format)
Pattern:  "private_key":\s*"-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9\n/+=]+-----END PRIVATE KEY-----\n"
Example:  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY=\n-----END PRIVATE KEY-----\n"

# GCP API Key
Pattern:  AIza[0-9A-Za-z_-]{35}
Example:  AIzaSyDc6d6xYhG9vE2YzQ7zQ7zQ7zQ7zQ7zQ7zQ7zQ

# GCP OAuth Client ID
Pattern:  \d{12}-[A-Za-z0-9]{32}\.apps\.googleusercontent\.com
Example:  123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com
```

#### Azure Keys

```
# Azure Subscription ID / Tenant ID (UUID format)
Pattern:  (?:"|'|`)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:"|'|`)
Example:  "123e4567-e89b-12d3-a456-426614174000"

# Azure Storage Account Key (88 chars base64)
Pattern:  (?:"|'|`)[A-Za-z0-9+/=]{88}(?:"|'|`)
Example:  "qO0p6Vq8xU2wY9a1b3c5d7e9f0g2h4j6k8l0m2n4o6p8q0r2s4t6u8v0w2x4y6z8A=="

# Azure Connection String
Pattern:  DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+

# Azure SQL Connection String
Pattern:  Server=tcp:[a-zA-Z0-9.-]+\.database\.windows\.net,1433;Initial Catalog=[^;]+;User ID=[^;]+;Password=[^;]+;
Example:  Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;User ID=admin;Password=P@ssw0rd;

# Azure DevOps PAT
Pattern:  (?:"|'|`)[a-z0-9]{52}(?:"|'|`)
```

#### Alibaba Cloud / DigitalOcean

```
# Alibaba Cloud AccessKey ID
Pattern:  LTAI[A-Za-z0-9]{12,}
Example:  LTAI5tAbCdEfGhIjKlMnOpQr

# DigitalOcean Personal Access Token
Pattern:  dop_v1_[a-f0-9]{64}
Example:  dop_v1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

### 3.2 Authentication / Token Services

#### JWT Tokens

```
# JWT (JSON Web Token) -- unverified (just structural match)
Pattern:  eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
Example:  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHq4w2N0e1g

# JWT with "Bearer" context
Pattern:  ["'`]Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}["'`]

# JWT secret / signing key
Pattern:  ["'`](?:jwt|JWT|secret|signingKey|signing_key|privateKey)[^:]*:\s*["'`]([^"'`]+)["'`]
Example:  "jwtSecret": "mySuperSecretKey123!"
```

```powershell
Select-String -Path "*.js" -Pattern 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "jwt-tokens.txt"
```

#### Firebase

```
# Firebase API Key
Pattern:  AIza[0-9A-Za-z_-]{35}
Example:  AIzaSyCkL9vM6qNJ8q5h4q0q4q0q4q0q4q0q4q0q4q0

# Firebase Database URL
Pattern:  https://[a-zA-Z0-9-]+\.(?:firebaseio|firebasedatabase)\.com/
Example:  https://my-app.firebaseio.com/

# Firebase Config Block (extract entire initializeApp call)
Pattern:  firebase\.initializeApp\(\{([^}]+)\)
```

#### Auth0

```
# Auth0 Domain
Pattern:  [a-zA-Z0-9-]+\.auth0\.com
Example:  myapp.auth0.com

# Auth0 Client ID (32 chars)
Pattern:  [A-Za-z0-9]{32}
(Context: near "auth0" or "AUTH0")

# Auth0 Audience / API Identifier
Pattern:  https://[a-zA-Z0-9-]+\.auth0\.com/api/v2/
```

#### Okta

```
# Okta Domain
Pattern:  https://[a-zA-Z0-9-]+\.okta\.com
Example:  https://mycompany.okta.com

# Okta API Token
Pattern:  (?:"|'|`)(?:00[A-Za-z0-9_-]{38,40})(?:"|'|`)
Example:  "00AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd"

# Okta Client ID
Pattern:  (?:"|'|`)0oa[A-Za-z0-9]{22}(?:"|'|`)
```

#### Supabase

```
# Supabase URL
Pattern:  https://[a-zA-Z0-9-]+\.supabase\.co
Example:  https://myproject.supabase.co

# Supabase Service Role Key (HIGH CRITICALITY)
Pattern:  ["'`]eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}["'`]
(Labeled as "service_role" or "serviceRole" nearby)
```

### 3.3 SaaS / Platform API Keys

#### Stripe

```
# Stripe Publishable Key (test)
Pattern:  pk_test_[A-Za-z0-9]{24}
Example:  pk_test_51H4abcdefghijklmnopqrstuvwxyz

# Stripe Publishable Key (live)
Pattern:  pk_live_[A-Za-z0-9]{24}
Example:  pk_live_51H4abcdefghijklmnopqrstuvwxyzABCD

# Stripe Secret Key (test) -- CRITICAL
Pattern:  sk_test_[A-Za-z0-9]{24,}
Example:  sk_test_USE_SHORT_EXAMPLE

# Stripe Secret Key (live) -- CRITICAL
Pattern:  sk_live_[A-Za-z0-9]{24,}
Example:  sk_live_USE_SHORT_EXAMPLE

# Stripe Restricted Key
Pattern:  rk_live_[A-Za-z0-9]{24,}

# Stripe Webhook Signing Secret
Pattern:  whsec_[A-Za-z0-9]{32}
Example:  whsec_abcdefghijklmnopqrstuvwxyz123456
```

```powershell
Select-String -Path "*.js" -Pattern '(?:sk_live|sk_test|pk_live|pk_test|rk_live|whsec)_[A-Za-z0-9]{8,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "stripe-keys.txt"
```

#### GitHub

```
# GitHub Personal Access Token (classic)
Pattern:  ghp_[A-Za-z0-9]{36}
Example:  ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ

# GitHub Personal Access Token (fine-grained)
Pattern:  github_pat_[A-Za-z0-9_]{82}
Example:  github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

# GitHub OAuth Access Token
Pattern:  gho_[A-Za-z0-9]{36}

# GitHub App Installation Token
Pattern:  ghs_[A-Za-z0-9]{36}

# GitHub Refresh Token
Pattern:  ghr_[A-Za-z0-9]{36}
```

```powershell
Select-String -Path "*.js" -Pattern 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gh[osru]_[A-Za-z0-9]{36}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "github-tokens.txt"
```

#### GitLab

```
# GitLab Personal Access Token
Pattern:  glpat-[A-Za-z0-9_-]{20,}
Example:  glpat-AbCdEfGhIjKlMnOpQrSt

# GitLab CI Job Token
Pattern:  (?:"|'|`)glopt-[A-Za-z0-9_-]{20,}(?:"|'|`)
```

#### Slack

```
# Slack Bot Token
Pattern:  xoxb-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}
Example:  xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX

# Slack Webhook URL
Pattern:  https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+
Example:  [see pattern above — example omitted]

# Slack App Token
Pattern:  xapp-[0-9]-[A-Za-z0-9_-]{70,}
Example:  xapp-1-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz

# Slack User Token
Pattern:  xoxp-[0-9]{10,12}-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{32}
```

```powershell
Select-String -Path "*.js" -Pattern 'xox[bpa]-[A-Za-z0-9_-]{20,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "slack-tokens.txt"

Select-String -Path "*.js" -Pattern 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "slack-webhooks.txt"
```

#### Discord

```
# Discord Bot Token
Pattern:  [A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}
Example:  AbCdEfGhIjKlMnOpQrStUvWx.Yz0123.AbCdEfGhIjKlMnOpQrStUvWxYz012345678

# Discord Webhook URL
Pattern:  https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+
Example:  https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz
```

#### Twilio / SendGrid / Mailgun

```
# Twilio Account SID
Pattern:  AC[A-Za-z0-9]{32}
Example:  ACxxxx_EXAMPLE_xxxxxxxxxxxxxx

# Twilio Auth Token (32 chars hex)
Pattern:  (?:"|'|`)[A-Za-z0-9]{32}(?:"|'|`)
Example:  "abcdef1234567890abcdef1234567890"

# Twilio API Key
Pattern:  SK[A-Za-z0-9]{32}

# SendGrid API Key
Pattern:  SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
Example:  SG.AbCdEfGhIjKlMnOpQrStUvWx.Yz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123

# Mailgun API Key
Pattern:  key-[A-Za-z0-9]{32}
Example:  key-abcdefghijklmnopqrstuvwxyz123456

# Mailchimp API Key
Pattern:  [a-f0-9]{32}-us[0-9]{1,2}
Example:  [example omitted — see pattern]
```

#### Map Services

```
# Google Maps API Key
Pattern:  AIza[0-9A-Za-z_-]{35}

# Mapbox Access Token (public)
Pattern:  pk\.[A-Za-z0-9_-]{60}\.[A-Za-z0-9_-]{22}
Example:  pk.eyJ1IjoibXl1c2VyIiwiYSI6ImNraWRhIn0.abcdefghijklmnopqrstuvwxyz

# Mapbox Secret Token
Pattern:  sk\.[A-Za-z0-9_-]{60}\.[A-Za-z0-9_-]{22}

# Bing Maps Key
Pattern:  Ag[A-Za-z0-9_-]{60,}
```

### 3.4 Database Connection Strings

```
# MongoDB Connection String
Pattern:  mongodb(?:\+srv)?://[^/\s]+/[a-zA-Z0-9_-]+(?:\?[^\s"']*)?
Example:  mongodb+srv://admin:P@ssw0rd@cluster0.mongodb.net/mydb?retryWrites=true

# PostgreSQL Connection String
Pattern:  postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[a-zA-Z0-9_-]+
Example:  postgresql://user:password@localhost:5432/mydb

# MySQL Connection String
Pattern:  mysql://[^:\s]+:[^@\s]+@[^/\s]+/[a-zA-Z0-9_-]+
Example:  mysql://user:password@localhost:3306/mydb

# Redis Connection String
Pattern:  redis://(?::[^@\s]+@)?[^/\s]+:[0-9]+
Example:  redis://:password@localhost:6379

# Generic JDBC String
Pattern:  jdbc:[a-zA-Z]+://[^:\s]+:[0-9]+/[a-zA-Z0-9_?-]+
Example:  jdbc:mysql://localhost:3306/mydb?useSSL=false
```

```powershell
Select-String -Path "*.js" -Pattern 'mongodb(?:\+srv)?://[^\s"'`]+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "mongodb-uris.txt"
```

### 3.5 AI / LLM Provider Keys

```
# OpenAI API Key
Pattern:  sk-[A-Za-z0-9]{32,}
Example:  sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz

# OpenAI Organization ID
Pattern:  org-[A-Za-z0-9]{24,}
Example:  org-AbCdEfGhIjKlMnOpQrStUvWx

# Anthropic API Key
Pattern:  sk-ant-[A-Za-z0-9]{32,}
Example:  sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef

# Anthropic API Key (v2 format)
Pattern:  sk-ant-api03-[A-Za-z0-9_-]{60,}

# Hugging Face Token
Pattern:  hf_[A-Za-z0-9]{34,}
Example:  hf_AbCdEfGhIjKlMnOpQrStUvWxYz012345678

# Replicate API Token
Pattern:  r8_[A-Za-z0-9]{37,}
Example:  r8_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf

# Google AI (Gemini) API Key
Pattern:  AIza[0-9A-Za-z_-]{35}
(Context: "gemini" or "GEMINI" or "palm" nearby)
```

```powershell
Select-String -Path "*.js" -Pattern 'sk-[A-Za-z0-9]{32,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "openai-keys.txt"

Select-String -Path "*.js" -Pattern 'sk-ant-[A-Za-z0-9]{20,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "anthropic-keys.txt"

Select-String -Path "*.js" -Pattern 'hf_[A-Za-z0-9]{30,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "huggingface-tokens.txt"
```

### 3.6 Monitoring / Logging Services

```
# Datadog API Key (32 hex chars)
Pattern:  (?:"|'|`)[a-f0-9]{32}(?:"|'|`)
(Context: "datadog" or "DATADOG" or "DD_API_KEY" nearby)

# Datadog Application Key (40 hex chars)
Pattern:  (?:"|'|`)[a-f0-9]{40}(?:"|'|`)
(Context: "datadog" or "DATADOG" nearby)

# New Relic API Key
Pattern:  (?:"|'|`)NRAK-[A-Za-z0-9]{27}(?:"|'|`)

# Sentry DSN
Pattern:  https://[a-f0-9]{64}@[a-zA-Z0-9.-]+/[0-9]+
Example:  https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/1234567

# Sentry Auth Token
Pattern:  (?:"|'|`)[a-f0-9]{64}(?:"|'|`)
(Context: "sentry" or "SENTRY" nearby)

# Rollbar Access Token
Pattern:  (?:"|'|`)[a-f0-9]{32}(?:"|'|`)
(Context: "rollbar" or "ROLLBAR" nearby)
```

```powershell
Select-String -Path "*.js" -Pattern 'https://[a-f0-9]{32,}@[a-zA-Z0-9.-]+\.[a-z]+/[0-9]+' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "sentry-dsns.txt"
```

### 3.7 Private Keys / Certificates

```
# RSA Private Key
Pattern:  -----BEGIN (?:RSA |EC )?PRIVATE KEY-----\n[\sA-Za-z0-9+/=]+-----END (?:RSA |EC )?PRIVATE KEY-----
Example:  -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...

# SSH Private Key
Pattern:  -----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----

# SSH Public Key
Pattern:  ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]+

# Certificate
Pattern:  -----BEGIN CERTIFICATE-----\n[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----
```

### 3.8 Hardcoded Credential Patterns

```
# Generic credential assignment
Pattern:  ["'`](?:password|passwd|pwd|secret|passphrase)\s*["'`]\s*[:=]\s*["'`]([^"'`]{4,})["'`]
Example:  "password": "P@ssw0rd123!"

# Base64-encoded credentials (Authorization headers)
Pattern:  (?:Basic\s+)([A-Za-z0-9+/]{20,}={0,2})
Example:  Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

# Username:password in URL
Pattern:  https?://[^:\s]+:[^@\s]+@
Example:  https://admin:P@ssw0rd@internal.example.com
```

```powershell
# Extract password-like assignments
Select-String -Path "*.js" -Pattern "['`](?:password|passwd|pwd|secret|passphrase)['`]\s*[:=]\s*['`]([^'`]{4,})['`]" -AllMatches |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique |
    Out-File -FilePath "hardcoded-passwords.txt"
```

### 3.9 High-Entropy String Detection

For strings that don't match known patterns but look like they could be secrets:

```
# High-entropy base64-like strings (40+ chars)
Pattern:  [A-Za-z0-9+/]{40,}={0,2}

# High-entropy hex strings (32+ chars)
Pattern:  [a-f0-9]{32,}

# High-entropy alphanumeric strings (30+ chars)
Pattern:  [A-Za-z0-9_-]{30,}
```

```powershell
# Entropy calculation function
function Get-Entropy {
    param([string]$s)
    $freq = @{}
    $s.ToCharArray() | ForEach-Object { $freq[$_]++ }
    $entropy = 0.0
    $len = $s.Length
    $freq.Values | ForEach-Object {
        $p = $_ / $len
        if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
    }
    return $entropy
}

# Extract high-entropy strings
Select-String -Path "*.js" -Pattern '[A-Za-z0-9]{30,}' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Where-Object { (Get-Entropy $_) -gt 4.0 } |
    Out-File -FilePath "high-entropy-strings.txt"
```

### 3.10 Semantic Key Lookup (Key Name Mining)

Sometimes keys are stored in variables that describe their purpose.

```powershell
# Semantic variable name extraction
$keyNames = @(
    "api_key", "apiKey", "apikey", "api_secret", "apiSecret"
    "app_key", "appKey", "app_secret", "appSecret"
    "access_key", "accessKey", "access_key_id", "accessKeyId"
    "secret_key", "secretKey", "secret_access_key", "secretAccessKey"
    "client_id", "clientId", "client_secret", "clientSecret"
    "consumer_key", "consumerKey", "consumer_secret", "consumerSecret"
    "auth_token", "authToken", "authentication_token", "authenticationToken"
    "webhook_secret", "webhookSecret", "webhook_url", "webhookUrl"
    "slack_token", "slackToken", "slack_webhook", "slackWebhook"
    "stripe_key", "stripeKey", "stripe_secret", "stripeSecret"
    "github_token", "githubToken", "github_access_token", "githubAccessToken"
    "aws_key", "awsKey", "aws_secret", "awsSecret"
    "jwt_secret", "jwtSecret", "jwt_signing_key", "jwtSigningKey"
    "encryption_key", "encryptionKey", "encryption_secret", "encryptionSecret"
    "hmac_secret", "hmacSecret", "hmac_key", "hmacKey"
    "private_key", "privateKey", "public_key", "publicKey"
    "session_secret", "sessionSecret", "cookie_secret", "cookieSecret"
)
$keyPattern = "['`]($($keyNames -join '|'))['`]\s*[:=]\s*['`]([^'`]{8,})['`]"
Select-String -Path "*.js" -Pattern $keyPattern -AllMatches |
    ForEach-Object {
        [PSCustomObject]@{
            KeyName = $_.Matches.Groups[1].Value
            KeyValue = $_.Matches.Groups[2].Value
            File = $_.Path
            Line = $_.LineNumber
        }
    } | Export-Csv -Path "semantic-keys.csv" -NoTypeInformation
```

### 3.11 Quick-Reference Table: All Key Patterns

| Service | Pattern | Example | Severity |
|---------|---------|---------|----------|
| AWS Access Key | (?:AKIA\|ASIA)[A-Z0-9]{16} | AKIAIOSFODNN7EXAMPLE | CRITICAL |
| AWS Secret Key | [A-Za-z0-9/+=]{40} | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY | CRITICAL |
| GCP API Key | AIza[0-9A-Za-z_-]{35} | AIzaSyCkL9vM6qNJ8q5h4q0q4q0q4q0q4q0q4q0q4q0 | CRITICAL |
| GCP OAuth Client | \d{12}-[A-Za-z0-9]{32}\.apps\.googleusercontent\.com | 123456789012-abc...@apps.googleusercontent.com | HIGH |
| Azure Storage Key | [A-Za-z0-9+/=]{88} | qO0p6Vq8xU2wY9a1b3c5d7e9f0g2h4j6k8l0m2n4o6p8q0r2s4t6u8v0w2x4y6z8A== | CRITICAL |
| Stripe Live Secret | sk_live_[A-Za-z0-9]{24,} | sk_live_51H4abcd... | CRITICAL |
| Stripe Test Secret | sk_test_[A-Za-z0-9]{24,} | sk_test_51H4abcd... | HIGH |
| Stripe Pub Live | pk_live_[A-Za-z0-9]{24,} | pk_live_51H4abcd... | MEDIUM |
| Stripe Webhook Key | whsec_[A-Za-z0-9]{32} | whsec_abcdef... | CRITICAL |
| GitHub PAT (classic) | ghp_[A-Za-z0-9]{36} | ghp_abcdefghijkl... | CRITICAL |
| GitHub PAT (fine) | github_pat_[A-Za-z0-9_]{82} | github_pat_11ABC... | CRITICAL |
| GitHub OAuth | gh[osru]_[A-Za-z0-9]{36} | gho_abcdefghijkl... | CRITICAL |
| GitLab Token | glpat-[A-Za-z0-9_-]{20,} | glpat-AbCdEfGhIjK... | CRITICAL |
| Slack Bot | xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{24} | xoxb-123-456-abc... | CRITICAL |
| Slack Webhook | https://hooks.slack.com/services/... | hooks.slack.com/services/T00/B00/x | CRITICAL |
| Slack User | xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{32} | xoxp-123-456-789-abc... | CRITICAL |
| SendGrid | SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+ | SG.AbCdEfGhIjKl... | CRITICAL |
| Twilio Account | AC[A-Za-z0-9]{32} | AC1234567890abcd... | HIGH |
| Twilio API Key | SK[A-Za-z0-9]{32} | SK1234567890abcd... | HIGH |
| Mailgun | key-[A-Za-z0-9]{32} | key-abcdef123456... | HIGH |
| Mailchimp | [a-f0-9]{32}-us[0-9]{1,2} | abcdef12-us10 | MEDIUM |
| Mapbox Public | pk\.[A-Za-z0-9_-]{60}\.[A-Za-z0-9_-]{22} | pk.eyJ1IjoiLi4u... | MEDIUM |
| Mapbox Secret | sk\.[A-Za-z0-9_-]{60}\.[A-Za-z0-9_-]{22} | sk.eyJ1IjoiLi4u... | CRITICAL |
| OpenAI | sk-[A-Za-z0-9]{32,} | sk-proj-AbCdEfGh... | CRITICAL |
| Anthropic | sk-ant-[A-Za-z0-9]{32,} | sk-ant-AbCdEfGh... | CRITICAL |
| Hugging Face | hf_[A-Za-z0-9]{34,} | hf_AbCdEfGhIjKlM... | CRITICAL |
| Replicate | r8_[A-Za-z0-9]{37,} | r8_AbCdEfGhIjKlM... | CRITICAL |
| Firebase URL | [a-z0-9-]+\.firebaseio\.com | my-app.firebaseio.com | MEDIUM |
| Discord Bot | [A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27} | AbCdEfGhIjKlM... | CRITICAL |
| Discord Webhook | https://discord.com/api/webhooks/[0-9]+/... | discord.com/api/webhooks/123/abc | HIGH |
| JWT Token | eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+ | eyJhbGciOiJIUzI1NiJ9... | HIGH |
| MongoDB URI | mongodb(?:\+srv)?://[^\s]+ | mongodb+srv://user:pass@cluster | HIGH |
| PostgreSQL URI | postgres(?:ql)?://[^\s]+ | postgresql://user:pass@host | HIGH |
| Sentry DSN | https://[a-f0-9]{64}@[a-z0-9.-]+/[0-9]+ | https://abc@o123.ingest.sentry.io/1 | MEDIUM |
| Private Key | -----BEGIN (?:RSA\|EC\|OPENSSH) PRIVATE KEY----- | -----BEGIN RSA PRIVATE KEY----- | CRITICAL |
| Okta Token | 00[A-Za-z0-9_-]{38,40} | 00AbCdEfGhIjKlM... | HIGH |
| Auth0 Domain | [a-z0-9-]+\.auth0\.com | myapp.auth0.com | LOW |
| Supabase URL | [a-z0-9-]+\.supabase\.co | myproject.supabase.co | LOW |
| New Relic | NRAK-[A-Za-z0-9]{27} | NRAK-AbCdEfGhIjK... | HIGH |



---

## 4. Feature Flag Mining

### 4.1 Flag Variable Patterns

Feature flags control which features are visible or enabled. They often contain meaningful names that hint at unreleased or internal functionality.

```
# Common flag variable naming patterns
Pattern:  (?:is|has|show|enable|disable|use|can|allow|flag|feature)_?[A-Za-z0-9_]+(?:\s*[:=]\s*(?:true|false|![01]))
Example:  isAdminPanelEnabled: true
          showBetaFeatures: true
          allowPaymentBypass: false

# Feature flag objects
Pattern:  (?:features|featureFlags|flags|experiments|toggles)\s*[:=]\s*\{[^}]+\}
Example:  features: { adminPanel: true, betaUI: false, experimentalAPI: true }

# LaunchDarkly-style flags
Pattern:  (?:ldClient|launchDarkly|LD)\.(?:variation|toggle|boolVariation)\s*\(["'`]([^"'`]+)["'`]
Example:  ldClient.variation("admin-dashboard", user, false)

# Split.io-style flags
Pattern:  (?:splitClient|split\.io)\.getTreatment\s*\(["'`]([^"'`]+)["'`]

# Flagsmith-style flags
Pattern:  (?:flagsmith)\.(?:hasFeature|getValue)\s*\(["'`]([^"'`]+)["'`]
```

### 4.2 High-Value Flag Names

These flag names frequently appear in production JS and indicate restricted functionality:

```
admin, adminPanel, admin_dashboard, dashboard
beta, betaFeatures, beta_access
experimental, experimentalFeatures
internal, internalAccess, internal_tools
debug, debugMode, developer, developerMode
staff, staffOnly, employee, employeeOnly
moderator, moderate
premium, enterprise, pro, proFeatures
paid, subscription, payment, billing
api_access, webhook, webhook_access
export, exportData, import, bulk, bulkActions
delete, hardDelete, impersonate, sudo, superuser
rootAccess, bypass, override
maintenance, maintenanceMode, migration, rollout
```

### 4.3 Flag Enumeration Regex

```
# Catch-all for feature flag definitions
Pattern:  ["'`]([a-z]+(?:Flag|Toggle|Enabled|Disabled|Active|Visible)[a-zA-Z0-9]*)["'`]\s*:\s*(true|false|![01])
Example:  "betaFeatureFlagEnabled": true

# Environment-based flags
Pattern:  (?:env|environment|NODE_ENV)\s*[:=]\s*["'`]([a-z]+)["'`]
Example:  "environment": "staging"
```

```powershell
Select-String -Path "*.js" -Pattern "['`]([a-z]+(?:Flag|Toggle|Enabled|Disabled|Active))['`]\s*:\s*(?:true|false)" -AllMatches |
    ForEach-Object {
        [PSCustomObject]@{
            Flag = $_.Matches.Groups[1].Value
            Value = $_.Matches.Groups[2].Value
            File = $_.Path
            Line = $_.LineNumber
        }
    } | Where-Object { $_.Value -eq "true" } |
    Export-Csv -Path "active-feature-flags.csv" -NoTypeInformation
```

---

## 5. Source Map Analysis

### 5.1 Source Map Discovery

Source maps (.map files) can reveal the full original, unminified source code. They are the highest-value target in JS analysis.

```
# URL patterns for source maps
Pattern:  //# sourceMappingURL=([^\s]+)
Example:  //# sourceMappingURL=bundle.js.map

# Inline source map (base64)
Pattern:  //# sourceMappingURL=data:application/json;base64,([A-Za-z0-9+/=]+)
```

#### Source Map Fetch Workflow

```bash
# For each JS file, check if .map exists
# If JS URL is: https://cdn.example.com/js/main.a1b2c3.js
# Check:       https://cdn.example.com/js/main.a1b2c3.js.map
# Check:       https://cdn.example.com/js/main.js.map

# curl source map check
curl -s -o /dev/null -w "%{http_code}" "https://cdn.example.com/js/main.a1b2c3.js.map"
curl -s "https://cdn.example.com/js/main.a1b2c3.js.map" -o main.js.map
```

```powershell
# Source map URL extraction
Select-String -Path "*.js" -Pattern 'sourceMappingURL=([^\s]+)' -AllMatches |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique |
    Out-File -FilePath "sourcemap-urls.txt"

# Source map fetch
$maps = Get-Content "sourcemap-urls.txt"
foreach ($map in $maps) {
    $url = $map
    if ($url -like "/*") { $url = "https://target.com$map" }
    $filename = [System.IO.Path]::GetFileName($map)
    try {
        Invoke-WebRequest -Uri $url -OutFile "maps/$filename" -ErrorAction Stop
        Write-Host "Downloaded: $filename"
    } catch {
        Write-Host "Failed: $url"
    }
}
```

### 5.2 Source Map Parsing

Once you have a source map, you can extract the original source files:

```javascript
// Source map format (JSON):
{
  "version": 3,
  "sources": ["webpack:///src/app.ts", "webpack:///src/utils/api.ts"],
  "sourcesContent": ["// Original source code here..."],
  "mappings": "...base64 VLQ mappings..."
}
```

#### Source Map Extraction

```bash
# Using source-map (Node.js)
npm install -g source-map
node -e "
const sourceMap = require('source-map');
const fs = require('fs');
const rawMap = JSON.parse(fs.readFileSync('bundle.js.map', 'utf8'));
rawMap.sources.forEach((source, i) => {
  const content = rawMap.sourcesContent && rawMap.sourcesContent[i];
  if (content) {
    fs.writeFileSync(source.replace(/[\/]/g, '_'), content);
    console.log('Extracted:', source);
  }
});
"
```

```powershell
# PowerShell source map parsing
$map = Get-Content "bundle.js.map" -Raw | ConvertFrom-Json
$i = 0
$map.sources | ForEach-Object {
    $sourceName = $_ -replace '[\/:]', '_'
    $content = $map.sourcesContent[$i]
    if ($content) {
        $content | Out-File -FilePath "extracted/$sourceName" -Encoding utf8
        Write-Host "Extracted: $sourceName"
    }
    $i++
}
```

### 5.3 Source Map Indicators of Interest

When examining source map output, prioritize files containing:

```
/src/server/           # Server-side code leaked in client bundle
/src/admin/            # Admin panel code
/src/internal/         # Internal tools
/src/backend/          # Backend logic
/src/config/           # Configuration
/private/
/api/                  # API route definitions
/routes/
/middleware/
/auth/
/permissions/
/roles/
/webhooks/
/integrations/
/secret.ts
/secrets.ts
/credentials.ts
/tokens.ts
/passwords.ts
/env.ts
/environment.ts
/config.ts
/constants.ts
/endpoints.ts
```

### 5.4 Source Map Discovery Automation

```powershell
# Batch source map check
$jsUrls = Get-Content "js-urls.txt"
foreach ($url in $jsUrls) {
    $patterns = @(
        "$url.map",
        $url -replace '\.js$', '.js.map',
        $url -replace '\.min\.js$', '.js.map'
    )
    foreach ($mapUrl in $patterns) {
        try {
            $req = [System.Net.WebRequest]::Create($mapUrl)
            $req.Method = "HEAD"
            $req.Timeout = 5000
            $resp = $req.GetResponse()
            if ($resp.StatusCode -eq 200) {
                Write-Host "FOUND: $mapUrl" -ForegroundColor Green
            }
            $resp.Close()
        } catch { }
    }
}
```

---

## 6. Internal Route Discovery

### 6.1 Route Definition Extraction

```
# React Router route definitions
Pattern:  (?:Route|route)\s*\(\s*\{[^}]*path:\s*["'`]([^"'`]+)["'`]
Example:  <Route path="/admin/users" component={AdminUsers} />

# Express-style route definitions
Pattern:  (?:router|app)\.(?:get|post|put|patch|delete|use)\s*\(["'`]([^"'`]+)["'`]
Example:  router.get('/api/v2/admin/users', authenticate, adminOnly, handler)

# Vue Router route definitions
Pattern:  path:\s*["'`]([^"'`]+)["'`].*?component:
Example:  { path: '/admin/dashboard', component: AdminDashboard }

# Angular route definitions
Pattern:  \{[\s\S]*?path:\s*["'`]([^"'`]+)["'`][\s\S]*?\}
Example:  { path: 'admin/users', component: AdminUsersComponent }
```

```powershell
# Extract all React route paths
Select-String -Path "*.js" -Pattern "(?:Route|route)\s*\(\s*\{[^}]*path:\s*['`]([^'`]+)['`]" -AllMatches |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique |
    Out-File -FilePath "route-paths.txt"
```

### 6.2 Route Parameter Extraction

Route parameters reveal the data models and query capabilities of internal APIs.

```
# Colon-style parameters (Express, Ruby on Rails)
Pattern:  ["'`](/[a-zA-Z0-9_/.-]*(?::[a-zA-Z0-9_]+)+[a-zA-Z0-9_/.-]*)["'`]
Example:  '/api/users/:userId/orders/:orderId'

# Template literal parameters
Pattern:  `/[a-zA-Z0-9_/.-]*(?:\$\{[a-zA-Z0-9_.]+\})+[a-zA-Z0-9_/.-]*`
Example:  `/api/users/${userId}/orders/${orderId}`

# Named URL parameters (C#/.NET style)
Pattern:  ["'`](/[a-zA-Z0-9_/.-]*\{[a-zA-Z0-9_]+\}[a-zA-Z0-9_/.-]*)["'`]
Example:  '/api/users/{userId}/orders/{orderId}'
```

### 6.3 Admin/Internal Route Discovery

Look for route definitions that suggest restricted access:

```
# Admin routes
/admin, /administration, /backoffice, /dashboard/admin

# Internal tool routes
/internal, /ops, /operations, /devtools, /console
/debug, /status, /health, /metrics, /monitoring, /logs, /audit

# Management routes
/users/manage, /users/admin, /users/impersonate, /users/sudo
/users/become, /teams/manage, /organizations/manage
/billing/admin, /subscriptions/admin

# Data export routes
/export, /data/export, /reports, /reports/admin
/analytics, /analytics/admin, /stats, /stats/detailed

# Configuration routes
/config, /settings/admin, /preferences
/feature-flags, /feature_toggles, /rollout
/maintenance, /maintenance-mode
```

### 6.4 Internal API Pattern Summary

```
# Full regex for internal route discovery
Pattern:  ["'`](/[a-zA-Z0-9_/.-]*)(?:admin|internal|private|dashboard|console|ops|management|backoffice|cms|moderate|staff|employee|sudo|impersonate|bypass|override|debug|dev|staging|beta|experimental)([a-zA-Z0-9_/.-]*)["'`]
```

```powershell
Select-String -Path "*.js" -Pattern "['`](?:/[a-zA-Z0-9_/.-]*)(?:admin|internal|private|dashboard|console|ops|management|backoffice|cms|staff|sudo|impersonate|bypass|override|debug)(?:[a-zA-Z0-9_/.-]*)['`]" -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
    Out-File -FilePath "internal-routes.txt"
```

---

## 7. Config Leaks

### 7.1 Client-Side Configuration Objects

Modern SPAs embed configuration objects directly in JS bundles.

```
# Common config variable names
config, configuration, settings, envConfig, appConfig
environmentConfig, clientConfig, runtimeConfig, globalConfig
APP_CONFIG, CONFIG, ENV, ENVIRONMENT
process.env, import.meta.env, __ENV__, __CONFIG__
window.__CONFIG__, window.__ENV__
```

#### Config Extraction Regex

```
# Config block extraction
Pattern:  (?:config|configuration|settings|envConfig|appConfig|globalConfig)\s*[:=]\s*\{(?:[^{}]|\{[^{}]*\})*\}
Example:  var config = { apiUrl: "https://internal-api.target.com", environment: "staging" }

# Process env access pattern (Node.js)
Pattern:  process\.env\.([A-Z_]+)
Example:  process.env.STRIPE_SECRET_KEY   <-- CRITICAL if bundled

# Import.meta.env (Vite / modern bundlers)
Pattern:  import\.meta\.env\.([A-Z_]+)

# Window config attachment
Pattern:  window\[["'`]__?(?:CONFIG|ENV|SETTINGS)["'`]\]\s*=\s*\{
```

### 7.2 Environment-Specific Values

```
# Environment detection
Pattern:  (?:NODE_ENV|ENVIRONMENT|APP_ENV|DEPLOY_ENV)\s*[:=]\s*["'`]([a-z]+)["'`]
Example:  NODE_ENV: "production", ENVIRONMENT: "staging"

# Environment-specific base URLs
Pattern:  (?:apiUrl|api_base_url|baseUrl|BASE_URL|API_URL)\s*[:=]\s*["'`](https?://[^"'`]+)["'`]
Example:  apiUrl: "https://internal-api.staging.target.com"
```

### 7.3 Cloud Infrastructure Config

```
# AWS region
Pattern:  (?:region|awsRegion|AWS_REGION)\s*[:=]\s*["'`]([a-z]{2}-[a-z]+-[0-9])["'`]
Example:  "region": "us-east-1"

# DynamoDB table names
Pattern:  (?:tableName|table|TABLE|TableName)\s*[:=]\s*["'`]([a-zA-Z0-9_-]+)["'`]
Example:  "tableName": "prod-users-table"

# S3 bucket names
Pattern:  (?:bucket|Bucket|bucketName|s3Bucket)\s*[:=]\s*["'`]([a-zA-Z0-9.-]+)["'`]
Example:  "bucket": "my-company-prod-assets"

# Lambda function names / ARNs
Pattern:  (?:functionName|FunctionName|lambda|Lambda)\s*[:=]\s*["'`]?(arn:aws:lambda:[^"'`\s]+|[a-zA-Z0-9_-]+)["'`]?
Example:  "FunctionName": "arn:aws:lambda:us-east-1:123456789012:function:my-function"

# Queue URLs / ARNs
Pattern:  (?:queueUrl|QueueUrl|queue|QUEUE)\s*[:=]\s*["'`]([^"'`]+sqs[^"'`]+)["'`]
Example:  "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"
```

### 7.4 Endpoint URLs with Keys Embedded

Sometimes API keys are embedded directly in endpoint URLs.

```
# API key as query parameter
Pattern:  (?:\?|&)(?:api[_-]?key|key|apikey|token|secret)\s*=\s*[^&\s"'`]{8,}
Example:  https://api.example.com/v1/data?api_key=AIzaSyCkL9vM6qNJ8q5h4

# API key in path segment
Pattern:  /(?:api|v1|v2|v3)/(?:key|token|secret)/([A-Za-z0-9_-]{16,})
```

### 7.5 CORS / Security Configuration

```
# CORS origin whitelist
Pattern:  (?:origin|origins|Origin|allowedOrigins|allowed_origins)\s*[:=]\s*\[[^\]]+\]
Example:  allowedOrigins: ["https://app.target.com", "http://localhost:3000"]

# Auth redirect URLs
Pattern:  (?:redirectUri|redirect_uri|redirectUrl|callbackUrl|callback_url)\s*[:=]\s*["'`]([^"'`]+)["'`]

# OAuth scopes
Pattern:  (?:scope|scopes)\s*[:=]\s*["'`]([a-zA-Z0-9:\/\s._-]+)["'`]
```

### 7.6 Third-Party Integration Config

```
# Sentry configuration
Pattern:  (?:Sentry|sentry)\.init\s*\(\s*\{[^}]+\}
Example:  Sentry.init({ dsn: "https://abc@o123.ingest.sentry.io/1234567" })

# Datadog RUM configuration
Pattern:  (?:datadogRum|DD_RUM|DatadogRum)\.init\s*\(\s*\{[^}]+\}
Example:  datadogRum.init({ applicationId: "abc123", clientToken: "pub123..." })

# Google Analytics / Tag Manager
Pattern:  (?:ga|gtag|UA-[0-9]+-[0-9]+|G-[A-Z0-9]+)
Example:  "UA-12345678-1" or "G-ABCDEF1234"

# Facebook Pixel
Pattern:  fbq\s*\(\s*["'`]init["'`]\s*,\s*["'`]([0-9]+)["'`]
Example:  fbq('init', '123456789012345')
```

### 7.7 Feature Configuration Blocks

```
# A/B testing config
Pattern:  (?:abTest|ab_test|experiment|Experiments)\s*[:=]\s*\{[^}]+:[^}]+\}
Example:  experiments: { "signup-flow-v2": { enabled: true, percentage: 50 } }

# Maintenance mode flags
Pattern:  (?:maintenance|maintenanceMode)\s*[:=]\s*(true|false)

# Rate limiting config
Pattern:  (?:rateLimit|rate_limit|throttle|throttling)\s*[:=]\s*\{[^}]+\}

# Pagination defaults
Pattern:  (?:pageSize|page_size|limit|perPage|per_page)\s*[:=]\s*[0-9]+
```

```powershell
# Extract configuration objects
Select-String -Path "*.js" -Pattern "(?:config|configuration|settings|envConfig|appConfig|runtimeConfig)\s*[:=]\s*\{(?:[^{}]|\{[^{}]*\})*\}" -AllMatches |
    ForEach-Object { $_.Matches.Value } |
    Out-File -FilePath "config-objects.txt"

# Extract all environment variable references
Select-String -Path "*.js" -Pattern "process\.env\.([A-Z_]{4,})" -AllMatches |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique |
    Out-File -FilePath "env-vars.txt"
```

---

## 8. Hardcoded Credentials

### 8.1 Username / Password Pairs

```
# Direct username and password assignment
Pattern:  (?:user|username|userName)\s*[:=]\s*["'`]([^"'`]+)["'`].*?(?:pass|password|pwd)\s*[:=]\s*["'`]([^"'`]+)["'`]
Example:  "username": "admin", "password": "P@ssw0rd123!"

# Configuration object with auth
Pattern:  auth\s*[:=]\s*\{[^}]*user(?:name)?[^}]*pass[^}]*\}
Example:  auth: { username: "api_bot", password: "supersecret" }
```

### 8.2 API Test / Demo Credentials

```
# Demo account credentials
Pattern:  (?:demo|test|sample|example|dummy|mock|fake)\s*(?:user|account|login|credential).*?(?:pass|secret|key|token)
Example:  "testUser": "demo@example.com", "testPassword": "demo123"

# Hardcoded tokens in test fixtures
Pattern:  ["'`](?:test|stub|mock|fake)_?(?:token|key|secret)[^=]*["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]
```

### 8.3 Encryption Keys

```
# AES Keys (128/256-bit in hex or base64)
Pattern:  (?:aes|AES|encryptionKey|encryption_key|cipherKey|cipher_key)\s*[:=]\s*["'`]([A-Za-z0-9+/=]{16,44})["'`]
Example:  "encryptionKey": "cGFzc3dvcmQxMjM0NTY3ODkwMTIzNDU2Nzg5MA=="

# IV / Initialization Vector
Pattern:  (?:iv|initializationVector|initVector)\s*[:=]\s*["'`]([A-Za-z0-9+/=]{8,24})["'`]

# HMAC Secret
Pattern:  (?:hmac|HMAC|hmacSecret|hmac_secret|signingSecret|signing_secret)\s*[:=]\s*["'`]([^"'`]+)["'`]

# JWT Signing Key / Secret
Pattern:  (?:jwt|JWT|tokenSecret|token_secret|jwtSecret|jwt_secret)\s*[:=]\s*["'`]([^"'`]+)["'`]
```

### 8.4 Tokens in Headers / Authorization

```
# Authorization header with Bearer token
Pattern:  ["'`]Authorization["'`]\s*[:=]\s*["'`]Bearer\s+([A-Za-z0-9._-]+)["'`]
Example:  "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHq4w2N0e1g"

# Authorization header with Basic auth
Pattern:  ["'`]Authorization["'`]\s*[:=]\s*["'`]Basic\s+([A-Za-z0-9+/=]+)["'`]

# X-API-Key header
Pattern:  ["'`]X-API-Key["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]

# Cookie values with tokens
Pattern:  ["'`](?:session|token|auth|sid|jwt|connect\.sid)\s*=\s*([^"'`;]+)["'`]
```

---

## 9. Third-Party Integration Keys

### 9.1 Full Third-Party Integration Config Objects

Complete integration configuration blocks are high-value because they contain multiple keys.

```
# Slack client initialization
Pattern:  (?:Slack|slack)\.(?:WebClient|IncomingWebhook|Webhook)\s*\(\s*["'`][^"'`]+["'`]

# Nodemailer / email config
Pattern:  (?:mailer|Mailer|nodemailer|emailClient|sendEmail)\s*[=:].*?auth\s*[:=]\s*\{[^}]+\}

# Algolia search config
Pattern:  (?:algolia|Algolia)\s*\(\s*["'`][^"'`]+["'`],\s*["'`][^"'`]+["'`]

# Cloudinary config
Pattern:  (?:cloudinary|Cloudinary)(?:\.config)?\s*\(?\s*\{[^}]+api[^}]+secret[^}]*\}

# AWS SDK config
Pattern:  (?:awsConfig|AWSConfig|s3Config|S3_CONFIG)\s*[:=]\s*\{[^}]+\}

# Firebase config
Pattern:  (?:firebase|Firebase)\.(?:initializeApp|config)\s*\(\s*\{[^}]+\}
```

### 9.2 Integration Configuration Extraction Examples

```
# Slack Webhook Configuration
Example:  slack: { webhookUrl: "https://hooks.slack.com/services/T00/B00/xxxx" }

# Mailgun Configuration
Example:  "MAILGUN_API_KEY": "key-abcdefghijklmnopqrstuvwxyz123456"

# Algolia Configuration
Example:  algolia: { appId: "ABCDEFGHIJ", apiKey: "abcdefghijklmnopqrstuvwxyz123" }

# Cloudinary Configuration
Example:  cloudinary: { cloudName: "mycompany", apiKey: "123456789012345", apiSecret: "abcdefghijklmnopqrstuvwxyz" }

# Amazon SES Configuration
Example:  ses: { accessKeyId: "AKIA...", secretAccessKey: "...", region: "us-east-1" }
```

```powershell
# Extract firebase configs
Select-String -Path "*.js" -Pattern "(?:firebase|Firebase)\.(?:initializeApp|config)\s*\(\s*\{" -AllMatches |
    ForEach-Object {
        $lineNumber = $_.LineNumber
        $file = $_.Path
        Get-Content $file | Select-Object -Index ($lineNumber-1), $lineNumber, ($lineNumber+1), ($lineNumber+2), ($lineNumber+3) -ErrorAction SilentlyContinue
    } | Out-File -FilePath "firebase-configs.txt"
```

### 9.3 Known Vendor Key Patterns Quick Reference

```
Vendor               Prefix/Length                  Example
-------              -----------                    -------
AWS Access Key       AKIA/ASIA + 16 chars           AKIAIOSFODNN7EXAMPLE
AWS Secret Key       40 chars base64                wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GCP API Key          AIza + 35 chars                AIzaSyCkL9vM6qNJ8q5h4q0q4q0q4q0q4q0q4q0q4q0
Stripe Live Secret   sk_live_ + 24+ chars           sk_live_USE_SHORT_EXAMPLE
Stripe Test Secret   sk_test_ + 24+ chars           sk_test_USE_SHORT_EXAMPLE
GitHub PAT           ghp_ + 36 chars                ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
GitHub Fine-Grained  github_pat_ + 82 chars         github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ...
Slack Bot Token      xoxb- + tokens                 xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX
Slack Webhook        hooks.slack.com/services/...   [omitted — see pattern above]
SendGrid             SG.xxxxx.xxxxx                 SG.xxxxx.xxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Twilio Account SID   AC + 32 chars                  ACxxxx_EXAMPLE_xxxxxxxxxxxxxx
Twilio Auth Token    32 chars hex                   [example omitted]
Firebase API Key     AIza + 35 chars                AIza[EXAMPLE_KEY_OMITTED]
Mapbox Public        pk.xxxxx.xxxxx                 pk.eyJ1Ijo[example]
Mapbox Secret        sk.xxxxx.xxxxx                 [omitted]
OpenAI API Key       sk- + 32+ chars                [omitted]
Anthropic API Key    sk-ant- + 32+ chars            [omitted]
Hugging Face Token   hf_ + 34+ chars                [omitted]
Replicate Token      r8_ + 37+ chars                [omitted]
Algolia App ID       10 chars upper                 ABCDEFGHIJ
Algolia API Key      26 chars                       abcdefghijklmnopqrstuvwxyz123
```

---

## 10. Bundle Diffing Over Time

### 10.1 Why Diff Bundles

JavaScript bundles change frequently. Comparing versions over time can reveal:

- New API endpoints added (before they are documented or secured)
- Feature flags enabled/disabled
- New third-party integrations (with keys)
- Config changes (new environments, new service URLs)
- Removed debug code (that was previously exposed)
- New admin/internal paths added

### 10.2 Bundle Snapshot Workflow

```powershell
# PowerShell bundle snapshot workflow
$jsUrls = @(
    "https://target.com/js/main.js",
    "https://target.com/js/vendor.js",
    "https://target.com/js/app.js"
)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$basedir = "js-snapshots"
New-Item -ItemType Directory -Path "$basedir/$timestamp" -Force | Out-Null

foreach ($url in $jsUrls) {
    $filename = [System.IO.Path]::GetFileName($url)
    $outputPath = "$basedir/$timestamp/$filename"
    try {
        Invoke-WebRequest -Uri $url -OutFile $outputPath -ErrorAction Stop
        Write-Host "Downloaded: $filename" -ForegroundColor Green
    } catch {
        Write-Host "Failed: $url" -ForegroundColor Red
    }
}
# Also download .map files
foreach ($url in $jsUrls) {
    $mapUrl = "$url.map"
    $filename = [System.IO.Path]::GetFileName("$url.map")
    try {
        Invoke-WebRequest -Uri $mapUrl -OutFile "$basedir/$timestamp/$filename" -ErrorAction Stop
    } catch { }
}
```

### 10.3 Diff Commands

```powershell
# PowerShell diff against previous snapshot
$previousSnapshots = Get-ChildItem "js-snapshots" | Sort-Object Name -Descending
$previous = $previousSnapshots[1].FullName
$current = $previousSnapshots[0].FullName
$jsFiles = Get-ChildItem "$current/*.js" | Select-Object -ExpandProperty Name

foreach ($file in $jsFiles) {
    $oldPath = Join-Path $previous $file
    $newPath = Join-Path $current $file
    if ((Test-Path $oldPath) -and (Test-Path $newPath)) {
        $diff = Compare-Object (Get-Content $oldPath) (Get-Content $newPath)
        $addedLines = $diff | Where-Object { $_.SideIndicator -eq "=>" } | Select-Object -ExpandProperty InputObject
        if ($addedLines) {
            Write-Host "=== Changes in $file ===" -ForegroundColor Cyan
            $addedLines | Select-String -Pattern 'https?://' | ForEach-Object {
                Write-Host "[NEW URL] $_" -ForegroundColor Yellow
            }
            $addedLines | Select-String -Pattern '(?:AKIA|sk_live|ghp_|AIza|SG\.|xoxb-)' | ForEach-Object {
                Write-Host "[NEW SECRET] $_" -ForegroundColor Red
            }
            $addedLines | Select-String -Pattern '/api/|/v[0-9]+/|/admin/|/internal/' | ForEach-Object {
                Write-Host "[NEW API] $_" -ForegroundColor Green
            }
        }
    }
}
```

### 10.4 Change Significance Classification

```
CRITICAL (Report Immediately):
  - New secret keys appearing
  - New hardcoded credentials
  - New internal IP/hostname exposure
  - New admin/internal routes exposed
  - Stripe/GitHub/AWS/Cloud key additions

HIGH (Report within 24h):
  - New API endpoints (especially unauthenticated patterns)
  - New feature flags being enabled
  - New third-party integrations
  - New config values for production environments
  - New WebSocket connections

MEDIUM (Report within 1 week):
  - New client-side routes
  - New A/B experiments visible
  - New error tracking/debug config
  - New analytics integrations

LOW (Note but low priority):
  - UI text changes
  - Component renames
  - CSS class changes
  - Version bumps with no new exposed data
```

---

## 11. Windows / PowerShell Workflow

### 11.1 Complete Windows-Based JS Analysis Pipeline

The following script is a complete end-to-end JS analysis pipeline for Windows environments.

```powershell
# Complete JS Analysis Pipeline for Windows
param(
    [string]$TargetUrl = "",
    [string]$OutputDir = "js-analysis-output",
    [string]$JsFileList = "target-js-urls.txt",
    [switch]$FetchMaps = $true
)

$info = "Cyan"; $success = "Green"; $warning = "Yellow"
$critical = "Red"; $header = "Magenta"

function Write-Status { param([string]$Message, [string]$Color=$info)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

New-Item -ItemType Directory -Path $OutputDir, "$OutputDir/js", "$OutputDir/maps", "$OutputDir/results" -Force | Out-Null
Write-Status "=== Starting JS Analysis Pipeline ===" -Color $header

# Step 1: Discover or load JS URLs
$jsUrls = @()
if (Test-Path $JsFileList) {
    $jsUrls = Get-Content $JsFileList | Where-Object { $_ -and $_ -notlike '#*' }
    Write-Status "Loaded $($jsUrls.Count) URLs from $JsFileList" -Color $success
} elseif ($TargetUrl) {
    $commonPaths = @("/js/main.js", "/js/app.js", "/js/bundle.js", "/js/vendor.js",
                     "/js/main.min.js", "/js/app.min.js", "/js/bundle.min.js",
                     "/assets/main.js", "/assets/app.js", "/assets/bundle.js",
                     "/static/js/main.js", "/dist/js/app.js", "/build/js/main.js")
    foreach ($path in $commonPaths) {
        try {
            $req = [System.Net.WebRequest]::Create("$TargetUrl$path")
            $req.Method = "HEAD"; $req.Timeout = 5000
            $resp = $req.GetResponse()
            if ($resp.StatusCode -eq 200) { $jsUrls += "$TargetUrl$path" }
            $resp.Close()
        } catch { }
    }
}
if ($jsUrls.Count -eq 0) { Write-Status "No JS URLs found." -Color $critical; return }

# Step 2: Download JS files
$downloadedFiles = @()
foreach ($url in $jsUrls) {
    $url = $url.Trim()
    $filename = [System.IO.Path]::GetFileName($url)
    if ([string]::IsNullOrWhiteSpace($filename)) { continue }
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        $wc.DownloadFile($url, "$OutputDir/js/$filename"); $wc.Dispose()
        Write-Status "Saved: $filename" -Color $success
        $downloadedFiles += "$OutputDir/js/$filename"
    } catch { Write-Status "FAILED: $url" -Color $critical }
}

# Step 3: Check source maps
if ($FetchMaps) {
    foreach ($filePath in $downloadedFiles) {
        $content = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
        if ($content -match 'sourceMappingURL=([^\s]+)') {
            $mapUrl = $Matches[1]
            if ($mapUrl -notlike 'http*') {
                $jsBase = (Get-Content "$OutputDir/js-urls.txt" -ErrorAction SilentlyContinue) |
                    Where-Object { $_ -like "*$([System.IO.Path]::GetFileName($filePath))*" } | Select-Object -First 1
                if ($jsBase) { $mapUrl = "$(($jsBase -split '/')[0..($jsBase -split '/').Count-2] -join '/')/$mapUrl" }
            }
            try { Invoke-WebRequest -Uri $mapUrl -OutFile "$OutputDir/maps/$([System.IO.Path]::GetFileName($mapUrl))" -ErrorAction Stop } catch { }
        }
    }
}

# Step 4: Run regex extraction
$patterns = @{
    "API Paths"            = "['`](/api/[^'`\s]+)['`]"
    "Admin Paths"          = "['`](/[a-zA-Z0-9_/.-]*(?:admin|internal|private|dashboard|console)[a-zA-Z0-9_/.-]*)['`]"
    "AWS Keys"             = "(?:AKIA|ASIA)[A-Z0-9]{16}"
    "Stripe Keys"          = "(?:sk_live|sk_test|pk_live|pk_test|rk_live|whsec)_[A-Za-z0-9]{8,}"
    "GitHub Tokens"        = "ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"
    "Slack Tokens"         = "xox[bpa]-[A-Za-z0-9_-]{20,}"
    "Google/Firebase Keys" = "AIza[0-9A-Za-z_-]{35}"
    "SendGrid Keys"        = "SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    "OpenAI Keys"          = "sk-[A-Za-z0-9]{30,}"
    "Anthropic Keys"       = "sk-ant-[A-Za-z0-9]{30,}"
    "Hugging Face"         = "hf_[A-Za-z0-9]{30,}"
    "JWT Tokens"           = "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    "Private IPs"          = "(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    "MongoDB URIs"         = "mongodb(?:\+srv)?://[a-zA-Z0-9.:/?&%=@_-]+"
    "Sentry DSN"           = "https://[a-f0-9]{32,}@[a-zA-Z0-9.-]+\.[a-z]+/[0-9]+"
    "WebSockets"           = "wss?://[a-zA-Z0-9./?=%-_]+"
    "GraphQL Endpoints"    = "['`](/?(?:graphql|gql|graphiql|voyager|playground)[^'`\s]*)['`]"
    "Hardcoded Passwords"  = "['`](?:password|passwd|pwd|secret|passphrase)['`]\s*[:=]\s*['`]([^'`]{4,})['`]"
    "Private Keys"         = "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    "GitLab Tokens"        = "glpat-[A-Za-z0-9_-]{20,}"
}

$allResults = @()
foreach ($p in $patterns.Keys) {
    $regex = $patterns[$p]
    foreach ($file in $downloadedFiles) {
        $matches = Select-String -Path $file -Pattern $regex -AllMatches -ErrorAction SilentlyContinue
        foreach ($match in $matches) {
            foreach ($m in $match.Matches) {
                $value = if ($m.Groups.Count -gt 1 -and $m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Value }
                $severity = if ($p -match 'Key|Token|Secret|Password|Private') { "CRITICAL" } elseif ($p -match 'Admin|Internal|IP|URI|Webhook|GraphQL') { "HIGH" } else { "MEDIUM" }
                $allResults += [PSCustomObject]@{ Pattern=$p; Value=$value; File=[System.IO.Path]::GetFileName($file); Severity=$severity }
            }
        }
    }
}
$allResults | Export-Csv -Path "$OutputDir/results/all-findings.csv" -NoTypeInformation
$allResults | Sort-Object Severity | Format-Table Pattern, Severity, Value -AutoSize -Wrap

$allResults | Where-Object Severity -eq "CRITICAL" | Select-Object -ExpandProperty Value -Unique | Sort-Object | Out-File -FilePath "$OutputDir/results/secrets.txt"
Write-Status "CRITICAL: $(( $allResults | Where-Object Severity -eq 'CRITICAL' | Measure-Object ).Count)" -Color $critical
Write-Status "HIGH: $(( $allResults | Where-Object Severity -eq 'HIGH' | Measure-Object ).Count)" -Color $warning
Write-Status "=== ANALYSIS COMPLETE ===" -Color $header
```

### 11.2 Individual Pattern Test Commands

Quick single-line commands for each pattern type:

```powershell
# Find all absolute URLs
Select-String -Path "*.js" -Pattern 'https?://[a-zA-Z0-9./?=_%-]+' | % Matches | % Value | Sort -U
# Find all API paths
Select-String -Path "*.js" -Pattern "['`](/api/[^'`\s]+)['`]" | % { $_.Matches.Groups[1].Value } | Sort -U
# Find all AWS Keys
Select-String -Path "*.js" -Pattern '(AKIA|ASIA)[A-Z0-9]{16}' | % Matches | % Value | Sort -U
# Find all private IPs
Select-String -Path "*.js" -Pattern '(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})' | % Matches | % Value | Sort -U
# Find all JWT tokens
Select-String -Path "*.js" -Pattern 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | % Matches | % Value | Sort -U
# Find all hardcoded passwords
Select-String -Path "*.js" -Pattern "['`](?:password|passwd|pwd|secret|passphrase)['`]\s*[:=]\s*['`]([^'`]{4,})['`]" | % { $_.Matches.Groups[1].Value } | Sort -U
# Find all env variable references
Select-String -Path "*.js" -Pattern 'process\.env\.([A-Z_]+)' | % { $_.Matches.Groups[1].Value } | Sort -U
# Find all source mapping URLs
Select-String -Path "*.js" -Pattern 'sourceMappingURL=([^\s]+)' | % { $_.Matches.Groups[1].Value } | Sort -U
# Find all fetch() calls
Select-String -Path "*.js" -Pattern "fetch\s*\(\s*['`]([^'`]+)['`]" | % { $_.Matches.Groups[1].Value } | Sort -U
# Find all WebSocket connections
Select-String -Path "*.js" -Pattern 'wss?://[a-zA-Z0-9./?=_%-]+' | % Matches | % Value | Sort -U
# Find feature flags
Select-String -Path "*.js" -Pattern "['`]([a-z]+(?:Flag|Toggle|Enabled|Disabled))['`]\s*:\s*(?:true|false)" | % { $_.Matches.Groups[1].Value } | Sort -U
```

### 11.3 Recursive Directory Search

```powershell
# Search all JS files recursively for secret patterns
Get-ChildItem -Path ".\" -Recurse -Filter "*.js" |
    Select-String -Pattern '(?:sk_live|ghp_|AKIA|AIza|SG\.)' -AllMatches |
    ForEach-Object { [PSCustomObject]@{ File=$_.Path; Line=$_.LineNumber; Match=$_.Matches.Value } } |
    Export-Csv -Path "secrets-found.csv" -NoTypeInformation

# Search all file types for secret patterns
Get-ChildItem -Path ".\" -Recurse -Include "*.js", "*.json", "*.ts", "*.env*", "*.config.*" |
    Select-String -Pattern '(?:AKIA|sk_live_|ghp_|AIza|SG\.|xoxb-)' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique > all-secrets.txt
```

### 11.4 Extract and Decode Base64 Credentials

```powershell
# Extract and decode base64 strings
$b64Strings = Select-String -Path "*.js" -Pattern '([A-Za-z0-9+/]{40,}={0,2})' -AllMatches |
    ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object -Unique

Add-Type -AssemblyName System.Text.Encoding
$decodedFindings = @()
foreach ($b64 in $b64Strings) {
    try {
        $bytes = [Convert]::FromBase64String($b64)
        $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($decoded -match '(?:password|secret|key|token|http|api|admin|aws|azure)') {
            $decodedFindings += [PSCustomObject]@{ Original=$b64; Decoded=$decoded }
        }
    } catch { }
}
$decodedFindings | Format-Table -AutoSize -Wrap
$decodedFindings | Export-Csv -Path "base64-decoded.csv" -NoTypeInformation
```

---

## 12. Automated Extraction Scripts

### 12.1 Full Automation Script

```powershell
# auto-extract.ps1
param(
    [string]$TargetUrl,
    [string]$LocalDir,
    [string]$OutputDir = "js-extraction-results",
    [string]$JsUrlFile,
    [switch]$CheckSourceMaps = $true,
    [switch]$DecodeBase64 = $true
)

New-Item -ItemType Directory -Path $OutputDir, "$OutputDir/reports" -Force | Out-Null
$jsFiles = @()

if ($LocalDir) {
    $jsFiles = Get-ChildItem -Path $LocalDir -Recurse -Filter "*.js" -ErrorAction SilentlyContinue
    Write-Host "Found $($jsFiles.Count) JS files in $LocalDir"
} elseif ($TargetUrl) {
    New-Item -ItemType Directory -Path "$OutputDir/js" -Force | Out-Null
    $jsUrlList = @()
    if ($JsUrlFile -and (Test-Path $JsUrlFile)) {
        $jsUrlList = Get-Content $JsUrlFile | Where-Object { $_ -and $_ -notlike '#*' }
    } else {
        foreach ($path in @("/js/main.js", "/js/app.js", "/js/bundle.js", "/js/vendor.js")) {
            try {
                $req = [System.Net.HttpWebRequest]::Create("$TargetUrl$path")
                $req.Method = "HEAD"; $req.Timeout = 3000
                $resp = $req.GetResponse()
                if ($resp.StatusCode -eq 200) { $jsUrlList += "$TargetUrl$path" }
                $resp.Close()
            } catch {}
        }
    }
    foreach ($url in $jsUrlList) {
        $url = $url.Trim(); if (-not $url) { continue }
        $filename = [System.IO.Path]::GetFileName($url)
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            $wc.DownloadFile($url, "$OutputDir/js/$filename"); $wc.Dispose()
        } catch { Write-Host "Failed: $url" -ForegroundColor Red }
    }
    $jsFiles = Get-ChildItem -Path "$OutputDir/js" -Filter "*.js" -ErrorAction SilentlyContinue
}

if ($jsFiles.Count -eq 0) { Write-Host "No JS files found!" -ForegroundColor Red; return }

# Define all patterns
$patterns = @(
    @{Name="AWS Access Key"; Regex='(?:AKIA|ASIA)[A-Z0-9]{16}'; Severity="CRITICAL"}
    @{Name="Stripe Live Secret"; Regex='sk_live_[A-Za-z0-9]{20,}'; Severity="CRITICAL"}
    @{Name="Stripe Test Secret"; Regex='sk_test_[A-Za-z0-9]{20,}'; Severity="HIGH"}
    @{Name="GitHub PAT"; Regex='ghp_[A-Za-z0-9]{36}'; Severity="CRITICAL"}
    @{Name="Slack Bot Token"; Regex='xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}'; Severity="CRITICAL"}
    @{Name="Google/Firebase Key"; Regex='AIza[0-9A-Za-z_-]{35}'; Severity="CRITICAL"}
    @{Name="SendGrid Key"; Regex='SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'; Severity="CRITICAL"}
    @{Name="OpenAI Key"; Regex='sk-[A-Za-z0-9]{30,}'; Severity="CRITICAL"}
    @{Name="Anthropic Key"; Regex='sk-ant-[A-Za-z0-9]{20,}'; Severity="CRITICAL"}
    @{Name="JWT Token"; Regex='eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'; Severity="HIGH"}
    @{Name="Private Key"; Regex='-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'; Severity="CRITICAL"}
    @{Name="MongoDB URI"; Regex='mongodb(?:\+srv)?://[a-zA-Z0-9._~:/?#@!$&()*+,;=-]+'; Severity="HIGH"}
    @{Name="Private IP"; Regex='(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})'; Severity="HIGH"}
    @{Name="Discord Bot Token"; Regex='[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}'; Severity="CRITICAL"}
    @{Name="GitLab Token"; Regex='glpat-[A-Za-z0-9_-]{20,}'; Severity="CRITICAL"}
    @{Name="Hardcoded Password"; Regex='["\x27\x60](?:password|passwd|pwd|secret|passphrase)["\x27\x60]\s*[:=]\s*["\x27\x60]([^"\x27\x60]{4,})["\x27\x60]'; Severity="CRITICAL"}
)

$allFindings = @()
foreach ($p in $patterns) {
    foreach ($file in $jsFiles) {
        $matches = Select-String -Path $file.FullName -Pattern $p.Regex -AllMatches -ErrorAction SilentlyContinue
        foreach ($match in $matches) {
            foreach ($m in $match.Matches) {
                $allFindings += [PSCustomObject]@{
                    Severity=$p.Severity; Pattern=$p.Name
                    Value = if ($m.Groups.Count -gt 1 -and $m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Value }
                    File=$file.Name; Line=$match.LineNumber
                }
            }
        }
    }
}
$allFindings | Export-Csv -Path "$OutputDir/findings.csv" -NoTypeInformation
$allFindings | Sort-Object Severity | Format-Table Severity, Pattern, Value, File -AutoSize -Wrap
Write-Host "CRITICAL: $(($allFindings | Where-Object Severity -eq 'CRITICAL' | Measure-Object).Count)" -ForegroundColor Red
Write-Host "HIGH: $(($allFindings | Where-Object Severity -eq 'HIGH' | Measure-Object).Count)" -ForegroundColor Yellow
Write-Host "Report saved to $OutputDir/findings.csv"
```

### 12.2 Quick One-Liners

```powershell
# Download a JS file
Invoke-WebRequest -Uri "https://target.com/js/main.js" -OutFile "main.js"

# Extract all secrets at once from directory
Get-ChildItem -Path "." -Filter "*.js" -Recurse |
    Select-String -Pattern "(?:AKIA|sk_live_|ghp_|AIza|SG\.|xoxb-|eyJ[A-Za-z0-9_-]+\.)" -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique > secrets.txt

# Find internal IPs quickly
Get-ChildItem -Path "." -Filter "*.js" |
    Select-String -Pattern "(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b" -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique > ips.txt

# Count lines in all JS files
Get-ChildItem -Path "." -Filter "*.js" | Select-Object Name, @{N="Lines";E={(Get-Content $_.FullName | Measure-Object).Length}}
```

---

## 13. Output Prioritization

### 13.1 Severity Classification Matrix

| Severity    | Finding Types | Response | Example |
|-------------|--------------|----------|---------|
| CRITICAL    | Cloud provider keys, database creds, private keys, JWT secrets | Immediate | AKIAIOSFODNN7EXAMPLE, sk_live_abc |
| CRITICAL    | Hardcoded passwords, encryption keys, HMAC secrets | Immediate | "password": "P@ssw0rd" |
| CRITICAL    | GitHub tokens, Slack tokens, Stripe live keys | Immediate | ghp_abcdef, xoxb-123, sk_live_ |
| CRITICAL    | OpenAI, Anthropic, Hugging Face, Replicate keys | Immediate | sk-proj-abc, sk-ant-abc |
| CRITICAL    | Private keys (RSA, SSH, PGP) | Immediate | -----BEGIN RSA PRIVATE KEY----- |
| CRITICAL    | Firestore admin SDK service account keys | Immediate | Full serviceAccountKey JSON |
| HIGH        | Internal IPs and hostnames | 24h | 10.0.1.45, db-01.internal |
| HIGH        | Database connection strings | 24h | mongodb+srv://user:pass@cluster |
| HIGH        | Admin/internal routes | 24h | /admin/users, /internal/api |
| HIGH        | Stripe test keys, Twilio tokens | 24h | sk_test_abc, AC123, SK123 |
| HIGH        | JWT tokens | 24h | eyJhbGciOiJIUzI1NiJ9... |
| HIGH        | GraphQL with introspection | 24h | /graphql with query { __schema } |
| HIGH        | Webhook URLs | 24h | hooks.slack.com/services/... |
| HIGH        | Newly-added secrets (bundle diff) | 24h | Any secret not in previous snapshot |
| MEDIUM      | API base URLs, versioned endpoints | 1 week | /api/v2/users, /v1/products |
| MEDIUM      | Feature flags (admin, beta, internal) | 1 week | isAdminPanelEnabled: true |
| MEDIUM      | Config objects, env variables | 1 week | process.env, config objects |
| MEDIUM      | Third-party publishable keys | 1 week | pk_live_, pk_test_, mapbox public |
| MEDIUM      | Sentry DSN, Datadog keys | 1 week | sentry.io DSN, datadog appId |
| MEDIUM      | WebSocket endpoints | 1 week | wss://ws.target.com/socket.io/ |
| LOW         | Generic URLs (non-sensitive) | As available | https://cdn.example.com/image.jpg |
| LOW         | Non-sensitive route definitions | As available | /about, /contact, /privacy |
| LOW         | Version numbers and metadata | As available | appVersion, buildNumber |

### 13.2 Reporting Format

#### Markdown Report Structure

```markdown
# JS Analysis Report - target.com
Date: 2026-04-08 14:30:00
Files Analyzed: 12
Source Maps Found: 3

## Critical Findings (5)

### 1. AWS Access Key Found
- **File:** main.a1b2c3.js
- **Line:** 1423
- **Value:** AKIAIOSFODNN7EXAMPLE
- **Context:** `AWS.config.update({ accessKeyId: "AKIAIOSFODNN7EXAMPLE" })`

### 2. Stripe Live Secret Key
- **File:** vendor.d4e5f6.js
- **Line:** 2891
- **Value:** sk_live_USE_SHORT_EXAMPLE
- **Context:** `stripe("sk_live_USE_SHORT_EXAMPLE")`

## High Findings (12)

## Medium Findings (28)
```

#### Text Report Structure

```
========================================
JS ANALYSIS REPORT
Target: target.com
Date: 2026-04-08 14:30:00
========================================

=== CRITICAL ===
[AKIAIOSFODNN7EXAMPLE] main.js:1423 - AWS Access Key
[sk_live_51H4...]      vendor.js:2891 - Stripe Live Secret
[ghp_abcdef...]        app.js:567   - GitHub PAT

=== HIGH ===
[10.0.1.45]            main.js:89   - Private IP
[mongodb://...]        config.js:45 - MongoDB connection string
[/admin/users]         routes.js:234 - Admin route

=== MEDIUM ===
[https://api.target.com/v2] config.js:12 - API base URL
[isAdminEnabled: true]      features.js:78 - Feature flag
```

### 13.3 Reporting Priority Queue

When multiple findings exist, process in this order:

1. **Active cloud keys** (AWS, GCP, Azure keys that appear to be in use)
2. **Database credentials with live-seeming connection strings**
3. **Payment platform secrets** (Stripe, PayPal, Square)
4. **GitHub / GitLab tokens with repo access patterns**
5. **Slack webhooks and bot tokens** (lead to internal channels)
6. **AI provider keys** (OpenAI, Anthropic -- costly to the victim)
7. **Hardcoded passwords** (user accounts, service accounts)
8. **Private keys** (SSH, TLS, PGP -- can lead to infrastructure access)
9. **Internal IPs and hostnames** (network mapping)
10. **Internal/admin routes** (undocumented endpoints)
11. **JWT tokens** (session hijacking potential)
12. **Feature flags indicating restricted functionality**
13. **All other findings** (config leaks, metadata, URLs)

### 13.4 Submission Checklist

Before submitting or reporting any JS-based finding:

- [ ] Verify the key/secret is active (tested against the service endpoint)
- [ ] Verify the finding is NOT in a test/demo file or dead code path
- [ ] Check if the key is restricted (IP-limited, read-only, etc.)
- [ ] Collect evidence: screenshot of the file with context lines
- [ ] Document the file URL, line number, and surrounding code
- [ ] Note whether a source map was available (indicates severity)
- [ ] Classify severity according to the matrix above
- [ ] For bundle diffs: confirm the secret was not in the previous version
- [ ] Check if the same secret appears in multiple files (wider exposure)
- [ ] Determine if the secret has been rotated (check diff history)
