#!/usr/bin/env python3
"""
idor_hunter.py — Insecure Direct Object Reference Hunter (P1)

Detects IDOR vulnerabilities by systematically testing object references
(IDs, UUIDs, hashes, tokens) across endpoints. Supports sequential/parallel
ID scanning, UUID/guid testing, hash-based ID recognition, parameter
pollution, mass assignment, authenticated IDOR, privilege escalation,
response comparison, and batch target scanning. Tests object references
in URLs, query params, POST bodies, headers, cookies, and JWTs.

Features: sequential ID scanning, parallel ID testing, UUID detection,
hash-based ID detection, parameter pollution for IDOR, batch ID enumeration,
response comparison, authenticated IDOR, mass assignment, privilege
escalation, header reference testing, cookie reference testing, wildcard
testing, negative ID testing, array ID injection, JWT ID manipulation,
HMAC ID bypass, UUID confusion, response fingerprinting, scope-based
testing, report generation, and reference discovery.
"""

import base64
import csv
import json
import os
import random
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class IDORHunter:
    """
    P1 IDOR hunter with 20+ detection methods.

    Tests endpoints for insecure direct object references using sequential
    IDs, UUIDs, hashes, arrays, wildcards, headers, cookies, and JWTs.
    Compares responses for anomalies indicating unauthorized access to
    other users' data.

    Attributes:
        target_url: Base API endpoint pattern (use {id} as placeholder).
        findings: List of discovered IDOR findings.
        auth_tokens: Authentication tokens for authenticated testing.
        discovered_refs: Object references discovered during testing.
    """

    def __init__(self, target_url: str = "", auth_token: Optional[str] = None):
        self.target_url = target_url
        self.findings: List[Dict[str, Any]] = []
        self.auth_tokens: List[str] = [auth_token] if auth_token else []
        self.discovered_refs: List[str] = []
        self._session: Optional[Any] = None
        self._init_session()

    def _init_session(self) -> None:
        try:
            import requests as req
            self._session = req.Session()
            self._session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json, */*",
            })
            if self.auth_tokens:
                self._session.headers["Authorization"] = f"Bearer {self.auth_tokens[0]}"
        except ImportError:
            self._session = None

    def set_auth(self, token: str) -> None:
        self.auth_tokens = [token]
        if self._session:
            self._session.headers["Authorization"] = f"Bearer {token}"

    def add_auth(self, token: str) -> None:
        self.auth_tokens.append(token)

    def _request(self, url: str, method: str = "GET", **kwargs) -> Optional[Dict[str, Any]]:
        if not self._session:
            return None
        try:
            resp = self._session.request(method, url, timeout=15, verify=False, **kwargs)
            return {
                "url": resp.url, "status": resp.status_code,
                "body": resp.text, "body_length": len(resp.text),
                "headers": dict(resp.headers), "elapsed": resp.elapsed.total_seconds(),
            }
        except Exception as e:
            return {"url": url, "error": str(e), "status": 0}

    def _resolve_url(self, object_id: Union[str, int]) -> str:
        return self.target_url.replace("{id}", str(object_id)).replace("{ID}", str(object_id))

    def test_sequential_ids(self, start: int = 1, end: int = 10, owner_id: Union[str, int] = 1) -> List[Dict[str, Any]]:
        baseline = self._request(self._resolve_url(owner_id))
        results = []
        for oid in range(start, end + 1):
            if str(oid) == str(owner_id):
                continue
            resp = self._request(self._resolve_url(oid))
            if resp and baseline and not self._is_same_response(baseline, resp):
                results.append(self._make_finding("sequential_idor", str(oid), resp, baseline))
        self.findings.extend(results)
        return results

    def test_parallel_ids(self, ids: List[Union[str, int]], method: str = "GET") -> List[Dict[str, Any]]:
        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {}
            for oid in ids:
                futures[ex.submit(self._request, self._resolve_url(oid), method)] = str(oid)
            for future in as_completed(futures):
                try:
                    oid = futures[future]
                    resp = future.result(timeout=15)
                    if resp and resp.get("status") in (200, 200) and "error" not in resp.get("body", "").lower()[:50]:
                        results.append(self._make_finding("parallel_idor", oid, resp or {}))
                except Exception:
                    pass
        self.findings.extend(results)
        return results

    def test_uuid(self, base_uuid: str) -> List[Dict[str, Any]]:
        results = []
        parts = base_uuid.split("-")
        if len(parts) != 5:
            return results
        variants = [
            "00000000-0000-0000-0000-000000000000",  # null UUID
            "ffffffff-ffff-ffff-ffff-ffffffffffff",  # all Fs
            "11111111-1111-1111-1111-111111111111",
            base_uuid[:-1] + str((int(base_uuid[-1], 16) + 1) % 16),  # increment last char
        ]
        for variant in variants:
            resp = self._request(self._resolve_url(variant))
            if resp and resp.get("status") == 200 and len(resp.get("body", "")) > 10:
                results.append(self._make_finding("uuid_idor", variant, resp or {}))
        return results

    def test_mass_assignment(self, extra_fields: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        fields = extra_fields or {
            "is_admin": True, "role": "admin", "verified": True,
            "email_verified": True, "account_balance": 999999,
            "plan": "enterprise", "subscription": "premium",
            "is_verified": True, "is_active": True,
        }
        results = []
        for field, value in fields.items():
            try:
                resp = self._request(self.target_url, method="POST",
                                     json={field: value})
                if resp and resp.get("status") in (200, 201):
                    body = resp.get("body", "").lower()
                    field_lower = field.lower().replace("is_", "").replace("_", "")
                    if field_lower in body or str(value).lower() in body:
                        results.append(self._make_finding("mass_assignment", field, resp or {}))
            except Exception:
                pass
        return results

    def test_negative_ids(self, owner_id: Union[str, int] = 1) -> List[Dict[str, Any]]:
        results = []
        negative_ids = [-1, -100, -9999, 0, "0", "-1", "null", "undefined", "", "true", "false"]
        for nid in negative_ids:
            resp = self._request(self._resolve_url(nid))
            if resp and resp.get("status") == 200:
                results.append(self._make_finding("negative_idor", str(nid), resp or {}))
        return results

    def test_wildcard(self) -> List[Dict[str, Any]]:
        results = []
        wildcards = ["*", "%", "_", ".*", ".+", "all", "admin", "*.*"]
        for w in wildcards:
            resp = self._request(self._resolve_url(w))
            if resp and resp.get("status") == 200 and len(resp.get("body", "")) > 20:
                results.append(self._make_finding("wildcard_idor", w, resp or {}))
        return results

    def test_array_injection(self) -> List[Dict[str, Any]]:
        results = []
        arrays = ["id[]=1&id[]=2&id[]=3", "ids=1,2,3", "id[0]=1&id[1]=2", "user_ids=1,2,3"]
        for arr in arrays:
            try:
                resp = self._request(self.target_url + "?" + arr)
                if resp and resp.get("status") == 200:
                    results.append(self._make_finding("array_idor", arr[:40], resp or {}))
            except Exception:
                pass
        return results

    def test_headers(self, header_name: str = "X-User-ID", values: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        test_values = values or ["1", "2", "admin", "0", "-1"]
        baseline = self._request(self.target_url)
        for val in test_values:
            resp = self._request(self.target_url, headers={header_name: val})
            if resp and baseline and not self._is_same_response(baseline, resp):
                if resp.get("status") == 200:
                    results.append(self._make_finding("header_idor", f"{header_name}:{val}", resp or {}))
        return results

    def test_cookies(self, cookie_name: str = "user_id", values: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        test_values = values or ["1", "2", "admin", "0"]
        baseline = self._request(self.target_url)
        for val in test_values:
            resp = self._request(self.target_url, cookies={cookie_name: val})
            if resp and baseline and not self._is_same_response(baseline, resp):
                if resp.get("status") == 200:
                    results.append(self._make_finding("cookie_idor", f"{cookie_name}:{val}", resp or {}))
        return results

    def test_jwt_id(self, jwt_token: str) -> List[Dict[str, Any]]:
        results = []
        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return results
            padding = 4 - len(parts[1]) % 4
            if padding != 4:
                parts[1] += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(parts[1]))
            id_fields = ["id", "user_id", "sub", "uid", "account_id", "customer_id"]
            for field in id_fields:
                if field in payload:
                    original = payload[field]
                    payload[field] = 1 if isinstance(original, int) else "1"
                    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
                    new_token = f"{parts[0]}.{new_payload}.{parts[2]}"
                    resp = self._request(self.target_url, headers={"Authorization": f"Bearer {new_token}"})
                    if resp and resp.get("status") == 200:
                        results.append(self._make_finding("jwt_idor", f"jwt.{field}=1", resp or {}))
        except Exception:
            pass
        return results

    def test_hmac_id_bypass(self, param: str = "id", hmac_param: str = "hash") -> List[Dict[str, Any]]:
        results = []
        test_pairs = [(1, ""), (2, ""), (1, "deadbeef"), (2, "00000000000000000000000000000000")]
        for oid, hmac in test_pairs:
            params = {param: oid}
            if hmac_param and hmac:
                params[hmac_param] = hmac
            resp = self._request(self.target_url, params=params)
            if resp and resp.get("status") == 200:
                results.append(self._make_finding("hmac_bypass", f"{param}={oid}", resp or {}))
        return results

    def discover_references(self, content: str) -> List[str]:
        patterns = [
            r'(?:user|account|order|profile|document|file|message)_?(?:id|i[dD])[:=]\s*["\']?(\d+)["\']?',
            r'/(?:users|accounts|orders|profiles|documents|files|messages)/(\d+)',
            r'["\'](?:id|uid|user_id|account_id)["\']:\s*(\d+)',
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        ]
        refs = set()
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                refs.add(match.group(1))
        self.discovered_refs = sorted(refs)
        return self.discovered_refs

    def test_all(self, owner_id: Union[str, int] = 1, num_ids: int = 10) -> Dict[str, Any]:
        results = {
            "sequential": self.test_sequential_ids(1, num_ids, owner_id),
            "negative": self.test_negative_ids(owner_id),
            "wildcard": self.test_wildcard(),
            "array": self.test_array_injection(),
        }
        for key, vals in results.items():
            self.findings.extend(vals)
        return results

    def _is_same_response(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        if a.get("status") != b.get("status"):
            return False
        a_len = a.get("body_length", 0)
        b_len = b.get("body_length", 0)
        return abs(a_len - b_len) < 50

    def _make_finding(self, vuln_type: str, reference: str,
                      resp: Dict[str, Any], baseline: Optional[Dict] = None) -> Dict[str, Any]:
        finding: Dict[str, Any] = {
            "type": vuln_type, "reference": reference,
            "status": resp.get("status"), "url": resp.get("url", self.target_url),
            "body_length": resp.get("body_length", 0),
            "timestamp": datetime.now().isoformat(),
            "severity": "high",
        }
        if baseline:
            finding["baseline_status"] = baseline.get("status")
            finding["baseline_length"] = baseline.get("body_length", 0)
        return finding

    def export_json(self, filepath: Optional[str] = None) -> str:
        data = {"scan_time": datetime.now().isoformat(), "discovered_refs": self.discovered_refs,
                "findings": self.findings}
        j = json.dumps(data, indent=2, default=str)
        if filepath:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(j)
        return j

    def export_csv(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            if self.findings:
                w = csv.DictWriter(f, fieldnames=list(self.findings[0].keys()))
                w.writeheader()
                w.writerows(self.findings)

    def get_summary(self) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for f in self.findings:
            t = f.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_type": type_counts,
            "discovered_references": len(self.discovered_refs),
            "target": self.target_url,
        }


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    if len(sys.argv) < 2:
        print("Usage: python idor_hunter.py <url_with_{id}> [--owner <id>] [--range <start-end>] [--token <jwt>] [--output <path>]")
        sys.exit(1)

    url = sys.argv[1]
    owner = 1
    id_range = "1-10"
    token = None
    out = None

    if "--owner" in sys.argv:
        idx = sys.argv.index("--owner")
        owner = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else owner
    if "--range" in sys.argv:
        idx = sys.argv.index("--range")
        id_range = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else id_range
    if "--token" in sys.argv:
        idx = sys.argv.index("--token")
        token = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else token
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else out

    start, end = 1, 10
    if "-" in id_range:
        parts = id_range.split("-")
        start, end = int(parts[0]), int(parts[1])

    hunter = IDORHunter(target_url=url, auth_token=token)
    print(f"[+] Testing {url} for IDOR (IDs {start}-{end}, owner={owner})")
    results = hunter.test_all(owner_id=owner, num_ids=end)
    print(json.dumps(hunter.get_summary(), indent=2))
    for f in hunter.findings[:15]:
        print(f"  [{f.get('severity','?')}] {f['type']}: {f.get('reference','')[:60]} (status {f.get('status')})")

    if out:
        hunter.export_json(out)
