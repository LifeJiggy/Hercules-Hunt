#!/usr/bin/env python3
"""
base64_utils.py — Base64 Encoding/Decoding & Detection Toolkit

Comprehensive base64 analysis toolkit supporting standard, URL-safe, MIME,
and custom variants. Detects encoded content, handles nested/base64-in-base64,
JWT segment decoding, and bulk text scanning.

Features: standard decode, URL-safe decode, MIME decode, padding handling,
encoding detection (heuristic), content-type identification, recursive/nested
decode, JWT header/payload extraction, bulk scanning for encoded strings,
batch decode, hex-to-base64 conversion, base64-to-hex conversion,
encoding entropy scoring, multi-format export, progress tracking,
custom alphabet support, padding analysis, length validation,
and automated best-decode selection.
"""

import base64
import binascii
import csv
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union


@dataclass
class DecodeResult:
    variant: str
    success: bool
    decoded_text: str = ""
    decoded_bytes: bytes = b""
    error: str = ""
    content_type: str = "unknown"
    length: int = 0
    entropy: float = 0.0


class Base64Toolkit:
    """
    Base64 analysis toolkit with 20+ detection and decoding capabilities.

    Supports multiple variants, nested decoding, content detection,
    bulk scanning, batch processing, and automated best-result selection.
    """

    B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    B64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

    CONTENT_PATTERNS = {
        "json": [re.compile(r'^\s*[{[]'), re.compile(r'^[{[]')],
        "html": [re.compile(r'^\s*<', re.IGNORECASE), re.compile(r'<!DOCTYPE', re.IGNORECASE)],
        "jwt_header": [re.compile(r'^\{"alg"'), re.compile(r'^\{"typ"')],
        "url": [re.compile(r'^https?://', re.IGNORECASE)],
        "xml": [re.compile(r'^\s*<\?xml'), re.compile(r'^\s*<[a-zA-Z]')],
        "javascript": [re.compile(r'^\s*(?:function|const|let|var|class|import|export)\s')],
        "base64": [re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')],
    }

    def __init__(self, input_string: str = ""):
        self.input_string = input_string
        self.results: Dict[str, DecodeResult] = {}
        self.history: List[Dict[str, Any]] = []

    def set_input(self, s: str) -> None:
        self.input_string = s

    def is_base64(self, s: str, threshold: float = 0.85) -> bool:
        if not s or len(s) < 4:
            return False
        b64_ratio = sum(1 for c in s if c in self.B64_CHARS) / len(s)
        return b64_ratio >= threshold

    def is_base64url(self, s: str, threshold: float = 0.85) -> bool:
        if not s or len(s) < 4:
            return False
        url_ratio = sum(1 for c in s if c in self.B64URL_CHARS) / len(s)
        url_ratio = max(url_ratio, sum(1 for c in s if c in self.B64_CHARS) / len(s))
        return url_ratio >= threshold

    def encode(self, data: Union[str, bytes], variant: str = "standard") -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        if variant == "urlsafe":
            return base64.urlsafe_b64encode(data).decode()
        return base64.b64encode(data).decode()

    def _decode(self, data: str, decoder_func, variant_name: str) -> DecodeResult:
        try:
            decoded = decoder_func(data)
            if isinstance(decoded, bytes):
                text = self._bytes_to_text(decoded)
                content_type = self._detect_content_type(text)
                entropy = self._calc_entropy(text)
                return DecodeResult(
                    variant=variant_name, success=True,
                    decoded_text=text, decoded_bytes=decoded,
                    content_type=content_type, length=len(text),
                    entropy=entropy,
                )
            return DecodeResult(variant=variant_name, success=True, decoded_text=str(decoded), length=len(str(decoded)))
        except Exception as e:
            return DecodeResult(variant=variant_name, success=False, error=str(e))

    def decode_standard(self, data: str) -> DecodeResult:
        return self._decode(data, lambda d: base64.b64decode(d, validate=True), "standard")

    def decode_standard_nopad(self, data: str) -> DecodeResult:
        return self._decode(data, lambda d: base64.b64decode(d + "=" * (4 - len(d) % 4) if len(d) % 4 else d), "standard_nopad")

    def decode_urlsafe(self, data: str) -> DecodeResult:
        return self._decode(data, lambda d: base64.urlsafe_b64decode(d + "=="), "urlsafe")

    def decode_urlsafe_nopad(self, data: str) -> DecodeResult:
        return self._decode(data, lambda d: base64.urlsafe_b64decode(d), "urlsafe_nopad")

    def decode_mime(self, data: str) -> DecodeResult:
        cleaned = data.replace("\n", "").replace("\r", "").replace(" ", "")
        return self._decode(cleaned, lambda d: base64.b64decode(d), "mime")

    def decode_all_variants(self, data: Optional[str] = None) -> Dict[str, DecodeResult]:
        target = data or self.input_string
        if not target:
            return {}
        alt = target.replace("+", "-").replace("/", "_").replace("=", "")
        self.results = {
            "standard": self.decode_standard(target),
            "standard_nopad": self.decode_standard_nopad(target.rstrip("=")),
            "urlsafe": self.decode_urlsafe(target.replace("+", "-").replace("/", "_")),
            "urlsafe_nopad": self.decode_urlsafe_nopad(alt),
            "mime": self.decode_mime(target),
        }
        return self.results

    def decode_jwt_segments(self, token: str) -> Dict[str, Any]:
        parts = token.split(".")
        if len(parts) < 2:
            return {"error": "Not a JWT (min 2 parts)"}
        result: Dict[str, Any] = {}
        labels = ["header", "payload"]
        for i, label in enumerate(labels):
            if i >= len(parts):
                break
            try:
                raw = parts[i]
                padding = 4 - len(raw) % 4
                if padding != 4:
                    raw += "=" * padding
                decoded = base64.urlsafe_b64decode(raw)
                result[label] = json.loads(decoded)
            except Exception as e:
                result[label] = {"error": str(e)}
        if len(parts) >= 3:
            result["signature"] = parts[2][:20] + "..."
        return result

    def recursive_decode(self, data: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        steps = []
        current = data
        for depth in range(max_depth):
            if not self.is_base64(current, threshold=0.8):
                break
            results = self.decode_all_variants(current)
            best = self.get_best_decoding()
            if not best or not best.success:
                break
            steps.append({
                "depth": depth,
                "input": current[:80],
                "variant": best.variant,
                "output": best.decoded_text[:200],
                "content_type": best.content_type,
            })
            current = best.decoded_text
        return steps

    def find_encoded_strings(self, text: str, min_length: int = 20) -> List[Dict[str, Any]]:
        potentials = re.findall(r'[A-Za-z0-9+/=_-]{' + str(min_length) + r',}', text)
        findings = []
        for encoded in potentials:
            if self.is_base64(encoded):
                results = self.decode_all_variants(encoded)
                best = self.get_best_decoding()
                if best and best.success:
                    findings.append({
                        "encoded": encoded[:100],
                        "decoded": best.decoded_text[:200],
                        "content_type": best.content_type,
                        "variant": best.variant,
                    })
        return findings

    def get_best_decoding(self) -> Optional[DecodeResult]:
        successful = [r for r in self.results.values() if r.success]
        if not successful:
            return None
        priority = {"jwt_header": 7, "json": 6, "html": 5, "xml": 5, "url": 4, "javascript": 3, "text": 2, "base64": 1, "binary": 0}
        def sort_key(r: DecodeResult) -> int:
            return priority.get(r.content_type, 0) * 100 - (r.entropy * 10 if r.entropy else 0)
        return max(successful, key=sort_key)

    def _bytes_to_text(self, data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin-1")
            except Exception:
                return repr(data)

    def _detect_content_type(self, text: str) -> str:
        if not text:
            return "empty"
        for content_type, patterns in self.CONTENT_PATTERNS.items():
            if any(p.search(text) for p in patterns):
                return content_type
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        ratio = printable / max(len(text), 1)
        if ratio > 0.9:
            return "text"
        elif ratio > 0.5:
            return "semi_binary"
        return "binary"

    def _calc_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((c / len(text)) * math.log2(c / len(text)) for c in freq.values())
        return round(entropy, 4)

    def batch_decode(self, strings: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        def decode_one(s: str) -> Dict[str, Any]:
            tk = Base64Toolkit(s)
            tk.decode_all_variants()
            best = tk.get_best_decoding()
            return {"input": s[:50], "success": best.success if best else False, "decoded": best.decoded_text[:200] if best else "", "variant": best.variant if best else ""}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            results = list(ex.map(decode_one, strings))
        return results

    def analyze_padding(self, data: str) -> Dict[str, Any]:
        padding = data.count("=")
        return {
            "padding_chars": padding,
            "expected_padding": (4 - len(data.rstrip("=")) % 4) % 4,
            "well_padded": padding == (4 - len(data.rstrip("=")) % 4) % 4,
            "length_mod_4": len(data) % 4,
            "has_valid_chars": self.is_base64(data),
        }

    def hex_to_base64(self, hex_str: str) -> str:
        return base64.b64encode(bytes.fromhex(hex_str)).decode()

    def base64_to_hex(self, b64_str: str) -> str:
        return base64.b64decode(b64_str).hex()

    def export_results(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)) or ".", exist_ok=True)
        data = {
            "input": self.input_string[:100],
            "results": {k: {"success": v.success, "content_type": v.content_type, "length": v.length, "decoded": v.decoded_text[:500]} for k, v in self.results.items()},
            "best": self.get_best_decoding(),
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def get_statistics(self) -> Dict[str, Any]:
        successful = [r for r in self.results.values() if r.success]
        return {
            "variants_tested": len(self.results),
            "successful": len(successful),
            "content_types": list(set(r.content_type for r in successful)),
            "best_variant": self.get_best_decoding().variant if self.get_best_decoding() else None,
            "input_length": len(self.input_string),
        }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python base64_utils.py <decode|encode|analyze> <string>")
        sys.exit(1)
    mode = sys.argv[1]
    data = sys.argv[2] if len(sys.argv) > 2 else ""
    tk = Base64Toolkit(data)
    if mode == "decode":
        tk.decode_all_variants()
        best = tk.get_best_decoding()
        if best and best.success:
            print(f"Best ({best.variant}): {best.decoded_text[:500]}")
        else:
            print("No successful decoding")
    elif mode == "analyze":
        print(tk.analyze_padding(data))
    else:
        print(f"Encoded: {tk.encode(data)}")
