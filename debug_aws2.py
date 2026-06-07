import sys
sys.path.insert(0, "tools/python")
from secret_scanner import SecretScanner

s = SecretScanner()
text = "AKIA" + "BCDEFGHIJKLMNOPQ"
print("Text: [" + text + "] len=" + str(len(text)))
results = s.scan_text(text)
print("Findings: " + str(len(results)))
for r in results:
    print("  " + r["name"] + ": " + r["match"])

# Also check the pattern directly
import re
for p in s.PATTERNS:
    if p["name"] == "AWS Access Key":
        print("Pattern: " + p["regex"].pattern)
        m = p["regex"].search(text)
        print("Direct match: " + str(m))
        if m:
            print("  Matched: [" + m.group(0) + "]")
            print("  allowlisted: " + str(s._is_allowlisted(m.group(0))))
