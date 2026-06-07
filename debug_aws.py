import sys, re
sys.path.insert(0, "tools/python")
from secret_scanner import SecretScanner

s = SecretScanner()

# Debug AWS access key
pat = re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')
test = "AKIA" + "BCDEFGHIJKLMNOP"
print("Test: [" + test + "] len=" + str(len(test)))
for i, c in enumerate(test):
    print(f"  pos {i}: '{c}' (0x{ord(c):04x})")
m = pat.search(test)
print("Match: " + str(m))

# Check with s.scan_text
results = s.scan_text(test)
print("Findings: " + str(len(results)))
for r in results:
    print("  " + r["name"] + ": " + r["match"])
    # Check allowlist
    print("  allowlisted: " + str(s._is_allowlisted(r["match"])))
