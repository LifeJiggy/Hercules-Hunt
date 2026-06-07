import sys, re
sys.path.insert(0, "tools/python")
from secret_scanner import SecretScanner

s = SecretScanner()

# Check AWS
pat_aws = re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')
test_aws = "AKIA" + "BCDEFGHIJKLMNOPQR"
print("AWS:", test_aws, "len=", len(test_aws))
m = pat_aws.search(test_aws)
print("  Match:", m)

# Check Google
pat_google = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
test_google = "AIza" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"
print("Google:", test_google, "len=", len(test_google))
m = pat_google.search(test_google)
print("  Match:", m)

# Check Twilio
pat_twilio = re.compile(r'SK[0-9a-fA-F]{32}')
test_twilio = "SK" + "aAbBcCdDeEfF00112233445566778899"
print("Twilio:", test_twilio, "len=", len(test_twilio))
m = pat_twilio.search(test_twilio)
print("  Match:", m)
# Count after SK
print("  After SK: '"+test_twilio[2:]+"' len=", len(test_twilio[2:]))
# Check each char
for i,c in enumerate(test_twilio[2:]):
    if c not in "0123456789abcdefABCDEF":
        print(f"  Char {i}: '{c}' not hex!")

# Check full scan
results = s.scan_text(test_aws)
print("AWS findings:", len(results))
for r in results:
    print("  ", r["name"], "-", r["match"][:30])
