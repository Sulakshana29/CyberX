import requests
from scanner.owasp_scanner import OWASPScanner

print("Testing Authenticated Scan Logic...")

scanner = OWASPScanner(
    auth_headers={"Authorization": "Bearer super_secret_token", "X-Custom": "123"},
    auth_cookies={"session": "abc_xyz_123"}
)

# 1. Test Headers
print("\n--- Sending request to httpbin.org/headers ---")
resp = scanner._get("https://httpbin.org/headers")
if resp:
    data = resp.json()
    print("Headers received by the server:")
    for k, v in data.get('headers', {}).items():
        if k in ('Authorization', 'X-Custom', 'Cookie'):
            print(f"  {k}: {v}")
else:
    print("Failed to reach httpbin.org")

# 2. Test Cookies directly
print("\n--- Sending request to httpbin.org/cookies ---")
resp = scanner._get("https://httpbin.org/cookies")
if resp:
    print("Cookies received by the server:")
    print(f"  {resp.json().get('cookies')}")
else:
    print("Failed to reach httpbin.org")
