#!/usr/bin/env python3
"""
OWASP ZAP scan script for small static sites with only a few pages.

Requirements:
- ZAP running (GUI or daemon)
- pip install python-owasp-zap-v2.4
- ZAP_API_KEY must be set (PowerShell:  $env:ZAP_API_KEY="yourkey")

"""

import os
import time
from zapv2 import ZAPv2

# ------------------------------------------
# CONFIG
# ------------------------------------------
API_KEY = os.getenv("ZAP_API_KEY")
if not API_KEY:
    raise SystemExit("ERROR: Set ZAP_API_KEY environment variable.")

ZAP_ADDR = "http://127.0.0.1:8090"          # ZAP default port
BASE_URL = "https://xiefs1.github.io/capstone1"

PAGES = [
    f"{BASE_URL}/vulnerable_test_cases.html",           # <-- replace with your real second page
]

REPORT_HTML = "zap-report.html"
REPORT_JSON = "zap-report.json"

# ------------------------------------------
# INIT CLIENT
# ------------------------------------------
zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_ADDR, "https": ZAP_ADDR})


def wait(label, func):
    """Standard polling function."""
    while True:
        status = int(func())
        print(f"{label} progress: {status}%")
        if status >= 100:
            break
        time.sleep(2)


# ------------------------------------------
# STEP 1 — LOAD ALL PAGES (force requests)
# ------------------------------------------
print("\n[*] Priming ZAP with all target pages...")
for page in PAGES:
    print(f"  [+] Hitting {page}")
    zap.urlopen(page)
    time.sleep(1)

time.sleep(2)

# ------------------------------------------
# STEP 2 — SPIDER
# ------------------------------------------
print("\n[*] Starting spider...")
scan_id = zap.spider.scan(PAGES[0])
wait("Spider", lambda: zap.spider.status(scan_id))

# ------------------------------------------
# STEP 3 — PASSIVE SCAN (static site = finishes immediately)
# ------------------------------------------
print("\n[*] Triggering passive scan with manual page hits...")
for page in PAGES:
    time.sleep(0.5)

print("[*] Waiting for passive scan to settle...")
time.sleep(3)
print("[*] Passive scan completed.\n")

# ------------------------------------------
# STEP 4 — ACTIVE SCAN
# ------------------------------------------
print("[*] Starting active scan...")
ascan_id = zap.ascan.scan(PAGES[0])
wait("Active scan", lambda: zap.ascan.status(ascan_id))

# ------------------------------------------
# STEP 5 — GENERATE REPORTS
# ------------------------------------------
print("\n[*] Generating reports...")

html_report = zap.core.htmlreport()
json_report = zap.core.jsonreport()

with open(REPORT_HTML, "w", encoding="utf-8") as f:
    f.write(html_report)

with open(REPORT_JSON, "w", encoding="utf-8") as f:
    f.write(json_report)

print(f"[+] Reports saved as:\n    {REPORT_HTML}\n    {REPORT_JSON}")

# ------------------------------------------
# STEP 6 — PRINT ALERT SUMMARY
# ------------------------------------------
print("\n[*] Alert Summary:")
alerts = zap.core.alerts()

if not alerts:
    print("  No alerts found.")
else:
    for a in alerts:
        print(f" - [{a.get('risk')}] {a.get('alert')} → {a.get('url')}")

print("\n[*] Scan completed.")


