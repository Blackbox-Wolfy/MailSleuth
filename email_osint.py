#!/usr/bin/env python3
"""
email_osint.py - Ethical email OSINT tool (public data only).

Use ONLY on email addresses you own or have explicit permission to investigate.

Checks:
  1. Syntax validation
  2. Domain MX / SPF / DMARC records (DNS)
  3. Disposable-domain detection
  4. Gravatar profile (public)
  5. Breach lookup via HaveIBeenPwned (needs HIBP_API_KEY env var)

Install:  pip install requests dnspython
Run:      python email_osint.py someone@example.com [--json]
"""

import argparse
import hashlib
import json
import os
import re
import sys

import requests

try:
    import dns.resolver
except ImportError:
    dns = None

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# Small starter list. Extend it or load a bigger list from a file.
DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "tempmail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "dispostable.com", "maildrop.cc",
}

HEADERS = {"User-Agent": "email-osint-educational/1.0"}
TIMEOUT = 10


def check_syntax(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


def dns_lookup(domain: str, rtype: str, prefix: str = "") -> list:
    if dns is None:
        return ["dnspython not installed"]
    try:
        answers = dns.resolver.resolve(prefix + domain, rtype, lifetime=TIMEOUT)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def check_dns(domain: str) -> dict:
    mx = dns_lookup(domain, "MX")
    txt = dns_lookup(domain, "TXT")
    dmarc = dns_lookup(domain, "TXT", "_dmarc.")
    return {
        "mx_records": mx,
        "has_mx": bool(mx) and mx != ["dnspython not installed"],
        "spf": [t for t in txt if "v=spf1" in t],
        "dmarc": [t for t in dmarc if "v=DMARC1" in t],
    }


def check_gravatar(email: str) -> dict:
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    url = f"https://gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        found = r.status_code == 200
        return {"found": found, "avatar_url": url if found else None}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_breaches(email: str) -> dict:
    key = os.getenv("HIBP_API_KEY")
    if not key:
        return {"skipped": "Set HIBP_API_KEY to enable breach lookup"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        r = requests.get(
            url,
            headers={**HEADERS, "hibp-api-key": key},
            params={"truncateResponse": "false"},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"breached": False, "breaches": []}
        if r.status_code == 200:
            data = r.json()
            return {
                "breached": True,
                "count": len(data),
                "breaches": [
                    {"name": b["Name"], "date": b["BreachDate"],
                     "data": b["DataClasses"]}
                    for b in data
                ],
            }
        return {"error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def analyze(email: str) -> dict:
    email = email.strip().lower()
    result = {"email": email, "valid_syntax": check_syntax(email)}
    if not result["valid_syntax"]:
        return result
    domain = email.split("@", 1)[1]
    result["domain"] = domain
    result["disposable"] = domain in DISPOSABLE
    result["dns"] = check_dns(domain)
    result["gravatar"] = check_gravatar(email)
    result["breaches"] = check_breaches(email)
    return result


def print_report(r: dict) -> None:
    print(f"\n=== Email OSINT: {r['email']} ===")
    print(f"Valid syntax : {r['valid_syntax']}")
    if not r["valid_syntax"]:
        return
    print(f"Domain       : {r['domain']}")
    print(f"Disposable   : {r['disposable']}")
    d = r["dns"]
    print(f"Has MX       : {d['has_mx']}  {d['mx_records']}")
    print(f"SPF          : {d['spf'] or 'none'}")
    print(f"DMARC        : {d['dmarc'] or 'none'}")
    g = r["gravatar"]
    print(f"Gravatar     : {g.get('avatar_url') or g.get('error') or 'not found'}")
    b = r["breaches"]
    if "breached" in b:
        print(f"Breached     : {b['breached']} ({b.get('count', 0)} breaches)")
        for x in b["breaches"]:
            print(f"   - {x['name']} ({x['date']})")
    else:
        print(f"Breaches     : {b.get('skipped') or b.get('error')}")
    print()


def main() -> None:
    p = argparse.ArgumentParser(description="Ethical email OSINT tool")
    p.add_argument("email")
    p.add_argument("--json", action="store_true", help="output JSON")
    args = p.parse_args()

    result = analyze(args.email)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    sys.exit(main())
