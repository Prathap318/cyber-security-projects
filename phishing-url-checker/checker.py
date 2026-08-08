"""Offline heuristic phishing URL checker for defensive learning."""
from urllib.parse import urlparse
import ipaddress
import re
import sys

RISKY_WORDS = {"login", "verify", "update", "secure", "account", "password", "wallet", "signin"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}


def check_url(value: str) -> list[str]:
    value = value.strip()
    parsed = urlparse(value if "://" in value else "https://" + value)
    host = parsed.hostname or ""
    findings: list[str] = []

    if parsed.scheme != "https":
        findings.append("URL does not use HTTPS")

    try:
        ipaddress.ip_address(host)
        findings.append("Host is an IP address")
    except ValueError:
        pass

    if "@" in value:
        findings.append("URL contains @, which can obscure the real destination")

    if len(value) > 100:
        findings.append("Unusually long URL")

    if host.lower() in SHORTENERS:
        findings.append("Known URL-shortener host")

    tokens = set(re.findall(r"[a-z0-9]+", value.lower()))
    risky = sorted(tokens & RISKY_WORDS)
    if risky:
        findings.append("Risky keywords: " + ", ".join(risky))

    if host.count(".") >= 3:
        findings.append("Many subdomain levels")

    return findings


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else input("Enter URL to inspect: ")
    findings = check_url(url)
    print("=== Phishing URL Checker ===")
    print(f"URL: {url}")
    if findings:
        print("Indicators found:")
        for finding in findings:
            print(f"- {finding}")
    else:
        print("No obvious heuristic indicators found.")
    print("Note: This is a heuristic check, not proof that a URL is safe or malicious.")


if __name__ == "__main__":
    main()
