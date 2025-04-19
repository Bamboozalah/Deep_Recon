#!/usr/bin/env python3
import requests
import logging
import re
import sys
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def init_logging():
    logging.basicConfig(
        filename='supply_chain_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Supply Chain Detection Module started.")


def load_targets(input_arg):
    targets = []
    if input_arg.endswith(".txt") and os.path.isfile(input_arg):
        try:
            with open(input_arg, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(targets)} targets from {input_arg}.")
        except Exception as e:
            logging.error(f"Error reading {input_arg}: {e}")
            print(f"Error reading {input_arg}: {e}")
    else:
        targets.append(input_arg)
    return targets


def scan_for_supply_chain(content):
    findings = []
    keywords = {
        "scada": "SCADA system indicator",
        "plc": "PLC interface indicator",
        "rtu": "RTU device indicator",
        "hmi": "HMI (Human Machine Interface) detected",
        "dcs": "DCS (Distributed Control System) detected",
        "ics": "ICS (Industrial Control System) detected",
        "ot": "Operational Technology (OT) interface detected",
        "default password": "Potential default credential exposure",
        "exposed device": "Exposed device interface found",

        # Vendor and product indicators
        "rockwell": "Rockwell Automation product mentioned",
        "allen-bradley": "Allen-Bradley product mentioned",
        "siemens": "Siemens control system reference",
        "schneider": "Schneider Electric system reference",
        "abb": "ABB industrial system reference",
        "mitsubishi": "Mitsubishi PLC or ICS reference",
        "honeywell": "Honeywell industrial device referenced",
        "emerson": "Emerson control system reference",
        "omron": "Omron PLC interface detected",
        "yokogawa": "Yokogawa industrial device detected"
    }
    content_lower = content.lower()
    for key, message in keywords.items():
        if key in content_lower:
            findings.append((key, message))
    return list(set(findings))


def extract_embedded_code(html):
    embedded = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all("script"):
            if script.string:
                code = script.string.strip()
                if any(x in code.lower() for x in ["modbus", "bacnet", "opc", "mqtt", "ladder", "firmware"]):
                    embedded.append(code[:200])
    except Exception as e:
        logging.error(f"Error parsing embedded scripts: {e}")
    return embedded


def extract_js_config_links(html, base_url):
    js_links = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all("script", src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            if any(x in src.lower() for x in ["config", "settings", "init", "firmware"]):
                js_links.append(full_url)
    except Exception as e:
        logging.error(f"Error extracting JavaScript config links: {e}")
    return js_links


def download_and_check_js(js_urls):
    embedded_indicators = []
    for js_url in js_urls:
        try:
            response = requests.get(js_url, timeout=10)
            if response.status_code == 200:
                code = response.text.lower()
                if any(x in code for x in ["token", "apikey", "modbus", "plc", "vendor", "admin"]):
                    embedded_indicators.append((js_url, code[:150]))
        except Exception as e:
            logging.error(f"Error fetching or analyzing JS from {js_url}: {e}")
    return embedded_indicators


def query_cves(keyword):
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 3
        }
        response = requests.get(CVE_API_URL, params=params, timeout=10)
        if response.status_code == 200:
            results = response.json()
            return [item["cve"] for item in results.get("vulnerabilities", []) if "cve" in item]
    except Exception as e:
        logging.error(f"Error fetching CVEs for keyword '{keyword}': {e}")
    return []


def run_supply_chain_detection(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_findings = {}
    for target in targets:
        print(f"\n[Supply Chain Detection] Processing target: {target}")
        try:
            response = requests.get(target, timeout=15)
            raw_findings = scan_for_supply_chain(response.text)
            findings = [msg for _, msg in raw_findings]
            embedded_snippets = extract_embedded_code(response.text)
            js_config_links = extract_js_config_links(response.text, target)
            js_indicators = download_and_check_js(js_config_links)

            cve_results = {}
            for key, _ in raw_findings:
                cves = query_cves(key)
                if cves:
                    cve_results[key] = cves

            if embedded_snippets:
                findings.append(f"Embedded industrial-related code detected: {len(embedded_snippets)} snippet(s)")
            if js_indicators:
                findings.append(f"Exposed config/firmware JavaScript detected: {len(js_indicators)} file(s)")

            if findings:
                print(f"Findings: {', '.join(findings)}")
            else:
                print("No supply chain or exposed device indicators detected.")

            all_findings[target] = {
                "indicators": findings,
                "embedded_code_snippets": embedded_snippets,
                "js_config_indicators": js_indicators,
                "cves": cve_results
            }
        except Exception as e:
            logging.error(f"Error processing {target}: {e}")
            print(f"Error processing {target}: {e}")
        time.sleep(1)
    return all_findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 supply_chain_module.py <target_or_targets_file>")
        sys.exit(1)
    input_arg = sys.argv[1]
    findings = run_supply_chain_detection(input_arg)
    print("\n=== Supply Chain Detection Summary ===")
    for t, result in findings.items():
        print(f"\n{t}:")
        for f in result["indicators"]:
            print(f"  - {f}")
        if result["cves"]:
            print("  Related CVEs:")
            for k, cves in result["cves"].items():
                for cve in cves:
                    print(f"    [{k.upper()}] {cve.get('id')} - {cve.get('descriptions', [{}])[0].get('value', 'No description')}")
        if result["embedded_code_snippets"]:
            print("  Embedded Code Snippets:")
            for snippet in result["embedded_code_snippets"]:
                print(f"    > {snippet[:100]}...")
        if result["js_config_indicators"]:
            print("  JavaScript Config Indicators:")
            for js_url, snippet in result["js_config_indicators"]:
                print(f"    [URL] {js_url}\n    [Snippet] {snippet[:100]}...")


if __name__ == "__main__":
    main()


def parse_shodan_vulns(match):
    return list(match.get("vulns", {}).keys()) if "vulns" in match else []

def parse_github_secrets(results):
    secrets = []
    for hit in results:
        if "secret" in hit.get("description", "").lower():
            secrets.append(hit)
    return secrets

def compute_risk_score(shodan_vulns=None, github_hits=None):
    score = 0
    if shodan_vulns:
        score += len(shodan_vulns)
    if github_hits:
        score += 2 * len(github_hits)
    return min(score, 10)
