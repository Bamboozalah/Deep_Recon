#!/usr/bin/env python3
import requests
import logging
import re
import sys
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


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
            findings.append(message)
    return list(set(findings))


def extract_embedded_code(html):
    embedded = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all("script"):
            if script.string:
                code = script.string.strip()
                if any(x in code.lower() for x in ["modbus", "bacnet", "opc", "mqtt", "ladder", "firmware"]):
                    embedded.append(code[:200])  # Store a snippet of the code for context
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


def run_supply_chain_detection(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_findings = {}
    for target in targets:
        print(f"\n[Supply Chain Detection] Processing target: {target}")
        try:
            response = requests.get(target, timeout=15)
            findings = scan_for_supply_chain(response.text)
            embedded_snippets = extract_embedded_code(response.text)
            js_config_links = extract_js_config_links(response.text, target)
            js_indicators = download_and_check_js(js_config_links)

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
                "js_config_indicators": js_indicators
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
