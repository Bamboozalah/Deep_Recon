#!/usr/bin/env python3
import requests
import logging
import re
import time
import sys

def init_logging():
    logging.basicConfig(
        filename="wayback_js.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )
    logging.info("Wayback JS Module started.")

def fetch_wayback_data(target):
    url = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original"
    logging.info(f"Fetching Wayback Machine data for {target} using URL: {url}")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error("Error fetching Wayback data: " + str(e))
        print("Error fetching Wayback Machine data for target:", target)
        return []

def filter_js_urls(wayback_data):
    js_urls = set()
    if len(wayback_data) < 2:
        return list(js_urls)
    # Skip header row if present.
    for entry in wayback_data[1:]:
        if entry and len(entry) > 0:
            url = entry[0]
            if url.lower().endswith('.js'):
                js_urls.add(url)
    return list(js_urls)

def download_js_content(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")
        return None

def analyze_js_vulnerabilities(js_urls):
    """
    Scans the content of each JavaScript file for vulnerability indicators.
    Returns a list of findings, each a dictionary containing the URL and the list of (pattern, exploit) tuples.
    """
    findings = []
    # Patterns to scan for and the corresponding MITRE or descriptive mapping.
    patterns = {
        r"eval\s*\(": "MITRE T1059.001 - Command and Scripting Interpreter: JavaScript",
        r"document\.write\s*\(": "Potential Dynamic Code Generation (may lead to XSS)",
        r"password": "Credential Exposure (password found)",
        r"api[_-]?key": "Sensitive API key exposure",
        r"secret": "Sensitive information exposure"
    }
    print("\n[JS Vulnerability Analysis] Scanning JavaScript files for vulnerable patterns...")
    for url in js_urls:
        content = download_js_content(url)
        if content is None:
            continue
        file_findings = []
        for pattern, exploit in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                file_findings.append((pattern, exploit))
        if file_findings:
            findings.append({
                "url": url,
                "findings": file_findings
            })
            print(f"Vulnerabilities detected in: {url}")
        else:
            print(f"No notable vulnerabilities in: {url}")
    if not findings:
        print("No vulnerabilities detected in any JavaScript files.")
    logging.info(f"Vulnerability analysis complete. {len(findings)} files with potential vulnerabilities found.")
    return findings

def save_js_urls(js_urls, target):
    filename = f"wayback_js_{target.replace('.', '_')}.txt"
    try:
        with open(filename, "w") as f:
            for url in js_urls:
                f.write(url + "\n")
        logging.info(f"JS URLs saved to {filename}")
        return filename
    except Exception as e:
        logging.error("Error saving JS URLs: " + str(e))
        print("Error saving JS URLs to file.")
        return None

def run_wayback_js_extraction(target):
    """
    Fetches Wayback Machine data for the given target, filters for .js URLs,
    saves the URLs to a file, and runs vulnerability analysis on them.
    Returns a tuple: (list_of_js_urls, vulnerability_findings)
    """
    init_logging()
    print(f"\n[Wayback JS Extraction & Vulnerability Analysis] Processing target '{target}'...")
    print("Fetching data from Wayback Machine...", end="", flush=True)
    for _ in range(3):
        print(".", end="", flush=True)
        time.sleep(1)
    print(" Done.")
    wayback_data = fetch_wayback_data(target)
    js_urls = filter_js_urls(wayback_data)
    count = len(js_urls)
    print(f"Extracted {count} JavaScript URLs from the Wayback Machine.")
    logging.info(f"Extracted {count} JavaScript URLs for target {target}.")
    if count > 0:
        filename = save_js_urls(js_urls, target)
        if filename:
            print(f"JavaScript URLs saved to {filename}")
    else:
        print("No JavaScript URLs were extracted.")
    vulnerability_results = analyze_js_vulnerabilities(js_urls)
    return js_urls, vulnerability_results

def main():
    init_logging()
    if len(sys.argv) < 2:
        print("Usage: python3 wayback_js_module.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    run_wayback_js_extraction(target)

if __name__ == "__main__":
    main()
