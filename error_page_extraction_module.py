# error_page_extraction_module.py
#!/usr/bin/env python3
import requests
import re
import logging
import os
import sys

from urllib.parse import urlparse

def init_logging():
    logging.basicConfig(
        filename='error_page_extraction.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Error Page Extraction Module started.")

def normalize_url(target):
    if not target.startswith("http"):
        return f"http://{target}"
    return target

def extract_error_messages(html):
    error_patterns = [
        r"(?i)(?<=<!--).*?error.*?(?=-->)",
        r"(?i)<title>.*?error.*?</title>",
        r"(?i)exception.*?<br />",
        r"(?i)\berror [0-9]{3}\b",
        r"(?i)(stack trace|stacktrace)",
        r"(?i)(SQL syntax|mysqli|pdo|oracle|fatal error|exception|undefined|notice:|warning:)"
    ]
    messages = []
    for pattern in error_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
        messages.extend(matches)
    return list(set(messages))

def process_target_or_file(input_value):
    targets = []
    if os.path.isfile(input_value):
        with open(input_value, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    targets.append(normalize_url(line))
    else:
        targets = [normalize_url(input_value)]
    return targets

def run_error_page_extraction(input_value=None, enrichment_targets=None):
    init_logging()
    targets = []

    if enrichment_targets:
        targets.extend([normalize_url(t) for t in enrichment_targets])

    if input_value:
        targets.extend(process_target_or_file(input_value))

    # Deduplicate
    targets = list(set(targets))
    all_errors = []

    for target in targets:
        print(f"\n[Error Page Extraction] Checking: {target}")
        try:
            response = requests.get(target, timeout=10, allow_redirects=True, verify=False)
            response.raise_for_status()
            error_msgs = extract_error_messages(response.text)
            if error_msgs:
                print(f"  [!] Potential error messages found at {target}:")
                for msg in error_msgs:
                    print(f"    - {msg.strip()[:200]}")
                all_errors.append({"target": target, "errors": error_msgs})
            else:
                print(f"  [-] No error messages found on {target}.")
        except Exception as e:
            logging.error(f"Error checking {target}: {e}")
            print(f"  [x] Request failed for {target}: {e}")

    return all_errors

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 error_page_extraction_module.py <target_or_file>")
        sys.exit(1)
    input_value = sys.argv[1]
    run_error_page_extraction(input_value=input_value)

if __name__ == "__main__":
    main()
