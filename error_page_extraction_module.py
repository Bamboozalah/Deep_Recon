
import requests
import re
import logging

ERROR_PATTERNS = [
    r"(?i)(?<=<!--).*?error.*?(?=-->)",
    r"(?i)<title>.*?error.*?</title>",
    r"(?i)exception.*?<br />",
    r"(?i)\\berror [0-9]{3}\\b",
    r"(?i)(stack trace|stacktrace)",
    r"(?i)(SQL syntax|mysqli|pg_query|mysql_fetch|sql error|db error)"
]

def extract_errors(html):
    found = []
    for pattern in ERROR_PATTERNS:
        matches = re.findall(pattern, html, re.IGNORECASE)
        found.extend(matches)
    return list(set(found))

def run(shared_data):
    logging.info("Running Error Page Extraction Module")
    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains to scan for error pages.")
        return {}

    output = {}

    for domain in subdomains:
        url = f"https://{domain}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code >= 400 or "error" in r.text.lower():
                errors = extract_errors(r.text)
                if errors:
                    output[domain] = errors
                    logging.info(f"{domain} returned {len(errors)} error indicators")
        except Exception as e:
            logging.debug(f"Error fetching {domain}: {e}")

    shared_data["error_pages"] = output
    return output
