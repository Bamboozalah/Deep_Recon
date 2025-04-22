import requests
import re
import logging
from rich.prompt import Prompt
from rich.console import Console
import time

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
    console = Console()
    console.print("\n[bold cyan]Choose Error Page Extraction Module.Py Mode:[/bold cyan]")
    fast_mode = Prompt.ask("Run in fast mode? (limits to 150 items)", choices=["y", "n"], default="y") == "y"
    verbose_mode = not fast_mode

    subdomains = shared_data.get("subdomains") or shared_data.get("cert_domains") or []
    if not subdomains:
        logging.warning("No subdomains available. Consider running Subdomain or Cert modules first.")
        return

    if fast_mode:
        console.print("[yellow]Fast mode selected. Scanning only first 150 domains.[/yellow]")
        subdomains = subdomains[:150]

    logging.info("Running Error Page Extraction Module")
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
        except requests.exceptions.SSLError:
            logging.warning(f"SSL error for {domain}, skipping.")
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout on {domain}, skipping.")
        except requests.exceptions.RequestException as e:
            logging.debug(f"Request error fetching {domain}: {e}")

    shared_data["error_pages"] = output
    return output
