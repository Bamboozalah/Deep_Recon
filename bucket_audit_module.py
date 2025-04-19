
import time
import requests
import logging
from requests.exceptions import SSLError, Timeout, ConnectionError

def request_with_retries(url, retries=2, delay=0.25, verbose=False):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=5)
            return response.status_code
        except SSLError:
            logging.warning(f"SSL Error (skipped retry): {url}")
            return "ssl_error"
        except Timeout:
            logging.warning(f"Timeout (attempt {attempt}): {url}")
        except ConnectionError:
            logging.warning(f"Connection error (attempt {attempt}): {url}")
        except Exception as e:
            logging.warning(f"Other error (attempt {attempt}): {e}")
        if verbose:
            time.sleep(delay)
    return None

import requests
import logging

DEFAULT_WORDS = [
    "prod", "dev", "test", "backup", "logs", "assets", "data", "reports", "docs",
    "vpn", "configs", "internal", "external", "shared", "restricted", "outage",
    "iot", "archive", "dump", "nerc", "cip", "crew", "admin", "incident", "vpn"
]

def generate_bucket_candidates(domain, company=None, subdomains=None):
    base = domain.split('.')[0]
    labels = set()

    if subdomains:
        for sub in subdomains:
            label = sub.split('.')[0]
            labels.add(label.lower())

    parts = [base, domain, company] if company else [base, domain]
    parts.extend(labels)
    parts = set(filter(None, parts))

    candidates = set()
    for word in DEFAULT_WORDS:
        for base in parts:
            candidates.add(f"{base}-{word}")
            candidates.add(f"{word}-{base}")
            candidates.add(base)
    return sorted(candidates)

# replaced with request_with_retries

def run(shared_data):

    # Fast/Verbose Mode Prompt
    console.print("\n[bold cyan]Choose Bucket Audit Mode:[/bold cyan]")
    fast_mode = Prompt.ask("Run in fast mode? (limits checks to 100)", choices=["y", "n"], default="y") == "y"
    verbose_mode = not fast_mode
    logging.info("Running Public Cloud Bucket Audit (No Credentials)")
    domain = shared_data.get("root_domain", "")
    company = shared_data.get("company_name", "")
    subdomains = shared_data.get("subdomains", [])

    bucket_names = generate_bucket_candidates(domain, company, subdomains)

    results = {}
    for i, name in enumerate(bucket_names):
    if fast_mode and i >= 100:
        break
        result = {
            "aws": request_with_retries(f"https://{name}.s3.amazonaws.com", delay=0.25, verbose=verbose_mode),
            "gcp": check_bucket_url(f"https://storage.googleapis.com/{name}"),
            "azure": check_bucket_url(f"https://{name}.blob.core.windows.net")
        }
        results[name] = result
        if "public-readable" in result.values():
            logging.warning(f"🟢 Publicly accessible bucket: {name} => {result}")

    shared_data["bucket_audit"] = results
    return results
