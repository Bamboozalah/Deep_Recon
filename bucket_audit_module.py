
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

def check_bucket_url(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return "public-readable"
        elif r.status_code == 403:
            return "exists-not-listable"
        elif r.status_code == 404:
            return "not-found"
        else:
            return f"unknown-{r.status_code}"
    except Exception as e:
        logging.warning(f"Error checking {url}: {e}")
        return "error"

def run(shared_data):
    logging.info("Running Public Cloud Bucket Audit (No Credentials)")
    domain = shared_data.get("root_domain", "")
    company = shared_data.get("company_name", "")
    subdomains = shared_data.get("subdomains", [])

    bucket_names = generate_bucket_candidates(domain, company, subdomains)

    results = {}
    for name in bucket_names:
        aws_result = check_bucket_url(f"https://{name}.s3.amazonaws.com")
    gcp_result = check_bucket_url(f"https://storage.googleapis.com/{name}")
    azure_result = check_bucket_url(f"https://{name}.blob.core.windows.net")

    def severity_level(result): 
        if "public-readable" in result:
            return "high"
        elif "exists-not-listable" in result:
            return "medium"
        else:
            return "info"

        result = {
            "aws": {"status": aws_result, "severity": severity_level(aws_result)},
            "gcp": {"status": gcp_result, "severity": severity_level(gcp_result)},
            "azure": {"status": azure_result, "severity": severity_level(azure_result)}
        }
        results[name] = result
        if "public-readable" in result.values():
            logging.warning(f"🟢 Publicly accessible bucket: {name} => {result}")

    shared_data["bucket_audit"] = results
    return results
