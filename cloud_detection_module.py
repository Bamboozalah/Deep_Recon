
import requests
import logging
import re

CLOUD_PATTERNS = {
    "AWS": ["s3.amazonaws.com", "cloudfront.net", "amazonaws.com"],
    "Azure": ["azurewebsites.net", "cloudapp.net", "windows.net"],
    "Google Cloud": ["appspot.com", "googleusercontent.com", "gstatic.com"],
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
    "Oracle Cloud": ["oraclecloud.com", "ocp.oraclecloud.com"],
    "DigitalOcean": ["digitalocean"],
    "Alibaba Cloud": ["aliyun.com"]
}

def detect_cloud_from_headers(headers):
    stack = []
    for key, value in headers.items():
        for cloud, patterns in CLOUD_PATTERNS.items():
            if any(pat.lower() in value.lower() for pat in patterns):
                stack.append(cloud)
    return list(set(stack))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run(shared_data):
    logging.info("Running Cloud Detection Module")

    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains provided to Cloud Detection Module")
        return {}

    cloud_results = {}

    for domain in subdomains:
        url = f"https://{domain}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            stack = detect_cloud_from_headers(r.headers)
            cloud_results[domain] = {
                "status_code": r.status_code,
                "cloud_providers": stack,
                "headers": dict(r.headers)
            }
            logging.info(f"{domain}: {stack}")
        except requests.RequestException as e:
            logging.warning(f"Request failed for {domain}: {e}")

    shared_data["cloud_fingerprint"] = cloud_results
    return cloud_results
