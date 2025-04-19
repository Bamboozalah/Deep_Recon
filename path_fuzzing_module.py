
import requests
import logging

COMMON_PATHS = [
    "/.env", "/admin", "/login", "/config", "/debug", "/test", "/backup", "/.git", "/phpinfo.php",
    "/server-status", "/.DS_Store", "/wp-admin", "/robots.txt", "/sitemap.xml", "/error", "/debug.log"
]

def fuzz_paths(domain):
    results = []
    base_url = f"https://{domain}"

    for path in COMMON_PATHS:
        url = base_url + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 301, 302, 403]:
                results.append({"path": path, "status": r.status_code})
                logging.info(f"{domain}{path} -> {r.status_code}")
        except requests.RequestException as e:
            logging.debug(f"Request to {url} failed: {e}")
    return results

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run(shared_data):
    logging.info("Running Path Fuzzing Module")
    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains for path fuzzing.")
        return {}

    output = {}
    for domain in subdomains:
        output[domain] = fuzz_paths(domain)

    shared_data["path_fuzzing"] = output
    return output
