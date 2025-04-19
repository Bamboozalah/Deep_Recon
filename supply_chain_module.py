
import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def extract_third_party_domains(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    domains = set()

    for tag in soup.find_all(["script", "link", "img", "iframe"]):
        src = tag.get("src") or tag.get("href")
        if src:
            full_url = urljoin(base_url, src)
            domain = urlparse(full_url).netloc
            if domain and not domain.endswith(base_url):
                domains.add(domain)
    return list(domains)

def run(shared_data):
    subdomains = shared_data.get("subdomains") or shared_data.get("cert_domains") or []
    if not subdomains:
        logging.warning("No subdomains available. Consider running Subdomain or Cert modules first.")
        return

    logging.info("Running Supply Chain Module")
    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains to scan for third-party supply chain domains.")
        return {}

    supply_map = {}

    for domain in subdomains:
        url = f"https://{domain}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                vendors = extract_third_party_domains(r.text, url)
                if vendors:
                    supply_map[domain] = vendors
                    logging.info(f"{domain} includes {len(vendors)} third-party services")
        except Exception as e:
            logging.debug(f"Failed to fetch {url}: {e}")

    shared_data["supply_chain"] = supply_map
    return supply_map