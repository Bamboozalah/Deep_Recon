import os
import logging
from utils import get_api_key
from shodan_utils import shodan_search, shodan_get_asn

def get_api_key(key):
    return os.getenv(key)

def run(shared_data):
    search_terms = list(filter(None, [
        shared_data.get("company_name"),
        shared_data.get("organization_name"),
        shared_data.get("origin_registrant"),
        shared_data.get("prefix_registrant")
    ]))
    
    if not search_terms:
        manual = input("Enter a fallback organization search term (optional): ").strip()
        if manual:
            search_terms.append(manual)

    domains = shared_data.get("cert_domains", [])
    asns = set()
    ip_ranges = set()

    for term in search_terms:
        logging.info(f"Searching Shodan for org: {term}")
        results = shodan_search(f'org:"{term}"')
        for match in results:
            asn = match.get("asn")
            ip = match.get("ip_str")
            if asn:
                asns.add(asn)
            if ip:
                ip_ranges.add(ip + "/32")

    if not asns and domains:
        logging.info("No ASNs from org name, trying fallback cert domain-based resolution...")
        for domain in domains:
            results = shodan_search(f'hostname:"{domain}"')
            for match in results:
                asn = match.get("asn")
                ip = match.get("ip_str")
                if asn:
                    asns.add(asn)
                if ip:
                    ip_ranges.add(ip + "/32")

    shared_data["grid_asns"] = sorted(asns)
    shared_data["grid_ips"] = sorted(ip_ranges)
    shared_data["grid_sources"] = ["shodan"]
    logging.info(f"Identified {len(asns)} ASNs and {len(ip_ranges)} IPs for scanning.")

def fetch_grid_related_ips(shared_data):
    return run(shared_data)
