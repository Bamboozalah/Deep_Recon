from utils import get_api_key
def get_api_key(key):
    return os.getenv(key)


from shodan_utils import shodan_search, shodan_get_asn
import logging

def run(shared_data):
    company = shared_data.get("company_name", "").strip()
    domains = shared_data.get("cert_domains", [])
    asns = set()
    ip_ranges = set()

    if company:
        logging.info(f"Running Shodan org search for company: {company}")
        results = shodan_search(f'org:"{company}"')
        for match in results:
            asn = match.get("asn")
            if asn:
                asns.add(asn)
            ip = match.get("ip_str")
            if ip:
                ip_ranges.add(ip + "/32")

    if not asns and domains:
        logging.info("No ASNs from org name, trying fallback cert domain-based resolution...")
        for domain in domains:
            results = shodan_search(f'hostname:"{domain}"')
            for match in results:
                asn = match.get("asn")
                if asn:
                    asns.add(asn)
                ip = match.get("ip_str")
                if ip:
                    ip_ranges.add(ip + "/32")

    shared_data["grid_asns"] = sorted(asns)
    shared_data["grid_ips"] = sorted(ip_ranges)

    logging.info(f"Identified {len(asns)} ASNs and {len(ip_ranges)} IPs for scanning.")