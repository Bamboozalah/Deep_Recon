
import os
import requests
import logging
from dotenv import load_dotenv
from shodan_utils import shodan_search, shodan_get_asn

load_dotenv(dotenv_path="config/api_keys.env")

def search_asns_by_company(company_name):
    logging.info(f"Searching ASNs for company: {company_name}")
    try:
        url = f"https://api.bgpview.io/search?query_term={company_name}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if "asns" in data["data"]:
                return [asn["asn"] for asn in data["data"]["asns"]]
    except Exception as e:
        logging.error(f"ASN lookup failed for {company_name}: {e}")
    return []


def fetch_subnets_for_asn(asn, api_key):
    # api initialization removed (using shodan_utils)
    subnets = []
    try:
        asn_data = shodan_get_asn(f"AS{asn}")
        subnets = [prefix for prefix in asn_data.get("prefixes", [])]
    except Exception as e:
        logging.error(f"Failed to get Shodan ASN data for AS{asn}: {e}")
    return subnets


def run(shared_data):
    logging.info("Running Grid IP Harvester...")
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logging.error("SHODAN_API_KEY not set. Please configure your API key.")
        return {}

    company = shared_data.get("company_name", "")
    asns = search_asns_by_company(company)
    if not asns:
        logging.warning(f"No ASNs found for company: {company}")
        return {}

    all_subnets = []
    for asn in asns:
        all_subnets.extend(fetch_subnets_for_asn(asn, api_key))

    shared_data["grid_ips"] = all_subnets
    return all_subnets
