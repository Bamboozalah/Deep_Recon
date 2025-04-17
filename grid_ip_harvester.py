
import shodan
import logging
import os

def fetch_grid_related_ips(org=None, asn=None, keywords=None, limit=100):
    logging.info("Fetching grid-related IPs from Shodan")
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logging.error("SHODAN_API_KEY not set in environment variables.")
        return []

    api = shodan.Shodan(api_key)
    query_parts = []

    if org:
        query_parts.append(f'org:"{org}"')
    if asn:
        query_parts.append(f"asn:{asn}")
    if keywords:
        query_parts.extend(keywords)

    query = " ".join(query_parts) or "Electric Cooperative port:502"
    logging.info(f"Running Shodan search with query: {query}")

    try:
        results = api.search(query, limit=limit)
        ips = list({match["ip_str"] for match in results["matches"] if "ip_str" in match})
        logging.info(f"Found {len(ips)} unique IPs")
        return ips
    except Exception as e:
        logging.error(f"Error searching Shodan: {e}")
        return []
