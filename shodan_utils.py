load_dotenv(dotenv_path='config/api_keys.env')

import os
import logging
from dotenv import load_dotenv
import shodan

load_dotenv(dotenv_path="config/api_keys.env")

def get_api():
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logging.error("SHODAN_API_KEY not found in environment.")
        return None
    return shodan.Shodan(api_key)

def shodan_search(query, limit=100):
    api = get_api()
    if not api:
        return []

    try:
        results = api.search(query, limit=limit)
        return results.get("matches", [])
    except Exception as e:
        logging.error(f"Shodan search failed for query '{query}': {e}")
        return []

def shodan_get_asn(asn):
    api = get_api()
    if not api:
        return {}

    try:
        return api.asn(f"AS{asn}")
    except Exception as e:
        logging.error(f"Shodan ASN lookup failed for AS{asn}: {e}")
        return {}
