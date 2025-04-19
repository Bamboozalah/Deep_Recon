
from shodan_utils import shodan_search, shodan_get_asn
import socket
import logging
import os

def resolve_to_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception as e:
        logging.warning(f"Could not resolve {hostname} to IP: {e}")
        return None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run(shared_data):
    logging.info("Running Shodan Query Module")

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logging.error("SHODAN_API_KEY not set in environment variables.")
        return {}

    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains found in shared_data.")
        return {}

    # api initialization removed (using shodan_utils)
    results = {}

    for host in subdomains:
        ip = resolve_to_ip(host)
        if not ip:
            continue

        try:
            response = api.host(ip)
            results[host] = {
                "ip": ip,
                "data": response
            }
            logging.info(f"Retrieved Shodan data for {host} ({ip})")
        except shodan.APIError as e:
            logging.warning(f"Shodan API error for {host}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during Shodan query for {host}: {e}")

    shared_data["shodan_results"] = results
    return results
