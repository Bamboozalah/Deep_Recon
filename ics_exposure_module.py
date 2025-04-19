
import os
import logging
from dotenv import load_dotenv
from shodan_utils import shodan_search, shodan_get_asn

load_dotenv(dotenv_path="config/api_keys.env")

def run(shared_data):
    logging.info("Running ICS Exposure Detection Module...")
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logging.error("SHODAN_API_KEY not found. Please run Configure API Keys from the CLI.")
        return {}

    domain = shared_data.get("root_domain", "")
    company = shared_data.get("company_name", "")
    subnets = shared_data.get("grid_ips", [])
    if not subnets:
        logging.warning("No grid IPs found in shared_data.")
        choice = input("Would you like to run the Grid IP Harvester now? (y/n): ").strip().lower()
        if choice == 'y':
            try:
                from grid_ip_harvester import run as run_grid_harvest
                run_grid_harvest(shared_data)
                subnets = shared_data.get("grid_ips", [])
            except Exception as e:
                logging.error(f"Failed to run grid_ip_harvester: {e}")
        else:
            logging.info("Skipping ICS scan due to missing IPs.")
            return {}
    if not subnets:
        logging.warning("No grid IP ranges provided to scan.")
        return {}

    # api initialization removed (using shodan_utils)
    ics_ports = [102, 502, 20000, 44818, 47808, 1911, 1962]
    results = []

    for subnet in subnets:
        for port in ics_ports:
            try:
                query = f"net:{subnet} port:{port}"
                matches = shodan_search(query)
                for match in matches["matches"]:
                    result = {
                        "ip": match["ip_str"],
                        "port": match["port"],
                        "org": match.get("org", ""),
                        "product": match.get("product", ""),
                        "asn": match.get("asn", ""),
                        "hostnames": match.get("hostnames", []),
                        "location": match.get("location", {}),
                        "timestamp": match.get("timestamp")
                    }
                    results.append(result)
            except Exception as e:
                logging.warning(f"Error scanning {subnet} port {port}: {e}")
                continue

    shared_data["ics_exposure"] = results
    return results
