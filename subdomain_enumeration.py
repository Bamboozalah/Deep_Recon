
import subprocess
import logging

def run_subdomain_enumeration(domain, tool='subfinder'):
    logging.info(f"Starting subdomain enumeration on: {domain} using {tool}")
    try:
        if tool.lower() == 'subfinder':
            cmd = ['subfinder', '-d', domain, '-silent']
        elif tool.lower() == 'assetfinder':
            cmd = ['assetfinder', '--subs-only', domain]
        else:
            logging.warning(f"Unknown tool {tool}, defaulting to subfinder.")
            cmd = ['subfinder', '-d', domain, '-silent']

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            subdomains = list(set(result.stdout.strip().split('\n')))
            logging.info(f"Found {len(subdomains)} subdomains for {domain}")
            return subdomains
        else:
            logging.error(f"Subdomain enumeration failed for {domain}: {result.stderr}")
            return []
    except Exception as e:
        logging.error(f"Exception during subdomain enumeration for {domain}: {e}")
        return []

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run(shared_data):
    logging.info("Running Subdomain Enumeration Module")
    root_domain = shared_data.get("root_domain")
    if not root_domain:
        logging.error("No root domain provided in shared_data['root_domain']")
        return []

    subdomains = run_subdomain_enumeration(root_domain)
    shared_data["subdomains"] = subdomains
    return subdomains
