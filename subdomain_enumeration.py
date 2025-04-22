import subprocess
import logging

def run_subdomain_enumeration(domain, shared_data, tool='subfinder'):
    logging.info(f"Starting subdomain enumeration on: {domain} using {tool}")
    
    if tool.lower() == 'subfinder':
        cmd = ['subfinder', '-d', domain, '-silent']
    elif tool.lower() == 'assetfinder':
        cmd = ['assetfinder', '--subs-only', domain]
    else:
        logging.warning(f"Unknown tool {tool}, defaulting to subfinder.")
        cmd = ['subfinder', '-d', domain, '-silent']

    timeout = shared_data.get("enum_timeout", 120)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            subdomains = list(set(result.stdout.strip().split('\n')))
            logging.info(f"Found {len(subdomains)} subdomains for {domain}")
            return subdomains
        else:
            logging.warning(f"{tool} failed for {domain}, attempting fallback.")
    except Exception as e:
        logging.warning(f"{tool} error: {e}, attempting fallback.")

    # Fallback to assetfinder (only if it wasn't already used)
    if tool.lower() != 'assetfinder':
        fallback_cmd = ['assetfinder', '--subs-only', domain]
        try:
            fallback_result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=60)
            if fallback_result.returncode == 0:
                subdomains = list(set(fallback_result.stdout.strip().split('\n')))
                logging.info(f"Assetfinder found {len(subdomains)} subdomains for {domain}")
                return subdomains
            else:
                logging.error(f"Assetfinder also failed for {domain}: {fallback_result.stderr}")
        except Exception as e:
            logging.error(f"Assetfinder exception for {domain}: {e}")
    
    return []  # Fallback also failed

def run(shared_data):
    logging.info("Running Subdomain Enumeration Module")
    root_domain = shared_data.get("root_domain")
    if not root_domain:
        logging.error("No root domain provided in shared_data['root_domain']")
        return []

    subdomains = run_subdomain_enumeration(root_domain, shared_data)
    shared_data["subdomains"] = subdomains
    return subdomains
