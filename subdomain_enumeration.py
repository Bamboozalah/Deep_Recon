
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

        timeout = shared_data.get("enum_timeout", 120)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode == 0:
                subdomains = list(set(result.stdout.strip().split('\n')))
                logging.info(f"Found {len(subdomains)} subdomains for {domain}")
                return subdomains
            else:
                logging.warning(f"Subfinder failed for {domain}, trying assetfinder.")
        except Exception as e:
            logging.warning(f"Subfinder failed: {e}, trying assetfinder.")
        # Try assetfinder
        fallback_cmd = ['assetfinder', '--subs-only', domain]
        try:
            fallback_result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=60)
            if fallback_result.returncode == 0:
                subdomains = list(set(fallback_result.stdout.strip().split('\n')))
                logging.info(f"Assetfinder found {len(subdomains)} subdomains for {domain}")
                return subdomains
            else:
                logging.error(f"Assetfinder also failed for {domain}: {fallback_result.stderr}")
                return []
        except Exception as e:
            logging.error(f"Assetfinder exception for {domain}: {e}")
            return []
