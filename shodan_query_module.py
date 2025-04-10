#!/usr/bin/env python3
import shodan
import logging
import ipaddress
import socket
import sys
import time
import json
import os

def init_logging():
    logging.basicConfig(
        filename='shodan_query_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Shodan Query Module started.")

def load_targets(input_arg):
    """
    If the input argument ends with ".txt" and exists, assume it's a file containing targets
    (e.g., subdomains.txt) and return a list. Otherwise, treat the input argument as a single target.
    """
    targets = []
    if input_arg.endswith(".txt") and os.path.isfile(input_arg):
        try:
            with open(input_arg, "r") as f:
                for line in f:
                    target = line.strip()
                    if target:
                        targets.append(target)
            print(f"Loaded {len(targets)} targets from {input_arg}")
        except Exception as e:
            logging.error(f"Error reading {input_arg}: {e}")
            print(f"Error reading {input_arg}: {e}")
    else:
        targets.append(input_arg)
    return targets

def resolve_domain(domain):
    """Attempts to resolve a domain name to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        logging.error(f"Error resolving domain {domain}: {e}")
        return None

def query_shodan(api, target_ip):
    """Queries Shodan for the given IP address and returns host information."""
    try:
        result = api.host(target_ip)
        return result
    except Exception as e:
        logging.error(f"Error querying Shodan for {target_ip}: {e}")
        return None

def process_target(api, target):
    """Processes a single target: resolves to IP (if necessary), queries Shodan, and prints results."""
    print(f"\n[Shodan Query] Processing target: {target}")
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    target_ip = None
    if is_ip:
        target_ip = target
    else:
        target_ip = resolve_domain(target)
        if target_ip:
            print(f"Resolved {target} to IP: {target_ip}")
        else:
            print(f"Could not resolve {target}. Skipping target.")
            return None

    host_info = query_shodan(api, target_ip)
    if host_info is None:
        print(f"No Shodan data available for {target}")
        return None

    # Print Shodan results
    print(f"\n[Shodan Results for {target}]")
    print("IP:", host_info.get("ip_str", "N/A"))
    print("Organization:", host_info.get("org", "N/A"))
    print("Operating System:", host_info.get("os", "N/A"))
    ports = host_info.get("ports", [])
    print("Open Ports:", ports if ports else "None")
    vulns = host_info.get("vulns", [])
    print("Vulnerabilities:", vulns if vulns else "None")
    location = host_info.get("location", {})
    if location:
        print("Location:", location.get("city", "N/A"), location.get("country_name", "N/A"))
    return host_info

def run_shodan_query(input_arg, config):
    """
    Loads targets from a file or single input, resolves domains to IPs, queries Shodan for each,
    prints the results, and returns a list of dictionaries containing the Shodan data.
    """
    init_logging()
    if 'shodan_api_key' not in config or not config['shodan_api_key']:
        print("Shodan API key not configured. Please set it via the configuration module.")
        return []

    api_key = config['shodan_api_key']
    api = shodan.Shodan(api_key)
    results = []
    targets = load_targets(input_arg)

    for target in targets:
        host_info = process_target(api, target)
        if host_info is not None:
            results.append({
                "target": target,
                "ip": host_info.get("ip_str", "N/A"),
                "org": host_info.get("org", "N/A"),
                "os": host_info.get("os", "N/A"),
                "open_ports": host_info.get("ports", []),
                "vulnerabilities": host_info.get("vulns", []),
                "location": host_info.get("location", {})
            })
        time.sleep(1)  # To reduce rate-limit pressure
    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 shodan_query_module.py <target_or_targets_file> <config_file>")
        print("Example: python3 shodan_query_module.py subdomains.txt deep_recon_config.json")
        sys.exit(1)
    input_arg = sys.argv[1]
    config_file = sys.argv[2]
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except Exception as e:
        print("Error loading configuration:", e)
        sys.exit(1)
    results = run_shodan_query(input_arg, config)
    print("\n===== Shodan Query Summary =====")
    for res in results:
        print(res)

if __name__ == "__main__":
    main()
