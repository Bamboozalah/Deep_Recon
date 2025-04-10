#!/usr/bin/env python3
import requests
import logging
import json
import sys
import time
import os
import socket
import re


def init_logging():
    logging.basicConfig(
        filename='cert_data_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Certificate Data Module started.")


def load_targets(input_arg):
    targets = []
    if input_arg.endswith(".txt") and os.path.isfile(input_arg):
        try:
            with open(input_arg, "r") as f:
                for line in f:
                    t = line.strip()
                    if t:
                        targets.append(t)
            print(f"Loaded {len(targets)} targets from {input_arg}.")
        except Exception as e:
            logging.error(f"Error reading {input_arg}: {e}")
            print(f"Error reading {input_arg}: {e}")
    else:
        targets.append(input_arg)
    return targets


def fetch_cert_data_for_target(target):
    url = f"https://crt.sh/?q={target}&output=json"
    logging.info(f"Fetching certificate data for target {target} using URL: {url}")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON for target {target}: {e}")
            data = []
        return data
    except Exception as e:
        logging.error(f"Error fetching certificate data for {target}: {e}")
        print(f"Error fetching certificate data for {target}: {e}")
        return []


def extract_cert_info(cert_record):
    cert_info = {
        "common_name": cert_record.get("common_name", "N/A"),
        "issuer_name": cert_record.get("issuer_name", "N/A"),
        "entry_timestamp": cert_record.get("entry_timestamp", "N/A")
    }
    names_raw = cert_record.get("name_value", "")
    names = list(set(re.split(r'\s*\n\s*', names_raw.strip())))
    cert_info["names"] = names
    return cert_info


def resolve_names_to_ips(names):
    resolved = {}
    for name in names:
        try:
            try:
                socket.inet_aton(name)
                resolved[name] = name
                continue
            except socket.error:
                pass
            ip = socket.gethostbyname(name)
            resolved[name] = ip
        except Exception as e:
            logging.error(f"Error resolving name {name}: {e}")
            resolved[name] = None
    return resolved


def run_cert_data(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_cert_results = []
    for target in targets:
        print(f"\n[Certificate Data] Processing target: {target}")
        cert_records = fetch_cert_data_for_target(target)
        if not cert_records:
            print(f"No certificate data returned for {target}.")
            continue
        for record in cert_records:
            cert_info = extract_cert_info(record)
            resolved_ips = resolve_names_to_ips(cert_info.get("names", []))
            cert_info["resolved_ips"] = resolved_ips
            all_cert_results.append({
                "target": target,
                "certificate": cert_info
            })
            print("\nCertificate Record:")
            print(f"  Common Name: {cert_info.get('common_name')}")
            print(f"  Issuer: {cert_info.get('issuer_name')}")
            print(f"  Entry Timestamp: {cert_info.get('entry_timestamp')}")
            print("  Domains and Resolved IPs:")
            for name, ip in resolved_ips.items():
                ip_display = ip if ip else "Resolution failed"
                print(f"    {name} -> {ip_display}")
        print(f"\nCompleted processing certificate data for target: {target}")
        time.sleep(2)
    return all_cert_results


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cert_data_module.py <target_or_targets_file>")
        print("Example 1: python3 cert_data_module.py example.com")
        print("Example 2: python3 cert_data_module.py subdomains.txt")
        sys.exit(1)
    input_arg = sys.argv[1]
    results = run_cert_data(input_arg)
    print("\n===== Certificate Data Summary =====")
    for result in results:
        target = result.get("target")
        cert = result.get("certificate")
        print(f"\nTarget: {target}")
        print(f"  Common Name: {cert.get('common_name')}")
        print(f"  Issuer: {cert.get('issuer_name')}")
        print(f"  Entry: {cert.get('entry_timestamp')}")
        print("  Domains/IPs:")
        for name, ip in cert.get("resolved_ips", {}).items():
            ip_display = ip if ip else "Resolution failed"
            print(f"    {name} -> {ip_display}")


if __name__ == "__main__":
    main()
