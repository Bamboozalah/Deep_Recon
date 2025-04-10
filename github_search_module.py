#!/usr/bin/env python3
import requests
import logging
import sys
import os
import time
import json
import re


def init_logging():
    logging.basicConfig(
        filename='github_search_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("GitHub Search Module started.")


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
            logging.error(f"Error reading targets from {input_arg}: {e}")
            print(f"Error reading targets from {input_arg}: {e}")
    else:
        targets.append(input_arg)
    return targets


def construct_query(target, keyword):
    return f'"{target}" {keyword}'


def search_github_code(query, token):
    headers = {"Authorization": f"token {token}"}
    params = {"q": query, "per_page": 100}
    url = "https://api.github.com/search/code"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as he:
        logging.error(f"HTTP error during GitHub search for query '{query}': {he}")
    except Exception as e:
        logging.error(f"GitHub search error for query '{query}': {e}")
    return None


def run_github_search(input_arg, config):
    init_logging()
    if 'github_api_key' not in config or not config['github_api_key']:
        print("GitHub API key not configured. Please set it via the configuration module.")
        return []

    token = config['github_api_key']
    targets = load_targets(input_arg)
    keyword_bank = [
        # Common credential and secrets
        "password", "secret", "apikey", "credential", "token", "database", "auth",
        "key", "config", "ssh", "ftp", "username", "connectionstring", "sql",
        "db_password", "jwt", "auth_token", "encryption_key", "private_key",
        "client_secret", ".env", "vault", "azure_key", "gcp_key", "slack_token",
        "webhook", "jira_token", "oauth", "api_key", "access_token",

        # Grid and OT-specific terms
        "scada_password", "plc_config", "rtu_token", "hmi_password", "modbus_key",
        "dnp3_key", "ics_credentials", "ot_admin", "siemens_password", "abb_key",
        "rockwell_token", "firmware_password", "switch_config", "relay_settings",
        "outage_plan", "nerc_cip", "crown_jewel", "gridops", "transmission_key",
        "protection_config", "energy_management_system", "control_room"
    ]
    findings = []

    for target in targets:
        print(f"\n[GitHub Search] Processing target: {target}")
        for keyword in keyword_bank:
            query = construct_query(target, keyword)
            print(f"Searching for: {query}")
            result = search_github_code(query, token)
            if not result:
                continue
            total_count = result.get("total_count", 0)
            if total_count > 0:
                print(f"Found {total_count} results for query '{query}'.")
                findings.append({
                    "target": target,
                    "keyword": keyword,
                    "query": query,
                    "total_count": total_count,
                    "items": result.get("items", [])
                })
            else:
                print(f"No results for query '{query}'.")
            time.sleep(2)

    print("\nGitHub search complete.")
    if findings:
        try:
            with open("github_findings.json", "w") as outfile:
                json.dump(findings, outfile, indent=2)
            print("Results saved to github_findings.json")
        except Exception as e:
            logging.error(f"Error saving GitHub findings: {e}")
    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 github_search_module.py <target_or_targets_file> <config_file>")
        print("Example: python3 github_search_module.py subdomains.txt deep_recon_config.json")
        sys.exit(1)

    input_arg = sys.argv[1]
    config_file = sys.argv[2]

    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except Exception as e:
        print("Error loading configuration:", e)
        sys.exit(1)

    findings = run_github_search(input_arg, config)

    print("\n===== GitHub Search Summary =====")
    for f in findings:
        print(f"Target: {f['target']} | Keyword: {f['keyword']} | Count: {f['total_count']}")


if __name__ == "__main__":
    main()
