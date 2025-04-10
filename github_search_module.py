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
    """
    If input_arg ends with ".txt" and exists, loads targets line-by-line.
    Otherwise, returns a list containing input_arg.
    """
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
    """
    Constructs a GitHub code search query using the target (domain or subdomain)
    and a keyword, e.g. 'target password' or 'target secret'.
    """
    # Using double quotes around the target to force an exact match.
    query = f'"{target}" {keyword}'
    return query

def search_github_code(query, token):
    """
    Uses the GitHub API to search code with the given query.
    Returns the JSON search results.
    """
    headers = {"Authorization": f"token {token}"}
    params = {"q": query}
    url = "https://api.github.com/search/code"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"GitHub search error for query '{query}': {e}")
        return None

def run_github_search(input_arg, config):
    """
    Loads targets (a single target or a file of targets), iterates over a keyword bank,
    constructs queries using each target and keyword, and performs GitHub code searches.
    Prints a summary for each query.
    Returns a list of findings for integration with the reporting module.
    """
    init_logging()
    if 'github_api_key' not in config or not config['github_api_key']:
        print("GitHub API key not configured. Please set it via the configuration module.")
        return []

    token = config['github_api_key']
    targets = load_targets(input_arg)

    # Define a keyword bank for secret and vulnerability detection.
    keyword_bank = [
        "password", "secret", "apikey", "credential", "token", "database", "auth",
        "key", "config", "ssh", "aws_access_key_id", "aws_secret_access_key"
    ]
    findings = []
    for target in targets:
        print(f"\n[GitHub Search] Processing target: {target}")
        for keyword in keyword_bank:
            query = construct_query(target, keyword)
            print(f"Searching for: {query}")
            result = search_github_code(query, token)
            if result is None:
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
            # Respect GitHub rate limits
            time.sleep(2)
    print("\nGitHub search complete.")
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
        print(f)

if __name__ == "__main__":
    main()
