#!/usr/bin/env python3
import requests
import logging
import sys
import os
import time

def init_logging():
    logging.basicConfig(
        filename='path_fuzzing_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Path Fuzzing Module started.")

def load_targets(input_arg):
    """
    If input_arg ends with .txt and exists, load targets line-by-line.
    Otherwise, return a list containing the input_arg.
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

def load_wordlist():
    """
    Returns a built-in list of common paths to fuzz.
    Alternatively, a file can be used for a larger wordlist.
    """
    return [
        "/admin", "/login", "/dashboard", "/config", "/api", "/backup", "/.git", "/.env", "/test", "/dev", "/secret", "/data"
    ]

def fuzz_target(target, wordlist):
    """
    For a given target URL, appends each path from the wordlist.
    Sends an HTTP GET request and records endpoints that do not return 404.
    Returns a list of discovered paths.
    """
    discovered = []
    for path in wordlist:
        # Ensure proper URL formation
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 404:
                discovered.append({
                    "path": path,
                    "status_code": response.status_code
                })
                print(f"Found {url} (Status Code: {response.status_code})")
            else:
                print(f"{url} returned 404")
        except Exception as e:
            logging.error(f"Error fuzzing {url}: {e}")
        time.sleep(0.5)  # Delay to prevent overwhelming the target
    return discovered

def run_path_fuzzing(input_arg):
    """
    Loads targets (from a file or single input), loads a wordlist, and fuzzes each target.
    Prints discovered paths and returns a dictionary mapping targets to found paths.
    """
    init_logging()
    targets = load_targets(input_arg)
    wordlist = load_wordlist()
    all_results = {}
    for target in targets:
        print(f"\n[Path Fuzzing] Processing target: {target}")
        results = fuzz_target(target, wordlist)
        all_results[target] = results
    print("\nPath fuzzing complete.")
    return all_results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 path_fuzzing_module.py <target_or_targets_file>")
        print("Example: python3 path_fuzzing_module.py subdomains.txt")
        sys.exit(1)
    input_arg = sys.argv[1]
    results = run_path_fuzzing(input_arg)
    print("\n===== Path Fuzzing Summary =====")
    for target, paths in results.items():
        print(f"{target}:")
        for entry in paths:
            print(f"  {entry['path']} - {entry['status_code']}")

if __name__ == "__main__":
    main()
