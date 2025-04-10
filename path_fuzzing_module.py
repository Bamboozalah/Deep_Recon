#!/usr/bin/env python3
import requests
import logging
import sys
import os
import time
import json


def init_logging():
    logging.basicConfig(
        filename='path_fuzzing_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Path Fuzzing Module started.")


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


def load_wordlist():
    return [
        "/admin", "/login", "/dashboard", "/config", "/api", "/backup",
        "/.git", "/.env", "/test", "/dev", "/secret", "/data",
        "/credentials", "/auth", "/debug", "/hidden", "/staging",
        "/monitoring", "/grafana", "/kibana", "/logs", "/vault",
        "/internal", "/config.json", "/config.yml"
    ]


def fuzz_target(target, wordlist):
    discovered = []
    for path in wordlist:
        url = target.rstrip("/") + path
        try:
            response = requests.get(url, timeout=10)
            if response.status_code not in [404, 400]:
                discovered.append({
                    "path": path,
                    "status_code": response.status_code
                })
                print(f"[+] Found {url} (Status Code: {response.status_code})")
            else:
                print(f"[-] {url} returned {response.status_code}")
        except Exception as e:
            logging.error(f"Error fuzzing {url}: {e}")
        time.sleep(0.25)
    return discovered


def run_path_fuzzing(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    wordlist = load_wordlist()
    all_results = {}
    for target in targets:
        print(f"\n[Path Fuzzing] Processing target: {target}")
        results = fuzz_target(target, wordlist)
        all_results[target] = results
    try:
        with open("path_fuzzing_results.json", "w") as outfile:
            json.dump(all_results, outfile, indent=2)
        print("\nResults saved to path_fuzzing_results.json")
    except Exception as e:
        logging.error(f"Error saving results: {e}")
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
