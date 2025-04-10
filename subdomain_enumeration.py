#!/usr/bin/env python3
import subprocess
import logging
import sys

def init_logging():
    logging.basicConfig(
        filename='subdomain_enumeration.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Subdomain Enumeration Script Started.")

def run_subdomain_enumeration(target, tool='subfinder'):
    """
    Runs subdomain enumeration on the given target using either subfinder or assetfinder.
    The results are saved to 'subdomains.txt'.
    """
    print(f"Starting subdomain enumeration on: {target} using {tool}...")
    try:
        if tool.lower() == 'subfinder':
            cmd = ['subfinder', '-d', target, '-o', 'subdomains.txt']
        elif tool.lower() == 'assetfinder':
            cmd = ['assetfinder', '--subs-only', target]
        else:
            print("Invalid tool specified. Use 'subfinder' or 'assetfinder'.")
            return False

        subprocess.run(cmd, check=True)
        print("Subdomain enumeration completed. Results saved to subdomains.txt")
        logging.info("Subdomain enumeration completed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print("Error during subdomain enumeration.")
        logging.error(f"Subdomain enumeration failed: {e}")
        return False

def main():
    init_logging()
    if len(sys.argv) < 3:
        print("Usage: python3 subdomain_enumeration.py <target> <tool>")
        print("Example: python3 subdomain_enumeration.py example.com subfinder")
        sys.exit(1)
    target = sys.argv[1]
    tool = sys.argv[2]
    run_subdomain_enumeration(target, tool)

if __name__ == "__main__":
    main()
