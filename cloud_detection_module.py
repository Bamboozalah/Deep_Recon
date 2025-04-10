#!/usr/bin/env python3
import requests
import logging
import re
import sys
import os

def init_logging():
    logging.basicConfig(
        filename='cloud_detection_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Cloud Detection Module started.")

def load_targets(input_arg):
    """
    Reads targets from a file if input_arg ends with '.txt' and the file exists;
    otherwise, returns a list containing the input_arg.
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
            logging.error(f"Error reading {input_arg}: {e}")
            print(f"Error reading {input_arg}: {e}")
    else:
        targets.append(input_arg)
    return targets

def detect_cloud_info(response):
    """
    Detects cloud provider or tech stack information from response headers and content.
    Returns a list of detection strings.
    """
    detections = []
    server = response.headers.get("Server", "").lower()
    # Check Server header for common patterns:
    if "cloudflare" in server:
        detections.append("Cloudflare")
    if "amazon" in server or "aws" in server:
        detections.append("AWS")
    if "microsoft" in server or "iis" in server:
        detections.append("Microsoft/IIS (Azure?)")
    if "nginx" in server:
        detections.append("nginx")
    if "apache" in server:
        detections.append("Apache")
    # Check content for additional hints:
    content = response.text.lower()
    if "google cloud" in content or "gcp" in content:
        detections.append("Google Cloud")
    if "azure" in content:
        detections.append("Azure")
    if "wordpress" in content or "wp-content" in content:
        detections.append("WordPress")
    if "drupal" in content:
        detections.append("Drupal")
    if "joomla" in content:
        detections.append("Joomla")
    return list(set(detections))

def run_cloud_detection(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_detections = {}
    for target in targets:
        print(f"\n[Cloud Detection] Processing target: {target}")
        try:
            response = requests.get(target, timeout=15)
            detections = detect_cloud_info(response)
            if detections:
                print(f"Detected: {', '.join(detections)}")
            else:
                print("No cloud or tech stack information detected.")
            all_detections[target] = detections
        except Exception as e:
            logging.error(f"Error processing {target}: {e}")
            print(f"Error processing {target}: {e}")
    return all_detections

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cloud_detection_module.py <target_or_targets_file>")
        sys.exit(1)
    input_arg = sys.argv[1]
    detections = run_cloud_detection(input_arg)
    print("\n=== Cloud Detection Summary ===")
    for t, d in detections.items():
        print(f"{t}: {d}")

if __name__ == "__main__":
    main()
