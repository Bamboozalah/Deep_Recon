#!/usr/bin/env python3
import requests
import logging
import re
import sys
import os
import json
from urllib.parse import urlparse


def init_logging():
    logging.basicConfig(
        filename='cloud_detection_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Cloud Detection Module started.")


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


def detect_cloud_info(response):
    detections = []
    server = response.headers.get("Server", "").lower()
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
    if "s3.amazonaws.com" in content:
        detections.append("Amazon S3")

    return list(set(detections))


def run_cloud_detection(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_detections = {}
    for target in targets:
        print(f"\n[Cloud Detection] Processing target: {target}")
        try:
            if not target.startswith("http"):
                target = f"http://{target}"
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


def export_results(results, filename="cloud_detections.json"):
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to {filename}")
    except Exception as e:
        logging.error(f"Error writing results to file: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cloud_detection_module.py <target_or_targets_file>")
        sys.exit(1)
    input_arg = sys.argv[1]
    detections = run_cloud_detection(input_arg)
    print("\n=== Cloud Detection Summary ===")
    for t, d in detections.items():
        print(f"{t}: {d}")
    export_results(detections)


if __name__ == "__main__":
    main()
