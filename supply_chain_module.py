#!/usr/bin/env python3
import requests
import logging
import re
import sys
import os
import time

def init_logging():
    logging.basicConfig(
        filename='supply_chain_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Supply Chain Detection Module started.")

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

def scan_for_supply_chain(content):
    """
    Scans HTML content for keywords suggesting exposed supply chain or industrial control devices.
    Returns a list of detection strings.
    """
    findings = []
    keywords = {
        "scada": "SCADA system indicator",
        "plc": "PLC interface indicator",
        "rtu": "RTU device indicator",
        "hmi": "HMI (Human Machine Interface) detected",
        "dcs": "DCS (Distributed Control System) detected",
        "ics": "ICS (Industrial Control System) detected",
        "ot": "Operational Technology (OT) interface detected",
        "default password": "Potential default credential exposure",
        "exposed device": "Exposed device interface found"
    }
    content_lower = content.lower()
    for key, message in keywords.items():
        if key in content_lower:
            findings.append(message)
    return list(set(findings))

def run_supply_chain_detection(input_arg):
    init_logging()
    targets = load_targets(input_arg)
    all_findings = {}
    for target in targets:
        print(f"\n[Supply Chain Detection] Processing target: {target}")
        try:
            response = requests.get(target, timeout=15)
            findings = scan_for_supply_chain(response.text)
            if findings:
                print(f"Findings: {', '.join(findings)}")
            else:
                print("No supply chain or exposed device indicators detected.")
            all_findings[target] = findings
        except Exception as e:
            logging.error(f"Error processing {target}: {e}")
            print(f"Error processing {target}: {e}")
        time.sleep(1)
    return all_findings

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 supply_chain_module.py <target_or_targets_file>")
        sys.exit(1)
    input_arg = sys.argv[1]
    findings = run_supply_chain_detection(input_arg)
    print("\n=== Supply Chain Detection Summary ===")
    for t, f in findings.items():
        print(f"{t}: {f}")

if __name__ == "__main__":
    main()
