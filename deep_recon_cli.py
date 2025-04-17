
#!/usr/bin/env python3
import os
import sys
import logging
from rich.console import Console
from rich.panel import Panel
from controller import register_module, run_all_modules
from reporting_module import generate_reports

# Imports for recon modules
from subdomain_enumeration import run as run_subdomains
from wayback_js_module import run as run_wayback
from cert_data_module import run as run_cert
from github_search_module import run as run_github
from shodan_query_module import run as run_shodan
from screenshot_capture_module import run as run_screens
from error_page_extraction_module import run as run_error_pages
from path_fuzzing_module import run as run_paths
from cloud_detection_module import run as run_cloud
from supply_chain_module import run as run_supply_chain
from bucket_audit_module import run as run_buckets
from ics_exposure_module import run as run_ics

# ----------------------------
# Banner Display
# ----------------------------
def display_banner():
    neon_purple = "\033[38;2;238;130;238m"
    reset = "\033[0m"
    banner = f"""
{neon_purple}
██████╗ ███████╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔═══██╗████╗  ██║
██║  ██║█████╗  █████╗  ██████╔╝    ██║  ██║█████╗  ██║  ███╗██████╔╝██║   ██║██╔██╗ ██║
██║  ██║██╔══╝  ██╔══╝  ██╔═══╝     ██║  ██║██╔══╝  ██║   ██║██╔═══╝ ██║   ██║██║╚██╗██║
██████╔╝███████╗███████╗██║         ██████╔╝███████╗╚██████╔╝██║     ╚██████╔╝██║ ╚████║
╚═════╝ ╚══════╝╚══════╝╚═╝         ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═══╝
{reset}
"""
    print(banner)

# ----------------------------
# Main Program
# ----------------------------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    display_banner()

    console = Console()
    console.print(Panel.fit("[bold cyan]Initializing Deep Recon Grid Edition..."))

    # Set this before calling run_all_modules
    shared_data = {"root_domain": input("Enter target root domain (e.g., example.com): ").strip()}

    # Register modules
    register_module(run_subdomains, "Subdomain Enumeration")
    register_module(run_cert, "Certificate Analysis")
    register_module(run_shodan, "Shodan Scan")
    register_module(run_cloud, "Cloud Fingerprint")
    register_module(run_github, "GitHub Leakage")
    register_module(run_wayback, "Wayback JS Discovery")
    register_module(run_paths, "Path Fuzzing")
    register_module(run_error_pages, "Error Page Extraction")
    register_module(run_screens, "Screenshot Capture")
    register_module(run_supply_chain, "Supply Chain Analysis")
    register_module(run_buckets, "Cloud Bucket Audit")
    register_module(run_ics, "ICS Exposure Scan")

    # Run all modules
    results = run_all_modules()

    # Merge shared_data results
    results.update(shared_data)

    # Generate reports
    generate_reports(results)

    console.print(Panel.fit("[bold green]Recon complete. Reports saved to output/"))

if __name__ == "__main__":
    main()
