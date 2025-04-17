
#!/usr/bin/env python3
import os
import sys
import json
import logging
from rich.console import Console
from rich.progress import Progress
from controller import register_module, run_all_modules
from reporting_module import generate_reports

# Load upgraded modules
from subdomain_enumeration import run as run_subdomains
from wayback_js_module import run as run_wayback
from cert_data_module import run as run_cert
from github_search_module import run as run_github
from shodan_query_module import run as run_shodan
from screenshot_capture_module import run as run_screens
from error_page_extraction_module import run as run_errors
from path_fuzzing_module import run as run_paths
from cloud_detection_module import run as run_cloud
from supply_chain_module import run as run_supply
from bucket_audit_module import run as run_buckets
from ics_exposure_module import run as run_ics

# ----------------------------
# Display banner
# ----------------------------
def display_banner():
    neon = "\033[38;2;238;130;238m"
    reset = "\033[0m"
    banner = f"""{neon}
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
██╗██████╗ ███████╗███████╗██████╗ ██████╗  ██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗███╗   ██╗
██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
██║██████╔╝█████╗  █████╗  ██║  ██║██████╔╝██║   ██║█████╗  ██║   ██║██████╔╝██║   ██║█████╗  ██╔██╗ ██║
██║██╔═══╝ ██╔══╝  ██╔══╝  ██║  ██║██╔═══╝ ██║   ██║██╔══╝  ██║   ██║██╔═══╝ ██║   ██║██╔══╝  ██║╚██╗██║
██║██║     ███████╗███████╗██████╔╝██║     ╚██████╔╝███████╗╚██████╔╝██║     ╚██████╔╝███████╗██║ ╚████║
╚═╝╚═╝     ╚══════╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═══╝
{reset}"""
    print(banner)

# ----------------------------
# Main menu interface
# ----------------------------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    display_banner()

    console = Console()
    shared_data = {}

    target = console.input("[bold cyan]Enter the root domain (e.g. example.com): [/bold cyan]").strip()
    shared_data["root_domain"] = target

    modules = [
        ("Subdomain Enumeration", run_subdomains),
        ("Certificate Analysis", run_cert),
        ("Shodan Scan", run_shodan),
        ("Cloud Fingerprint", run_cloud),
        ("GitHub Leakage", run_github),
        ("Wayback JS Discovery", run_wayback),
        ("Path Fuzzing", run_paths),
        ("Error Page Extraction", run_errors),
        ("Screenshot Capture", run_screens),
        ("Supply Chain Analysis", run_supply),
        ("Cloud Bucket Audit", run_buckets),
        ("ICS Exposure Scan", run_ics)
    ]

    console.print("\n[bold magenta]Select modules to run:[/bold magenta]")
    for i, (name, _) in enumerate(modules, 1):
        console.print(f"[bold white]{i}[/bold white]: {name}")
    console.print("[bold white]0[/bold white]: Run all modules")

    choice = console.input("\n[bold yellow]Enter choice (comma-separated or 0): [/bold yellow]")
    selected_indices = [int(c.strip()) for c in choice.split(",") if c.strip().isdigit()]

    if 0 in selected_indices:
        for _, func in modules:
            register_module(func, func.__name__)
    else:
        for i in selected_indices:
            if 1 <= i <= len(modules):
                register_module(modules[i - 1][1], modules[i - 1][0])

    console.print("\n[bold green]Running selected modules...[/bold green]")
    results = run_all_modules()
    results.update(shared_data)

    generate_reports(results)
    console.print("[bold green]Done. Reports saved to [underline]output/[/underline][/bold green]")

if __name__ == "__main__":
    main()
