from utils import get_api_key

#!/usr/bin/env python3
import os
import sys
import logging
import json
from rich.console import Console
from rich.prompt import Prompt
from reporting_module import generate_reports

# Load recon modules (ensure all accept shared_data and return results into it)
from subdomain_enumeration import run as run_subdomains
from cert_data_module import run as run_cert
from grid_ip_harvester_module import run as run_grid_harvest
from github_search_module import run as run_github
from shodan_query_module import run as run_shodan
from screenshot_capture_module import run as run_screens
from error_page_extraction_module import run as run_errors
from path_fuzzing_module import run as run_paths
from cloud_detection_module import run as run_cloud
from supply_chain_module import run as run_supply
from bucket_audit_module import run as run_buckets
from ics_exposure_module import run as run_ics
from wayback_js_module import run as run_wayback

console = Console()

def print_banner():
    banner = """
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▒▒▒▒▓▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▓░░░░░░░░░░░░░░░░░░▒▒▒░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▒▒▒▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░▒▒░░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░░▒▓▓▒▓▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░▒░░░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▓█████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒░░▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓███▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░░▒▓▒▒▓▓▓█▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒░▒░░░░░░░░░░░░░░░░░░▒▒▒░▒▒▒▒▒▓▓▓▓▒▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░▒▓▒▓▓▓▓▓▓▓▓▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░▒░▒░▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓████▓▓██▓▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ░░▒░░▒█▓▓█▓▓▓▓▓▓▓▓▓▓▓▒░▒▒▒▒▒▒▒▒▒▒▓▒▓▓▒▒▒▒▒▒▒▒▒▒▓░░░░░░░░░░░░░░░░░░░░░░▒░░░░▒▒▒░▒▒▓▓▒▒▓▓▒▒▒▒▓▓▓▓▓▓▓███▓▓▓▓▓█▓██▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░░▓▓██▓▓▓▓▓▓▒▒░░▒▒▓▓▓▒░░░░░▒▒▒▒▒▓▓▒▒▒▒▒▒▒░▒▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▓▓▒▒▒▒▒▓▓▓▓▓▓▓▓████▓▓██▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓▓▓█▓▓▒▒▒▒▒▒░░░░░░░░░░░░░░░▒▒▒▒▓▓▒▒▒▒░░▒▓░░░░░░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░▒▒▒▒▒▒▓▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓████▓▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓▓▓█▓█▓▓▒▒▒▒▒▒▒▒░▒▒▒▒▒░░░░░░░░▒▒▓▓▓▓▒░░░▒▓▒░░░░░░░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░▒▒░▒▒▓▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓████▓▓▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▓▓▓▓█▓▓▒▒▒▒▒▒▒▒░▓▓▓▒▒▒▒▒░░░░░▒▒▒▓▓▓█▓░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓███▓▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▓▓▓▓▓▒▒▒▒▒▒▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░▒▒▓▓▒▒▒▒▒▒░░░░░░░▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▓▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓▒▒▒▒▒▒░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▓▓▓▓▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▓▓▓▓▓▓░▒▓▓▓▓▓▓▓▓▓▓▓█
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒░░░░░░░░░▒▒░░░░░░▒▓▒▒▒▓▓▓▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒░░▓▓▒▓▒░░▓▓▓▓▓▓▓▓▓▓▓░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░▒░▒▓▓▓▓▒▒▒▒▒▒░░░░░░░▒▒▒▓▓▓▒░░▒▒▒▒▒▒▓░░░░░░░ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒░░░▒▓▓░░░░▓▒▓▓▓▓▓▓▒░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▒▓▓▒▒▒▒▒▒░░░░░░░ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒░░░░░░░░░░▒▓▒▓▒▒▓░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▒▒▒▒▒▒▒▒░       ░░░░░░░░░░░░░░░░░░░░░▒▒▓████▓▒▒░░░░░░░░░░░░░▒▒▒░░░░    ░░▒▒▒▒▒░░░░░ 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░▒▒▒▒▓▓▓▒▒▒▓░░       ░░░░░░░░░░░░░░░░░▒▓████▓█▓▓▒▒▒▓██▓░░░░░░░░░░▒▒▒░░░░     ░░░▒░░░░░░░ 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▒▓▒░░       ░░░░░░░░░░░░░░▒▓█████████▓░▒▓█▓▒████▒░░░░░░░▒▒▒░░░░     ░░ ░░░░░░░░ 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▒▒▒▒▓▓▓▓▒░░░       ░░░░░░░░░░░░▓██████████████░░▒▒▒▓████▓░░░░░░░▒▒░░░                  
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▓▓▓▓▓░░░░  ░    ░░░░░░░░░░░▓█▓██████████████▒░▓███████▒░░░░░░▒░░░░░ ░               
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░░░▒▒▒▓▓▓▓▓▒▒▒▒▒▒▒▒░░░░▒▒▒▒▒▓▓▓▓▓▓░░░░░     ░░░░░░░░░░░░▓█████████████████▓▒▓███████▓░░░░░░░░░░░░                ░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▓▓▓▓▓▒▒▒▒▒▒░░░░░▒▒▒▓▓▓▓▓░░░░░░     ░░ ░░░░░░░░▓████████████████████████████▓▓▓▒▒▒░▒▒░░░░                 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░░░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▓▓▓▓░░░░░░░     ░░ ░░░░░░░▒████████████████████████▓▒▓████▓▓▓█▓▓▓▓▒░░                 
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒░▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░       ░ ░░░░░░░░░░▒████████████████████▓▓▓▓▒▒▒▒▒▓▓▓▒▓▒▓▓▓▓▒▓░               ░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▓▓▓▓▒▒▒▒▒▒░░▒▒▒▒▒▒▒▒▓▓▓████▓▓▓░░░░░░  ░░░  ░░░░ ░░░░░░░░▓████████████████▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▓▓▒▒▒░    ░     ░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓▓▓▓▓▒▒▒▒▒▒░░▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒░░░░░░░░     ░░░░ ░░░░░░░░███████████████▓▓▒▒▒▒▒▒▒▒▒▒░▒▒▒▓█▓▒▒▒▒▒▒░░░          ░ ░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓▓▓▓▓▓▓▒▒▒▒▒░░░░▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓░░░░░░░░░░░░ ░░░░  ░░░░░░░░▓████████████▓▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▓▒▒▒░░░░░▒░░░       ░░ ░░░░░▒▓
░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▓▓▓▓▓▓▓▓▓▒▒▒▒░░░░░░░░░░▒▒▒▒▓▓▓▓▓▓▒░░░ ░░░░░░░░░░ ░░░░░░░░▒▒░░▓████▓▓▓▓▒▒▒▒▒▒▒░░░▒▒▒▒▒░░▒▒▓▒▒▓▓▓░░░▒▒▒░░░     ░░░░░ ░░░░▓▓
░░░░░░░░░░░░░░░░░ ░░░░░░░▒▓▓▓▓▓▓▓█▓▓▒▒▒▒▒░░░░░░░░░░░░▒▒▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░▒▒░░▒██▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒░▒▒▒▒░░▓▓░░░▒▒▒░░░░    ░   ░░░░░▓▓▓
░░░░░░░░░░░░░░░░░░░░▒▓▓▓▓▓▓▓▓▓███▓█▓▒▒▒░░░░░░░░░░░░░░▒▒▒▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░▒░░░▓▓▓▓▓▓▓▒▒▒▒░▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▓▓▒▓▓▓▒░░▒▒▒▒░░░░░░░░░░░░░░░▒███
░░░░░░░░░░░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▒▒░░░░░░░░░░░░▒▒▒▓▓▒▓▓▓█▓▓░░░░░▒▒░░░░░░░░░░░░░░▒▒░░░▒▓▒▒▓▓▓▓▒▒▒▒▒▒▒░░░▒▒▒▒▒▒▒▒▒▒▒▓▒▒▓▓▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓███
░░░▒▓▓▓▓▓▓▓▓▓▓▓█▓█▓▓▓██▓▓▓▓▓▓██████▓▓▓▓▓▓▓▒▒░░░░░░░▒▒▒▒▒▒▒▓▓▓█▓▓▓▒░░░░░░░░░░░░░░░░░░░▒▒░░░▒▒░▒▓▓▓▓▓▒▒▒▒▒░░░░▒▒▒▒░▒▒▒░░▒▒▓▓▒▓▓░▒▒▒▓▓▓▓▓▓▒░▓▓▓▓▓▓▓▓████
▓▓▓▓▓▓▓▓▓████▓▓▓█▓▓▓▓▓█▓▓▓▓▓▓█████▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░░░░░░░░░▒▒░░░▒▒░░▒▒▓▓▓▓▒▒▒▒▒░░░░░▒▒▒▒▓▓▓▒▒▒▒▒▒▓▓▒▒▒▒▓▓▓███▒░▓▓▓▓▓▓▓▓████
▓▓▓█████████████████▓██▓▓▓▓▓▓████▓▓▓▓▒▓▓▓▓▓▓▓▓███▓▓██▓▓▓▓▓██▓▓██▓▓▓▒░░░░▒░░░░▒░░░░░░░▒▒░░░░▒▒▒▒▒▓▓▓▓▓▒▒▒▒▒░░░░▒▒▒▒░▒▒▒▒▓▓▓▒▓▓▒▒▒▒▒░░▒░▒▒▒▒░░░░░░▒▓▓▓▓
▓▓▓▓█▓▓█████████▓▓▓▓▓▓▓▓▓▓▓▓▓█████▓▓█▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█████▓▓▒▓███▓▓▓██▓▓▒░░░░░░░░░░░░▒▒▒░░░░▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒░░░▒░░▒▒▒▒▒▒▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓
▓▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█████▓▓▓▓░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▒▓████▓▓███▓██▓░░░░░░░░░░▒▒▒░░░░░▒▒▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒░▒▒▒▒▒▒▓▓▓▓▓▓▓▒░▒▒▒▓████▓▒▒▓▓███████▓▓▓
█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓█████████████████▓▓▓▓▓█████▓▓█████████████████████░░░░░░░▒▒▒░░░░░░░▒▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▒▒▒▒▓▒▓▓▓▓▒░▒▒▒▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓███▓▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▓███████████████████▓▓▓▓█████▓▓▓██████████████████████▓░░░░▒▒▒░░░░░░░░▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓███▒▒▒▒▒░░░▒▒▒▒▒▒▒▒▒░▒░▓▓▓
▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒░░░░░░█▓▓█▓▓▓███████████▓▓▓▓██████▓▓████████████████████████▓▒░▒▒▒░░░░░░░░▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▓▓▓███████████▓░▒███▓▓▓▓▓▓▓▓▓
██▓▓▓▓▓▓▓▓▓▓▒▒░░░░░░▒▒▒░▒▓░░▓███▓▓█████████████▓▓▓▓█████▓▓█████████████████████▓████▓▒░▒░░░░░░░▓█▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓██████████████████████████▓
██▓▓▓▓▒░░░░░░░░▒▓▒░░▒▒▒░░░░░█████████████████████▓▓▓▓███▓▓████████████████████████████▓▒░░░▒░░▒███▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓████████████████████████████
██▓▓▓▓▒░░▓░░░░░░░▒░░░▒▓▒░▒████▓███████████████████▓▓▓▓███▓▓█████████████████████████████░░░▒░▒████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓███████████████████████████
██▓▓▓▓▓░░▒▓░░░░▒▓▓▒░░▓▒▒░░▓███████████████████████▓▓▓████▓▓██████████████████████████████░░▒███████▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓██▓▓▓▓▓██████████████████████████
█▓▓▓▓▓▓▒░░▓░░░░░░░░░░░░▓▓▓▒░▒█████████████████████▓▓▓█████▓▓███████████████████████▓███▓██▓████████▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓███████████████████████████
█▓▓▓▓▓▓▓░░░░░▓▒▒▒▒▓▒░░░░▒░▒▓░▓█████████████████████▓▓▓████▓▓██████████████████████▓█████████████████▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓██████████████████████████████
█▓▓▓▓▓▓▓▓▒▒▒▓▒░░░░░▒░▒░▒▒░░░░▒█████████████████████▓▓▓▓████▓▓█████████████████████▓█████████████████████▓▓▓▓▓▓▓▓▓▓▓▓█████████████████████████████████
█▓▓▓▓▓▓▓▓░░▒░░░▓░░░░░▒░░▓▓░▒▒░▓████████████████████▓▓▓▓▓▓██▓▓▓█████████████████████▓█████████████████████████████████████████████████████████████████
██▓▓▓▓▓▓▓░░▓▓▓░░▒░░░░▒▒░░░░▒▓██████▓▓▓▓████████▓██▓▓▓▓▓▓████▓▓█████████████████████▓██▓▓▓▓▓████████████▓▓▒▒▓███████▓▓▒▓▓█████████████████████████████
██▓▓▓░░░ ░ ░░░░░░░▒▒▒░░░ ░░░░░▒██▒░░░    ░▓██░░░░░░░░░░▒▓▓██▓▓▓▓▓▓▓▓▓██░░░░ ░░░░░▒█▓██░░░░░░░░░▒████▓░░░░░░░░▒██▓▒░░░░░░░▒▓███▓░ ░░░██████▒░░░▓██████
██▓▓▓░░░░░░░░░░░░▓▓▓▓▒░ ░░░░░░▓██▒░░░░░░░░▓██░ ░░░▒░░░ ░░▓█▓▓▓▓▓▓▓▓▓▓▓█░░░░▒▒░░░░░▒▓██░░ ░░░░░░▓██▓░░ ░░░░░░░▒█▓░░░░░▒░░░░░▓██▓░░░░░░▓████▒░ ░▓██████
█▓▓▓▓░░░░▓▓▓▓▒░░░░▒▓█▒░░░▒██▓▓▓██▒░ ░▒▓▓█████░░░░▓█▓▓░░░░▓▓▓▓▓▓▓▓██▓▓██░░░░▓██▒░░░░███░  ░▒██████▓░░░░░▓████▓▓█▒░░░▒███▒░░░░██▓░░░░░░░▒███▒░ ░▓██████
▓▓▓▓▓░░░░▓▓▓▓▓▒░░ ░██▒░░░░░░░░▓██▒░  ░░░░░███░ ░░▒▓▓░░░░░▓▓▓▓▓█████▓███░░░░▒▓▒░░░░▒███░  ░░░░░░▓█▒░░ ░████████▓░░░░▓████░░ ░▓█▓░░░░░░░░░▓█▒░░░▓██████
▓▓▓▓▓░░░░▓▓▓▓▓▒░░░░██▒░░░░░░░░▓██▒░░░░░░░░███░ ░░░░░░░░░▓▓▓▓█████▓▓▓▓▓▓░░░░░  ░░░▓████░  ░░░░░░▓█▓░░░░████████▓░░░░▓████░░░░▓█▓░░ ▒█▓░░░░▒░░░░▓██████
▓▓▓▓▓░░░░▓▓▓▓▒░░░░▒██▒░ ░▒█▓▓▓▓▓▓▒░░░▒███████░  ░▒▒▒▒▒▓▓▓▓█▓▓█▓▓▓▓▓▓▓▓▓░░░░▒░ ░░▒▓████░  ░▒▓█████▓░░░░░██████▓█░░░░▓███▓░░ ░██▓░░ ▒██▓░ ░░░░ ░▓██████
▓▓▓▓▓░░░░▒▒░░░░░░▒███▒░ ░░▒▒▒▒▓█▓▒ ░░░▒▒▒▒▓██░ ░░▓███▓▓▓▓▓▓████▓▓▓▓▓▓▓▓░░░░▓▓░░░░░▓███░  ░░▒▒▒▒▓██▓░░░░░░▒▒░░▒█▓░░░░▒▒▒░  ░▓██▓░░ ▒████▒░░░░░░▓██████
▓▓▓▓▓░    ░░░░░▒▓▓███▒░░░ ░░░░▒▓▓▒░░░░░  ░▓██░░░░▓████▓▓▓▓▓███████▓▓▓▓▓░░░░▓██░ ░░░▓██░░░░░░░░░▒████▒░░░░░  ░▒██▓░░░░░░░░░▓███▓░░░▒█████▓░░░░░▓██████
▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▓▓▓▓▓▒▒▓▓▓▓▓███▓▓▓▓▓████▓▓▓█████████▓▓▓▓█▓▓▓▓▓███▒▒▓▓▓▓█▓▓▓▓▓▒▓▓▓▓██████▓▒▒▒▒▒▓▓████▓▒▒▒▒▒▓█████▓▓▓▓▓███████▓▓▓▓▓██████
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓▓██▓▓▓█▓▓▓▓▓███████████████▓▓▒░░░░░░░░░░░▒█████████▓▓███▓████████████████████████████████████████████████████████████████
"""
    console.print(banner, style="bold magenta")

def configure_api_keys():
    os.makedirs("config", exist_ok=True)
    key_path = "config/api_keys.env"
    console.print("\n[bold cyan]-- API Key Setup --[/bold cyan]")
    shodan_key = Prompt.ask("Enter your Shodan API Key", default=os.getenv("SHODAN_API_KEY", ""))
    github_key = Prompt.ask("Enter your GitHub Token", default=os.getenv("GITHUB_TOKEN", ""))
    with open(key_path, "w") as f:
        if shodan_key:
            f.write(f"SHODAN_API_KEY={shodan_key}\n")
        if github_key:
            f.write(f"GITHUB_TOKEN={github_key}\n")
    console.print("[green]API keys saved to config/api_keys.env[/green]\n")

def run_module(name, func, shared_data):
    console.print(f"[cyan]Starting {name}...[/cyan]")
    try:
        func(shared_data)
    except Exception as e:
        console.print(f"[red]Error in {name}: {e}[/red]")
    else:
        console.print(f"[green]{name} complete. Results saved to shared_data.[/green]")

def recon_menu(shared_data):
    fast_mode = Prompt.ask("Run all modules in fast mode by default?", choices=["y", "n"], default="y") == "y"
    shared_data["fast_mode"] = fast_mode
    shared_data["verbose_mode"] = not fast_mode
    if fast_mode:
        console.print("[green]Fast mode selected: Valuable findings may be incomplete or omitted.[/green]")
    else:
        console.print("[yellow]Verbose mode selected: This may take longer.[/yellow]")

    while True:
        console.print("\n[bold magenta]Choose a module to run:[/bold magenta]")
        for i, name in enumerate([
            "Subdomain Enumeration", "Certificate Analysis", "Grid IP Harvester",
            "GitHub Search", "Shodan Scan", "Cloud Fingerprint Detection",
            "Wayback JS + Vulnerabilities", "Error Page Extraction", "Path Fuzzing",
            "Supply Chain Analysis", "Cloud Bucket Audit", "ICS Exposure Detection",
            "Screenshot Capture", "Run ALL Modules in Sequence", "Generate Report",
            "Configure API Keys", "Edit Target Info", "View Previous Reports"
        ], 1):
            console.print(f"{i}. {name}")
        console.print("0. Exit")

        choice = Prompt.ask("\n[bold yellow]Enter your choice[/bold yellow]", default="0")

        if choice == "1":
            run_module("Subdomain Enumeration", run_subdomains, shared_data)
        elif choice == "2":
            run_module("Certificate Analysis", run_cert, shared_data)
        elif choice == "3":
            run_module("Grid IP Harvester", run_grid_harvest, shared_data)
        elif choice == "4":
            run_module("GitHub Search", run_github, shared_data)
        elif choice == "5":
            run_module("Shodan Scan", run_shodan, shared_data)
        elif choice == "6":
            run_module("Cloud Detection", run_cloud, shared_data)
        elif choice == "7":
            run_module("Wayback JS", run_wayback, shared_data)
        elif choice == "8":
            run_module("Error Page Extraction", run_errors, shared_data)
        elif choice == "9":
            run_module("Path Fuzzing", run_paths, shared_data)
        elif choice == "10":
            run_module("Supply Chain Analysis", run_supply, shared_data)
        elif choice == "11":
            run_module("Bucket Audit", run_buckets, shared_data)
        elif choice == "12":
            run_module("ICS Exposure Detection", run_ics, shared_data)
        elif choice == "13":
            run_module("Screenshot Capture", run_screens, shared_data)
        elif choice == "14":
            for name, func in [
                ("Subdomain Enumeration", run_subdomains), ("Certificate Analysis", run_cert),
                ("Grid IP Harvester", run_grid_harvest), ("GitHub Search", run_github),
                ("Shodan Scan", run_shodan), ("Cloud Detection", run_cloud),
                ("Wayback JS", run_wayback), ("Error Page Extraction", run_errors),
                ("Path Fuzzing", run_paths), ("Supply Chain Analysis", run_supply),
                ("Bucket Audit", run_buckets), ("ICS Exposure Detection", run_ics),
                ("Screenshot Capture", run_screens)
            ]:
                run_module(name, func, shared_data)
        elif choice == "15":
            generate_reports(shared_data)
        elif choice == "16":
            configure_api_keys()
        elif choice == "17":
            for key in ["root_domain", "company_name", "organization_name", "origin_registrant", "prefix_registrant"]:
                shared_data[key] = Prompt.ask(f"{key.replace('_', ' ').title()} (optional)", default=shared_data.get(key, ""))
        elif choice == "18":
            from pathlib import Path
            reports = sorted(Path("output").glob("*.html"))
            if not reports:
                console.print("[red]No reports found in output/[/red]")
            else:
                for i, rpt in enumerate(reports, 1):
                    console.print(f"{i}. {rpt.name}")
                idx = Prompt.ask("Select report to preview (or 0 to cancel)", default="0")
                if idx.isdigit() and 1 <= int(idx) <= len(reports):
                    selected = reports[int(idx)-1]
                    console.print(f"[green]Selected:[/green] {selected.resolve()}")
        elif choice == "0":
            console.print("\n[bold red]Exiting Deep Recon.[/bold red]")
            break
        else:
            console.print("[red]Invalid choice.[/red]")

def main():
    print_banner()
    console.print("[bold cyan]Welcome to Deep_Recon[/bold cyan]")
    shared_data = {}
    if Prompt.ask("Configure API keys?", choices=["yes", "no", "keep"], default="yes") == "yes":
        configure_api_keys()
    shared_data["root_domain"] = Prompt.ask("Enter root domain")
    for key in ["company_name", "organization_name", "origin_registrant", "prefix_registrant"]:
        shared_data[key] = Prompt.ask(f"{key.replace('_', ' ').title()} (optional)", default="")
    shared_data["report_filename"] = Prompt.ask("Custom report filename (optional)", default="deep_recon_report")
    recon_menu(shared_data)

if __name__ == "__main__":
    main()
