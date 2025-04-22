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

def load_api_keys():
    keys = {
        "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
        "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN", "")
    }
    return keys

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

def recon_menu(shared_data):

    console.print("\n[bold cyan]Global Scan Mode:[/bold cyan]")
    fast_mode = Prompt.ask("Run all modules in fast mode by default?", choices=["y", "n"], default="y") == "y"
    if shared_data["fast_mode"]:
        console.print("[green]Fast mode selected: Valuable findings may be incomplete or omitted due to limited depth, throttling, and iteration caps.[/green]")
    shared_data["fast_mode"] = fast_mode
    shared_data["verbose_mode"] = not fast_mode
    if shared_data["verbose_mode"]:
        console.print("[yellow]Verbose mode selected: This scan may take significantly longer.[/yellow]")
    while True:
        console.print("\n[bold magenta]Choose a module to run:[/bold magenta]")
        console.print("1. Subdomain Enumeration")
        console.print("2. Certificate Analysis")
        console.print("3. Grid IP Harvester")
        console.print("4. GitHub Search")
        console.print("5. Shodan Scan")
        console.print("6. Cloud Fingerprint Detection")
        console.print("7. Wayback JS + Vulnerabilities")
        console.print("8. Error Page Extraction")
        console.print("9. Path Fuzzing")
        console.print("10. Supply Chain Analysis")
        console.print("11. Cloud Bucket Audit")
        console.print("12. ICS Exposure Detection")
        console.print("13. Screenshot Capture")
        console.print("14. Run [bold cyan]ALL[/bold cyan] Modules in Sequence")
        console.print("15. Generate Report")
        console.print("16. Configure API Keys")
        console.print("17. Edit Target Info")
        console.print("0. Exit")

        choice = Prompt.ask("\n[bold yellow]Enter your choice[/bold yellow]", default="0")

        if choice == "17":
            console.print("[bold cyan]\nEdit Target Information[/bold cyan]")
            shared_data["root_domain"] = Prompt.ask("Target domain", default=shared_data.get("root_domain", ""))
            shared_data["company_name"] = Prompt.ask("Company name", default=shared_data.get("company_name", ""))
            shared_data["organization_name"] = Prompt.ask("Organization name", default=shared_data.get("organization_name", ""))
            shared_data["origin_registrant"] = Prompt.ask("Origin registrant", default=shared_data.get("origin_registrant", ""))
            shared_data["prefix_registrant"] = Prompt.ask("Prefix registrant", default=shared_data.get("prefix_registrant", ""))
            console.print("[green]Target info updated.[/green]\n")
            continue

        if choice == "1":
            run_subdomains(shared_data)
        elif choice == "2":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_cert(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "3":
            run_grid_harvest(shared_data)
        elif choice == "4":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_github(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "5":
            run_shodan(shared_data)
        elif choice == "6":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_cloud(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "7":
            run_wayback(shared_data)
        elif choice == "8":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_errors(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "9":
            run_paths(shared_data)
        elif choice == "10":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_supply(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "11":
            run_buckets(shared_data)
        elif choice == "12":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_ics(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "13":
            run_screens(shared_data)
        elif choice == "14":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            run_subdomains(shared_data)
            run_cert(shared_data)
            run_grid_harvest(shared_data)
            run_github(shared_data)
            run_shodan(shared_data)
            run_cloud(shared_data)
            run_wayback(shared_data)
            run_errors(shared_data)
            run_paths(shared_data)
            run_supply(shared_data)
            run_buckets(shared_data)
            run_ics(shared_data)
            run_screens(shared_data)
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        elif choice == "15":
            generate_reports(shared_data)
        elif choice == "16":
            console.print(f"[cyan]Starting module {choice}...[/cyan]")
        try:
            # Module runs below will be nested in this block
            configure_api_keys()
        except Exception as e:
            console.print(f"[red]Error running module {choice}: {e}[/red]")
        else:
            console.print(f"[green]Module {choice} completed and data saved to shared_data.[/green]\n")
        
        elif choice == "18":
            from pathlib import Path
            reports = sorted(Path("output").glob("*.html"))
            if not reports:
                console.print("[red]No reports found in output/[/red]")
            else:
                console.print("[cyan]Available reports:[/cyan]")
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
