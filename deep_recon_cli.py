# deep_recon_cli.py
#!/usr/bin/env python3
import os
import sys
import json
import logging

# Import modular functionality
from subdomain_enumeration import run_subdomain_enumeration
from wayback_js_module import run_wayback_js_extraction
from cert_data_module import run_cert_data
from github_search_module import run_github_search
from shodan_query_module import run_shodan_query
from screenshot_capture_module import run_screenshot_capture
from error_page_extraction_module import run_error_page_extraction, process_target_or_file
from path_fuzzing_module import run_path_fuzzing
from reporting_module import generate_reports
from cloud_detection_module import run_cloud_detection
from supply_chain_module import run_supply_chain_detection
from bucket_auditing_module import run_bucket_auditing
from risk_utils import apply_risk_score

# ----------------------------
# Display banner
# ----------------------------
def display_banner():
    neon_purple = "\033[38;2;238;130;238m"
    reset = "\033[0m"
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
    print(neon_purple + banner + reset)

def init_logging():
    logging.basicConfig(
        filename='deep_recon.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Deep_Recon CLI started.")

def load_config():
    config_file = 'deep_recon_config.json'
    if os.path.isfile(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error("Error loading config: " + str(e))
            return {}
    return {}

def save_config(config):
    config_file = 'deep_recon_config.json'
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        logging.info("Config saved successfully.")
    except Exception as e:
        logging.error("Error saving config: " + str(e))

def configure_api_keys(config):
    print("\n-- API Keys Configuration --")
    github_key = input("Enter GitHub API key (or leave blank to skip): ").strip()
    if github_key:
        config['github_api_key'] = github_key
    shodan_key = input("Enter Shodan API key (or leave blank to skip): ").strip()
    if shodan_key:
        config['shodan_api_key'] = shodan_key
    save_choice = input("Save these keys for future sessions? (y/n): ").lower().strip()
    if save_choice == 'y':
        save_config(config)
        print("API keys saved securely.\n")
    else:
        print("API keys will not be saved.\n")
    return config

def load_enrichment_subdomains():
    enrichment = []
    file_path = "subdomains.txt"
    if os.path.isfile(file_path):
        try:
            with open(file_path, "r") as f:
                enrichment = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(enrichment)} enrichment subdomains from {file_path}")
        except Exception as e:
            logging.error("Error loading enrichment subdomains: " + str(e))
    else:
        print("No subdomains enumeration file found for enrichment.")
    return enrichment

def main_menu(config, global_target, enrichment_subdomains, vuln_cache):
    cert_results = []
    cert_domains = set()
    all_targets = set(enrichment_subdomains)
    while True:
        print("\n========== Deep_Recon Interactive Menu ==========")
        print("1. Run Subdomain Enumeration")
        print("2. Run Wayback JS Extraction & Vulnerability Analysis")
        print("3. Run Certificate Data Compilation")
        print("4. Run GitHub Search for Exposed Secrets")
        print("5. Run Shodan Query")
        print("6. Run Screenshot Capture")
        print("7. Run Error Page Extraction")
        print("8. Run Cloud/Techstack Detection")
        print("9. Run Bucket Auditing")
        print("10. Run S3 and Path Fuzzing")
        print("11. Run Supply Chain Detection")
        print("12. Generate Reports")
        print("13. Configure API Keys")
        print("0. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            sub_target = input("Enter the target domain: ").strip()
            tool = input("Choose tool (subfinder/assetfinder): ").strip().lower()
            os.system(f"python3 subdomain_enumeration.py {sub_target} {tool}")
            enrichment_subdomains = load_enrichment_subdomains()
            all_targets.update(enrichment_subdomains)

        elif choice == '2':
            print("Running Wayback JS Extraction on global target...")
            js_urls, vuln_results = run_wayback_js_extraction(global_target)
            vuln_results = apply_risk_score(vuln_results)
            vuln_cache.clear()
            vuln_cache.extend(vuln_results)
            for sub in enrichment_subdomains:
                print(f"\nProcessing subdomain: {sub}")
                _, sub_vulns = run_wayback_js_extraction(sub)
                vuln_cache.extend(apply_risk_score(sub_vulns))

        elif choice == '3':
            cert_input = input("Enter target or file (e.g., subdomains.txt): ").strip()
            cert_results = run_cert_data(cert_input)
            for result in cert_results:
                cert_domains.update(result["certificate"].get("names", []))
            all_targets.update(cert_domains)

        elif choice == '4':
            gh_input = input("Enter target or file: ").strip()
            run_github_search(gh_input, config)

        elif choice == '5':
            run_shodan_query(list(all_targets), config)

        elif choice == '6':
            print("Running Screenshot Capture prioritized by severity...")
            run_screenshot_capture(targets=list(all_targets), prioritize_risky=True)

        elif choice == '7':
            print("Running Error Page Extraction...")
            run_error_page_extraction(global_target, list(all_targets))

        elif choice == '8':
            print("Running Cloud Detection...")
            run_cloud_detection(global_target)
            for sub in all_targets:
                print(f"\nProcessing: {sub}")
                run_cloud_detection(sub)

        elif choice == '9':
            run_bucket_auditing(global_target)
            for sub in all_targets:
                run_bucket_auditing(sub)

        elif choice == '10':
            pf_input = input("Enter target or file: ").strip()
            run_path_fuzzing(pf_input)

        elif choice == '11':
            print("Running Supply Chain Detection...")
            run_supply_chain_detection(global_target)
            for sub in all_targets:
                run_supply_chain_detection(sub)

        elif choice == '12':
            generate_reports(global_target, vuln_cache)

        elif choice == '13':
            config = configure_api_keys(config)

        elif choice == '0':
            print("Exiting Deep_Recon. Goodbye!")
            break

        else:
            print("Invalid choice. Try again.")

def main():
    init_logging()
    display_banner()
    config = load_config()
    enrichment_subdomains = load_enrichment_subdomains()
    vuln_cache = []
    print("Welcome to Deep_Recon Interactive CLI!")
    print(f"Detected HTTP Proxy: {os.environ.get('HTTP_PROXY', 'Not set')}")
    print(f"Detected HTTPS Proxy: {os.environ.get('HTTPS_PROXY', 'Not set')}")
    global_target = ""
    while not global_target:
        global_target = input("\nEnter default target domain or IP: ").strip()
        if not global_target:
            print("Please enter a valid target.")
    main_menu(config, global_target, enrichment_subdomains, vuln_cache)

if __name__ == "__main__":
    main()



