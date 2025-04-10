# deep_recon_cli.py
#!/usr/bin/env python3
import os
import sys
import json
import logging

# Import modular functionality (ensure these files are in the same directory)
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
                config = json.load(f)
            return config
        except Exception as e:
            logging.error("Error loading config: " + str(e))
            return {}
    else:
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
    save_choice = input("Would you like to save these keys for future sessions? (y/n): ").lower().strip()
    if save_choice == 'y':
        save_config(config)
        print("API keys saved securely in configuration file.\n")
    else:
        print("API keys will not be saved for future sessions.\n")
    return config

def load_enrichment_subdomains():
    enrichment = []
    file_path = "subdomains.txt"
    if os.path.isfile(file_path):
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        enrichment.append(line)
            print(f"Loaded {len(enrichment)} enrichment subdomains from {file_path}")
        except Exception as e:
            logging.error("Error loading enrichment subdomains: " + str(e))
    else:
        print("No subdomains enumeration file found for enrichment.")
    return enrichment

def main_menu(config, global_target, enrichment_subdomains, vuln_cache):
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
            sub_target = input("Enter the target domain for subdomain enumeration: ").strip()
            tool = input("Choose enumeration tool (subfinder/assetfinder): ").strip().lower()
            os.system(f"python3 subdomain_enumeration.py {sub_target} {tool}")
            enrichment_subdomains = load_enrichment_subdomains()

        elif choice == '2':
            print("Running Wayback JS Extraction on the global target...")
            js_urls, vuln_results = run_wayback_js_extraction(global_target)
            if vuln_results:
                vuln_cache.clear()
                vuln_cache.extend(vuln_results)
            if enrichment_subdomains:
                print("\nRunning Wayback JS Extraction on enrichment subdomains...")
                for sub in enrichment_subdomains:
                    print(f"\nProcessing subdomain: {sub}")
                    js_u, vuln_res = run_wayback_js_extraction(sub)
                    if vuln_res:
                        vuln_cache.extend(vuln_res)

        elif choice == '3':
            cert_input = input("Enter a target or a file (e.g., subdomains.txt) for certificate data: ").strip()
            cert_results = run_cert_data(cert_input)

        elif choice == '4':
            gh_input = input("Enter a target or subdomains file for GitHub search: ").strip()
            gh_findings = run_github_search(gh_input, config)

        elif choice == '5':
            shodan_target = input("Enter target or subdomains file for Shodan query: ").strip()
            shodan_results = run_shodan_query(shodan_target, config)

        elif choice == '6':
            screenshot_input = input("Enter a target URL or file (press Enter to autoload from subdomains.txt): ").strip()
            if screenshot_input == "":
                run_screenshot_capture()
            else:
                run_screenshot_capture(screenshot_input)

        elif choice == '7':
            print("Running Error Page Extraction on the global target...")
            run_error_page_extraction(global_target)
            if enrichment_subdomains:
                print("\nRunning Error Page Extraction on enrichment subdomains...")
                for sub in enrichment_subdomains:
                    run_error_page_extraction(sub)

        elif choice == '8':
            print("Running Cloud Detection on the global target and enrichment subdomains...")
            cloud_results = run_cloud_detection(global_target)
            if enrichment_subdomains:
                for sub in enrichment_subdomains:
                    print(f"\nProcessing enrichment subdomain: {sub}")
                    cloud_results.update(run_cloud_detection(sub))

        elif choice == '9':
            run_bucket_auditing(global_target)
            if enrichment_subdomains:
                print("\nRunning Bucket Auditing on enrichment subdomains...")
                for sub in enrichment_subdomains:
                    run_bucket_auditing(sub)

        elif choice == '10':
            pf_input = input("Enter a target or subdomains file for path fuzzing: ").strip()
            fuzz_results = run_path_fuzzing(pf_input)

        elif choice == '11':
            print("Running Supply Chain Detection on the global target and enrichment subdomains...")
            supply_results = run_supply_chain_detection(global_target)
            if enrichment_subdomains:
                for sub in enrichment_subdomains:
                    print(f"\nProcessing enrichment subdomain: {sub}")
                    supply_results.update(run_supply_chain_detection(sub))

        elif choice == '12':
            generate_reports(global_target, vuln_cache)

        elif choice == '13':
            config = configure_api_keys(config)

        elif choice == '0':
            print("Exiting Deep_Recon. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

def main():
    init_logging()
    display_banner()
    config = load_config()
    enrichment_subdomains = load_enrichment_subdomains()
    vuln_cache = []
    print("Welcome to Deep_Recon Interactive CLI!")
    http_proxy = os.environ.get("HTTP_PROXY", "Not set")
    https_proxy = os.environ.get("HTTPS_PROXY", "Not set")
    print(f"Detected HTTP Proxy: {http_proxy}")
    print(f"Detected HTTPS Proxy: {https_proxy}")
    global_target = ""
    while not global_target:
        global_target = input("\nEnter the default target domain or IP (for modules other than subdomain enumeration): ").strip()
        if not global_target:
            print("Please enter a valid target (cannot be empty).")
    main_menu(config, global_target, enrichment_subdomains, vuln_cache)

if __name__ == "__main__":
    main()
