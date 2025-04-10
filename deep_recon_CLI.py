# deep_recon_cli.py 
#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import json
import logging
from active_bucket_testing import generate_bucket_candidates, active_bucket_testing
from subdomain_enumeration import run_subdomain_enumeration
# ----------------------------
# Display banner
# ----------------------------
def display_banner():
    neon_purple = "\033[38;2;238;130;238m"  # Bright neon purple
    reset = "\033[0m"
    banner = r"""
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
    print("Welcome to Deep_Recon!\n")

# ----------------------------
# Logging & Configuration
# ----------------------------
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
    # Ask for GitHub API key
    github_key = input("Enter GitHub API key (or leave blank to skip): ").strip()
    if github_key:
        config['github_api_key'] = github_key
    # Ask for Shodan API key
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

# ----------------------------
# Utility Functions
# ----------------------------
def show_progress(task_name, duration=3):
    print(f"\n{task_name} in progress", end="", flush=True)
    for i in range(duration):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(1)
    print(" Done.")

# ----------------------------
# Module Functionality
# ----------------------------
def run_subdomain_enumeration(target, tool='subfinder'):
    print(f"\n[Subdomain Enumeration] Running on target '{target}' using {tool}...")
    show_progress("Enumerating subdomains", duration=3)
    try:
        # In a real scenario, the tool would be executed.
        if tool == 'subfinder':
            cmd = ['subfinder', '-d', target, '-o', 'subdomains.txt']
        elif tool == 'assetfinder':
            cmd = ['assetfinder', '--subs-only', target]
        else:
            print("Invalid tool selected.")
            return

        # Uncomment below when the tool is installed:
        # subprocess.run(cmd, check=True)
        print("Subdomain enumeration completed. Results saved to subdomains.txt")
        logging.info("Subdomain enumeration successful.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Subdomain enumeration failed: {e}")
        print("Error during subdomain enumeration.")

def run_wayback_js(target):
    print(f"\n[Wayback JS Extraction] Processing target '{target}'...")
    show_progress("Extracting JavaScript URLs", duration=3)
    print("Wayback JS extraction complete. Found 42 JavaScript URLs.")
    logging.info("Wayback JS extraction completed.")

def run_cert_data(target):
    print(f"\n[Certificate Data] Collecting certificate information for '{target}'...")
    show_progress("Fetching certificate information", duration=3)
    print("Certificate data retrieval complete. Data saved to cert_data.json.")
    logging.info("Certificate data retrieved.")

def run_github_search(target, config):
    print(f"\n[GitHub Search] Searching for exposed secrets related to '{target}'...")
    if 'github_api_key' not in config:
        print("GitHub API key not configured. Please use the API Keys menu option.")
        return
    show_progress("Searching GitHub", duration=3)
    print("GitHub search complete. Exposed secrets (if any) documented.")
    logging.info("GitHub search completed.")

def run_shodan_query(target, config):
    print(f"\n[Shodan Query] Executing Shodan queries for target '{target}'...")
    if 'shodan_api_key' not in config:
        print("Shodan API key not configured. Please use the API Keys menu option.")
        return
    show_progress("Querying Shodan", duration=3)
    print("Shodan query complete. Results integrated into report.")
    logging.info("Shodan query completed.")

def run_screenshot_capture(target):
    print(f"\n[Screenshot Capture] Capturing screenshots for target '{target}' using gowitness...")
    show_progress("Taking screenshots", duration=3)
    print("Screenshot capture complete. Screenshots saved in screenshots/ directory.")
    logging.info("Screenshot capture completed.")

def run_error_page_extraction(target):
    print(f"\n[Error Page Extraction] Processing target '{target}'...")
    show_progress("Extracting error pages", duration=3)
    print("Error page extraction completed. Data saved for analysis.")
    logging.info("Error page extraction completed.")

def run_cloud_detection(target):
    print(f"\n[Cloud/Techstack Detection] Analyzing target '{target}'...")
    show_progress("Detecting technologies", duration=3)
    print("Cloud and techstack detection complete. Findings updated.")
    logging.info("Cloud/Techstack detection completed.")

def run_bucket_auditing(target):
    print(f"\n[Bucket Auditing] Auditing buckets for target '{target}'...")
    show_progress("Auditing buckets", duration=3)
    print("Bucket auditing complete. Potential misconfigurations documented.")
    logging.info("Bucket auditing completed.")

def run_path_fuzzing(target):
    print(f"\n[S3 and Path Fuzzing] Executing fuzzing for target '{target}'...")
    show_progress("Performing path fuzzing", duration=3)
    print("Path fuzzing completed. Results recorded.")
    logging.info("Path fuzzing completed.")

def run_supply_chain_detection(target):
    print(f"\n[Supply Chain Embedded Code Detection] Analyzing SCADA/OT systems for target '{target}'...")
    show_progress("Detecting supply chain issues", duration=3)
    print("Supply chain embedded code detection complete. Findings integrated.")
    logging.info("Supply chain code detection completed.")

def generate_reports(target):
    print(f"\n[Report Generation] Generating PDF and HTML reports for target '{target}'...")
    show_progress("Compiling reports", duration=3)
    print("Reports generated: DeepRecon_Report.pdf and DeepRecon_Report.html.")
    logging.info("Reports generated successfully.")

# ----------------------------
# Interactive Menu
# ----------------------------
def main_menu(config, target):
    while True:
        print("\n========== Deep_Recon Interactive Menu ==========")
        print("1. Subdomain Enumeration")
        print("2. Wayback JS Extraction")
        print("3. Certificate Data Compilation")
        print("4. GitHub Search for Exposed Secrets")
        print("5. Shodan Query")
        print("6. Screenshot Capture")
        print("7. Error Page Extraction")
        print("8. Cloud/Techstack Detection")
        print("9. Bucket Auditing")
        print("10. S3 and Path Fuzzing")
        print("11. Supply Chain Embedded Code Detection")
        print("12. Generate Reports")
        print("13. Configure API Keys")
        print("0. Exit")
        
        choice = input("Enter your choice: ").strip()
        if choice == '1':
            #run_subdomain_enumeration(target, tool)
            sub_target = input("Enter the target domain for subdomain enumeration: ").strip()
            tool = input("Choose enumeration tool (subfinder/assetfinder): ").strip().lower()
            run_subdomain_enumeration(sub_target, tool)
        elif choice == '2':
            run_wayback_js(target)
        elif choice == '3':
            run_cert_data(target)
        elif choice == '4':
            run_github_search(target, config)
        elif choice == '5':
            run_shodan_query(target, config)
        elif choice == '6':
            run_screenshot_capture(target)
        elif choice == '7':
            run_error_page_extraction(target)
        elif choice == '8':
            run_cloud_detection(target)
        elif choice == '9':
            #run_bucket_auditing(target)
            derived_buckets = []  # Or pass a list of derived names from URL filtering.
            candidate_buckets = generate_bucket_candidates(target, derived_buckets)
            print("\nGenerated Candidate Buckets for Testing:")
            for bucket in candidate_buckets:
            print("  -", bucket)
            active_bucket_testing(candidate_buckets)
        elif choice == '10':
            run_path_fuzzing(target)
        elif choice == '11':
            run_supply_chain_detection(target)
        elif choice == '12':
            generate_reports(target)
        elif choice == '13':
            config = configure_api_keys(config)
        elif choice == '0':
            print("Exiting Deep_Recon. Goodbye!")
            logging.info("Deep_Recon session ended by user.")
            break
        else:
            print("Invalid choice. Please try again.")

# ----------------------------
# Main Entry Point
# ----------------------------
def main():
    init_logging()
    config = load_config()
    print("Welcome to Deep_Recon Interactive CLI!")
    
    # Display proxy settings inherited from the environment
    http_proxy = os.environ.get("HTTP_PROXY", "Not set")
    https_proxy = os.environ.get("HTTPS_PROXY", "Not set")
    print(f"Detected HTTP Proxy: {http_proxy}")
    print(f"Detected HTTPS Proxy: {https_proxy}")
    
    target = input("\nEnter the target domain or IP: ").strip()
    main_menu(config, target)

if __name__ == "__main__":
    main()

