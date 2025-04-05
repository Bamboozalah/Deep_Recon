# deep_recon_v2.py (Docker-ready, all features)

import csv
import socket
import ssl
import requests
import argparse
import subprocess
from urllib.parse import urlparse
from datetime import datetime
import os
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Deep Recon Tool v2 with Correlation & Pivot Suggestions")
parser.add_argument('--domain', help='Domain to enumerate subdomains for')
parser.add_argument('--input', help='CSV input file with subdomains')
parser.add_argument('--mode', choices=['fast', 'full'], default='full', help='Enumeration mode')
args = parser.parse_args()

TARGET = args.domain or 'custom_input'
OUTPUT_FILE = f"recon_results_{TARGET}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
TABLE_OUTPUT = f"classified_recon_table_{TARGET}.txt"

def enumerate_subdomains(domain, mode='full'):
    print(f"[~] Enumerating subdomains for {domain} using {mode} mode...")
    enum_cmd = f"subfinder -silent -d {domain}" if mode == 'full' else f"assetfinder --subs-only {domain}"
    try:
        result = subprocess.check_output(enum_cmd, shell=True, text=True)
        subs = list(set(line.strip() for line in result.splitlines() if domain in line))
        print(f"[+] Found {len(subs)} subdomains.")
        return subs
    except Exception as e:
        print(f"[!] Subdomain enumeration failed: {e}")
        return []

def get_http_info(url):
    info = {
        "URL": url,
        "Status Code": None,
        "Redirect": None,
        "Server": None,
        "X-Powered-By": None,
        "Error": None,
        "Error Title": None
    }
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        info["Status Code"] = response.status_code
        info["Redirect"] = response.url if response.url != url else None
        info["Server"] = response.headers.get("Server")
        info["X-Powered-By"] = response.headers.get("X-Powered-By")
        if response.status_code >= 400:
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("title")
            if title:
                info["Error Title"] = title.text.strip()
    except Exception as e:
        info["Error"] = str(e)
    return info

def get_cert_issuer(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            return issuer.get('organizationName')
    except Exception:
        return None

def get_cname(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        return ", ".join(result[1]) if result[1] else None
    except Exception:
        return None

def correlate_cloud(headers, cname, cert_issuer):
    fingerprint = f"{cname} {headers.get('Server', '')} {headers.get('X-Powered-By', '')} {cert_issuer}"
    fp = fingerprint.lower()
    if 'amazon' in fp or 's3' in fp or 'cloudfront' in fp:
        return 'AWS'
    elif 'azure' in fp or 'microsoft' in fp:
        return 'Azure'
    elif 'oracle' in fp or 'objectstorage' in fp:
        return 'Oracle'
    elif 'google' in fp:
        return 'GCP'
    elif 'cloudflare' in fp:
        return 'Cloudflare'
    return 'Unknown'

def assess_risk(row):
    score = 0
    notes = []

    if row['Status Code'] and int(row['Status Code']) >= 400:
        score += 2
        notes.append("Error status")
    if row['X-Powered-By'] and any(x in row['X-Powered-By'].lower() for x in ['php', 'asp.net']):
        score += 2
        notes.append("Legacy stack")
    if row['Cert Issuer'] and 'Let\'s Encrypt' in row['Cert Issuer']:
        score += 1
        notes.append("LE short cert")
    if row['Cloud Provider'] != 'Unknown':
        score += 2
        notes.append("Cloud-hosted")
    if row['Server'] and any(x in row['Server'].lower() for x in ['apache', 'nginx', 'iis']):
        score += 1
        notes.append("Identified stack")

    if score >= 6:
        return "CRITICAL", "; ".join(notes)
    elif score >= 4:
        return "HIGH", "; ".join(notes)
    elif score >= 2:
        return "MEDIUM", "; ".join(notes)
    else:
        return "LOW", "; ".join(notes)

def suggest_pivots(domain, stack, risk):
    pivots = []
    if stack:
        stack = stack.lower()
        if 'django' in stack:
            pivots.append(f"site:github.com \"settings.py\" {domain}")
        if 'php' in stack:
            pivots.append(f"site:github.com \"config.php\" {domain}")
        if 'asp.net' in stack:
            pivots.append(f"site:github.com Web.config {domain}")
    if risk in ['HIGH', 'CRITICAL']:
        pivots.append(f"Check S3 buckets or cloud blobs linked to {domain}")
        pivots.append(f"Try fuzzing /admin /debug /internal on {domain}")
    return "; ".join(pivots)

if args.domain:
    subdomains = enumerate_subdomains(args.domain, mode=args.mode)
elif args.input:
    with open(args.input, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        subdomains = [row['Subdomain'] for row in reader]
else:
    print("[!] Please provide either --domain or --input")
    exit()

results = []
for sub in subdomains:
    url = f"https://{sub.strip()}"
    domain = urlparse(url).hostname
    print(f"[+] Scanning: {domain}")

    http_info = get_http_info(url)
    cert_issuer = get_cert_issuer(domain)
    cname = get_cname(domain)
    cloud = correlate_cloud(http_info, cname, cert_issuer)

    row = {
        "Subdomain": domain,
        **http_info,
        "Cert Issuer": cert_issuer,
        "CNAME": cname,
        "Cloud Provider": cloud
    }
    risk, notes = assess_risk(row)
    row["Risk Level"] = risk
    row["Notes"] = notes

    stack = row['X-Powered-By'] or row['Server'] or ''
    row['Pivot Suggestions'] = suggest_pivots(domain, stack, risk)

    results.append(row)

with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    fieldnames = list(results[0].keys())
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in results:
        writer.writerow(row)

with open(TABLE_OUTPUT, 'w') as table:
    table.write(f"{'Subdomain':<35} {'Cloud':<12} {'Stack':<15} {'Risk':<10} {'Notes'}\n")
    table.write("-" * 95 + "\n")
    for row in results:
        cloud = row['Cloud Provider']
        stack = row['X-Powered-By'] or row['Server'] or 'Unknown'
        table.write(f"{row['Subdomain']:<35} {cloud:<12} {stack[:15]:<15} {row['Risk Level']:<10} {row['Notes']}\n")

print(f"\n[✔] Recon complete! Results saved to {OUTPUT_FILE} and {TABLE_OUTPUT}")
