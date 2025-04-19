
import ssl
import socket
import logging
from datetime import datetime

def get_cert_info(domain, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"],
                    "serialNumber": cert.get("serialNumber", ""),
                    "subjectAltName": cert.get("subjectAltName", []),
                }
    except Exception as e:
        logging.warning(f"Could not retrieve cert for {domain}: {e}")
        return None

def run(shared_data):
    try:
        timeout = int(input("Enter SSL timeout (default 5 seconds): ") or 5)
    except ValueError:
        timeout = 5
    logging.info("Running Certificate Data Module")
    subdomains = shared_data.get("subdomains", [])
    results = {}

    for domain in subdomains:
        cert_info = get_cert_info(domain)
        if cert_info:
            results[domain] = cert_info

    shared_data["cert_data"] = results
    return results
