from utils import get_api_key
def get_api_key(key):


import shodan
import socket
import logging
import os
from grid_ip_harvester import fetch_grid_related_ips

ICS_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    102: "Siemens S7",
    47808: "BACnet",
    44818: "EtherNet/IP",
    2222: "EtherNet/IP (UDP)",
    20547: "ProConOS",
    18245: "GE SRTP"
}

MITRE_MAP = {
    "Modbus": "T0860",  # Default credentials/modbus comms
    "DNP3": "T0861",
    "S7": "T0862",
    "BACnet": "T0863",
    "EtherNet/IP": "T0864",
    "ProConOS": "T0865",
    "GE SRTP": "T0866",
    "Schneider": "T0882",
    "Siemens": "T0881",
    "ABB": "T0880",
    "Allen-Bradley": "T0883",
    "Mitsubishi": "T0884"
}

def assign_risk_score(port, vulns):
    score = 0
    if port in ICS_PORTS:
        score += 3
    if vulns:
        score += len(vulns)
    return min(score, 10)

def run(shared_data):
    logging.info("Running ICS Exposure Module with risk scoring")

    if not api_key:
        return {}

    subdomains = shared_data.get("subdomains", [])
    search_ips = []

    for host in subdomains:
        try:
            ip = socket.gethostbyname(host)
            search_ips.append((host, ip))
        except Exception as e:
            logging.warning(f"Failed to resolve {host}: {e}")

    suspect_ips = fetch_grid_related_ips(keywords=["port:502", "port:102", "modbus", "dnp3", "Electric Cooperative"], limit=100)
    for ip in suspect_ips:
        search_ips.append((ip, ip))

    api = shodan.Shodan(api_key)
    exposure_results = {}

    for hostname, ip in search_ips:
        try:
            response = api.host(ip)
            for item in response.get("data", []):
                port = item.get("port")
                product = item.get("product", "")
                if port in ICS_PORTS or any(p.lower() in product.lower() for p in ICS_PORTS.values()):
                    vulns = list(item.get("vulns", {}).keys()) if item.get("vulns") else []
                    risk = assign_risk_score(port, vulns)

                    mitre = []
                    for key, tactic in MITRE_MAP.items():
                        if key.lower() in product.lower():
                            mitre.append(tactic)

                    exposure = {
                        "port": port,
                        "product": product,
                        "transport": item.get("transport"),
                        "org": response.get("org"),
                        "location": response.get("location"),
                        "vulns": vulns,
                        "risk_score": risk,
                        "mitre_attack": mitre
                    }

                    if hostname not in exposure_results:
                        exposure_results[hostname] = []
                    exposure_results[hostname].append(exposure)

                    logging.info(f"ICS risk exposure for {hostname} - risk {risk} - port {port}")
        except shodan.APIError as e:
            logging.warning(f"Shodan API error for {ip}: {e}")
        except Exception as e:
            logging.error(f"Error checking ICS exposure for {ip}: {e}")

    shared_data["ics_exposure"] = exposure_results
    return exposure_results