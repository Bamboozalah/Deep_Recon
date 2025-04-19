
import subprocess
import os
import logging

def run_screenshot_capture(domains):
    output_dir = "screenshots"
    os.makedirs(output_dir, exist_ok=True)
    result_paths = {}

    for domain in domains:
        url = f"https://{domain}"
        outfile = os.path.join(output_dir, f"{domain}.png")
        try:
            cmd = ["gowitness", "single", "--url", url, "--destination", outfile]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            if os.path.exists(outfile):
                result_paths[domain] = outfile
                logging.info(f"Screenshot saved for {domain}")
        except Exception as e:
            logging.warning(f"Screenshot failed for {domain}: {e}")
    return result_paths

def run(shared_data):
    subdomains = shared_data.get("subdomains") or shared_data.get("cert_domains") or []
    if not subdomains:
        logging.warning("No subdomains available. Consider running Subdomain or Cert modules first.")
        return

    logging.info("Running Screenshot Capture Module")
    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains to screenshot.")
        return {}

    screenshots = run_screenshot_capture(subdomains)
    shared_data["screenshots"] = screenshots
    return screenshots