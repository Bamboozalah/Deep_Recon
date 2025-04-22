
import requests
import logging

COMMON_PATHS = [
    "/.env", "/admin", "/login", "/config", "/debug", "/test", "/backup", "/.git", "/phpinfo.php",
    "/server-status", "/.DS_Store", "/wp-admin", "/robots.txt", "/sitemap.xml", "/error", "/debug.log"
]

def fuzz_paths(domain):
    results = []
    base_url = f"https://{domain}"

    for i, path in enumerate(COMMON_PATHS):
        if fast_mode and i >= 200:
            break
        if verbose_mode:
            time.sleep(0.25)
        url = base_url + path
        if r.status_code in [200, 301, 302, 403]:
            results.append({"path": path, "status": r.status_code})
            logging.info(f"{domain}{path} -> {r.status_code}")
        except requests.RequestException as e:
            logging.debug(f"Request to {url} failed: {e}")
    return results

def run(shared_data):

    from rich.prompt import Prompt
    from rich.console import Console
    import time

    console = Console()
    console.print("\n[bold cyan]Choose Path Fuzzing Module.Py Mode:[/bold cyan]")
    fast_mode = Prompt.ask("Run in fast mode? (limits to 200 items)", choices=["y", "n"], default="y") == "y"
    verbose_mode = not fast_mode
    subdomains = shared_data.get("subdomains") or shared_data.get("cert_domains") or []
    if not subdomains:
        logging.warning("No subdomains available. Consider running Subdomain or Cert modules first.")
        return

    logging.info("Running Path Fuzzing Module")
    subdomains = shared_data.get("subdomains", [])
    if not subdomains:
        logging.warning("No subdomains for path fuzzing.")
        return {}

    output = {}
    for domain in subdomains:
        output[domain] = fuzz_paths(domain)

    shared_data["path_fuzzing"] = output
    return output
