
import requests
import logging

def fetch_wayback_js(domain):
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original"
    logging.info(f"Querying Wayback Machine for {domain}")
    js_urls = []

    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            data = r.json()
            for entry in data[1:]:  # Skip header row
                full_url = entry[0]
                if full_url.endswith(".js"):
                    js_urls.append(full_url)
            logging.info(f"Found {len(js_urls)} JS URLs for {domain}")
        else:
            logging.warning(f"Wayback response {r.status_code} for {domain}")
    except Exception as e:
        logging.error(f"Error querying Wayback for {domain}: {e}")
    return js_urls

def run(shared_data):

    from rich.prompt import Prompt
    from rich.console import Console
    import time

    console = Console()
    console.print("\n[bold cyan]Choose Wayback JS Mining Mode:[/bold cyan]")
    fast_mode = Prompt.ask("Run in fast mode? (limits to 500 JS files)", choices=["y", "n"], default="y") == "y"
    verbose_mode = not fast_mode
    logging.info("Running Wayback JS Module")
    domain = shared_data.get("root_domain")
    if not domain:
        logging.warning("No root_domain provided to Wayback module.")
        return []

    js_files = fetch_wayback_js(domain)
    shared_data["wayback_js"] = js_files
    return js_files
