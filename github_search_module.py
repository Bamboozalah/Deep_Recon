from utils import get_api_key
def get_api_key(key):
    return os.getenv(key)


import requests
import logging
import os

def github_search(domain, token=None):
    query = f'"{domain}"'
    url = f"https://api.github.com/search/code?q={query}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            results = [{"name": item.get("name"), "repo": item["repository"]["full_name"], "url": item["html_url"]}
                       for item in items]
            return results
        else:
            logging.warning(f"GitHub API returned status {r.status_code}: {r.text}")
            return []
    except Exception as e:
        logging.error(f"GitHub search error: {e}")
        return []

def run(shared_data):
    logging.info("Running GitHub Search Module")
    domain = shared_data.get("root_domain")
    if not domain:
        logging.warning("No root_domain found in shared_data")
        return []

    token = get_api_key("GITHUB_TOKEN")
    results = github_search(domain, token=token)
    shared_data["github_leaks"] = results
    return results