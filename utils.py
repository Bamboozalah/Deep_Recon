
from dotenv import load_dotenv
import os

def get_api_key(name):
    """
    Loads a named API key from config/api_keys.env.
    Example: get_api_key("SHODAN_API_KEY") or get_api_key("GITHUB_TOKEN")
    """
    load_dotenv(dotenv_path="config/api_keys.env")
    return os.getenv(name)
