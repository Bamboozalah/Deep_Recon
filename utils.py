import os
from dotenv import load_dotenv

def get_api_key(key):
    load_dotenv(dotenv_path="config/api_keys.env")
    return os.getenv(key)
