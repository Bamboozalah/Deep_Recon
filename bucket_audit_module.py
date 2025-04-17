
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
import logging
import requests

WORD_BANK = ["data", "backup", "dev", "prod", "logs", "config", "files", "api", "nerc", "cip", "assets", "docs", "infra", "creds"]

def generate_bucket_candidates(domain):
    base = domain.split('.')[0]
    candidates = [f"{base}", f"{domain}"]
    for word in WORD_BANK:
        candidates.extend([f"{base}-{word}", f"{word}-{base}", f"{domain}-{word}"])
    return list(set(candidates))

def check_s3_bucket(bucket_name):
    s3 = boto3.client('s3')
    try:
        s3.head_bucket(Bucket=bucket_name)
        try:
            result = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            return {"provider": "AWS", "accessible": True, "listable": bool(result.get("Contents"))}
        except ClientError:
            return {"provider": "AWS", "accessible": True, "listable": False}
    except (ClientError, EndpointConnectionError):
        return {"provider": "AWS", "accessible": False, "listable": False}

def check_gcp_bucket(bucket_name):
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code in [200, 403]:
            return {"provider": "GCP", "accessible": True, "status_code": r.status_code}
    except Exception as e:
        logging.debug(f"GCP check error for {bucket_name}: {e}")
    return {"provider": "GCP", "accessible": False}

def check_azure_blob(bucket_name):
    # Anonymous access attempt to container root
    url = f"https://{bucket_name}.blob.core.windows.net/?restype=container&comp=list"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code in [200, 403]:
            return {"provider": "Azure", "accessible": True, "status_code": r.status_code}
    except Exception as e:
        logging.debug(f"Azure check error for {bucket_name}: {e}")
    return {"provider": "Azure", "accessible": False}

def run(shared_data):
    logging.info("Running Multi-Cloud Bucket Audit Module")
    domain = shared_data.get("root_domain")
    if not domain:
        logging.warning("No root_domain provided.")
        return {}

    candidates = generate_bucket_candidates(domain)
    results = {}

    for name in candidates:
        results[name] = {
            "aws": check_s3_bucket(name),
            "gcp": check_gcp_bucket(name),
            "azure": check_azure_blob(name)
        }
        logging.info(f"Checked {name}: {results[name]}")

    shared_data["bucket_audit"] = results
    return results
