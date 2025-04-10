#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
import logging
import sys
import socket


def init_logging():
    logging.basicConfig(
        filename='bucket_audit_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Bucket Audit Module started.")


def generate_bucket_candidates(target, derived_names=None):
    """
    Generates candidate bucket names by combining the target domain’s base with a word bank.
    Includes terms for NERC/CIP, incident response, credentials, APIs, supply chain, maps,
    and manufacturer names.
    """
    if derived_names is None:
        derived_names = []
    domain_parts = target.split('.')
    domain_base = domain_parts[0] if domain_parts else target

    word_bank = [
        "nerc", "cip", "incident", "response", "api", "apikey", "personaldata",
        "credentials", "creds", "supplychain", "maps", "backup", "docs", "assets",
        "rockwellautomation", "schneiderelectric", "emerson", "siemens", "abb",
        "gevernova", "honeywell", "firmware", "binaries", "configs", "archives"
    ]

    candidates = set(derived_names)
    for word in word_bank:
        candidates.update({
            f"{domain_base}-{word}", f"{word}-{domain_base}",
            f"{domain_base}{word}", f"{word}{domain_base}"
        })
    return list(candidates)


def test_bucket_access(bucket_name):
    """
    Attempts to list objects in the candidate bucket.
    Returns a dictionary with the bucket name, status, and list of objects if accessible.
    """
    s3 = boto3.client('s3')
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            return {
                "bucket": bucket_name,
                "status": "open",
                "contents": [obj['Key'] for obj in response['Contents']]
            }
        else:
            return {
                "bucket": bucket_name,
                "status": "empty but accessible",
                "contents": []
            }
    except ClientError as e:
        error_code = e.response['Error'].get('Code', 'Unknown')
        if error_code == "AccessDenied":
            return {"bucket": bucket_name, "status": "restricted"}
        elif error_code == "NoSuchBucket":
            return {"bucket": bucket_name, "status": "non-existent"}
        else:
            logging.error(f"Unexpected error for bucket {bucket_name}: {error_code}")
            return {"bucket": bucket_name, "status": f"error: {error_code}"}
    except (NoCredentialsError, EndpointConnectionError) as e:
        logging.error(f"AWS connection issue: {e}")
        return {"bucket": bucket_name, "status": "aws error"}


def run_bucket_auditing(target):
    """
    Generates candidate bucket names for the target and tests each one.
    Prints a formatted report to the console and returns the results as a list.
    """
    init_logging()
    print(f"\n[Bucket Audit Module] Auditing buckets for target: {target}")
    candidates = generate_bucket_candidates(target)
    results = []
    for bucket in candidates:
        print(f"\nTesting bucket: {bucket}")
        result = test_bucket_access(bucket)
        results.append(result)
        status = result.get("status")
        if status in ["open", "empty but accessible"]:
            print(f"  Status: {status.upper()}")
            contents = result.get("contents", [])
            if contents:
                print("  Contents:")
                for item in contents:
                    print(f"    - {item}")
            else:
                print("  (No objects found in the bucket.)")
        else:
            print(f"  Status: {status.capitalize()}")
    print("\n[Bucket Audit Module] Testing complete.")
    logging.info("Bucket audit complete.")
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bucket_audit_module.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    results = run_bucket_auditing(target)
    print("\nSummary of Bucket Audit Results:")
    for result in results:
        print(result)
