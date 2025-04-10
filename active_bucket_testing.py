#!/usr/bin/env python3
import boto3
from botocore.exceptions import ClientError

def test_bucket_access(bucket_name):
    """
    Attempts to list objects in the bucket to determine accessibility.
    Returns a dictionary with the bucket name, its status, and contents (if accessible).
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
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            return {"bucket": bucket_name, "status": "restricted"}
        elif error_code == 'NoSuchBucket':
            return {"bucket": bucket_name, "status": "non-existent"}
        else:
            return {"bucket": bucket_name, "status": f"error: {error_code}"}

def active_bucket_testing(candidate_buckets):
    """
    Iterates over a list of candidate bucket names, tests each bucket,
    and prints a formatted report of the status and any publicly accessible contents.
    Returns a list of result dictionaries.
    """
    results = []
    print("\n========== Active Bucket Testing ==========")
    for bucket in candidate_buckets:
        print(f"\nTesting bucket: {bucket}")
        result = test_bucket_access(bucket)
        results.append(result)
        status = result.get("status")
        if status in ["open", "empty but accessible"]:
            print(f"  Status: {status.upper()}")
            if result.get("contents"):
                print("  Contents:")
                for item in result["contents"]:
                    print(f"    - {item}")
            else:
                print("  (No objects found in the bucket.)")
        else:
            print(f"  Status: {status.capitalize()}")
    print("\nActive bucket testing complete.\n")
    return results

def generate_bucket_candidates(target, derived_names=None):
    """
    Generates candidate bucket names based on the target domain and a word bank.
    'derived_names' represents names obtained from URL filtering or prior enumeration.
    """
    if derived_names is None:
        derived_names = []
        
    # Extract a simplified base from the target domain (e.g., "example" from "example.com")
    domain_parts = target.split('.')
    domain_base = domain_parts[0] if domain_parts else target

    # Define the word bank with NERC-CIP and other relevant terms.
    word_bank = [
        "nerc", "cip", "incident", "response", "incidentresponse", "ir",
        "personaldata", "credentials", "creds", "api", "apikey",
        "supplychain", "maps", "geo", "location", "backup", "storage", "docs", "documentation",
        # Manufacturer names (formatted: lowercase, no spaces)
        "rockwellautomation", "schneiderelectric", "emerson", "siemens", "abb", "gevernova", "honeywell"
    ]
    
    candidates = set(derived_names)  # Start with previously derived names.
    
    # Generate candidate buckets by combining the domain base with each word from the bank.
    for word in word_bank:
        candidates.add(f"{domain_base}-{word}")
        candidates.add(f"{word}-{domain_base}")
        candidates.add(f"{domain_base}{word}")
        candidates.add(f"{word}{domain_base}")
        
    return list(candidates)

if __name__ == '__main__':
    # Simulated candidate names derived from URL filtering or previous enumeration.
    derived_buckets = ["example-assets", "example-data", "assets-example"]
    
    # Target domain as entered or enumerated.
    target = "example.com"
    
    # Generate candidate bucket names using the derived names and the word bank.
    candidate_buckets = generate_bucket_candidates(target, derived_buckets)
    print("Generated Candidate Buckets:")
    for bucket in candidate_buckets:
        print("  -", bucket)
    
    # Run active bucket testing against all candidate buckets.
    results = active_bucket_testing(candidate_buckets)
    
    print("Summary of Active Bucket Testing Results:")
    for result in results:
        print(result)
