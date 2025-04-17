
from controller import register_module, run_all_modules
from cert_data_module import run as run_cert
from subdomain_enumeration import run as run_subdomains
from shodan_query_module import run as run_shodan
from cloud_detection_module import run as run_cloud
from github_search_module import run as run_github
from wayback_js_module import run as run_wayback
from path_fuzzing_module import run as run_paths
from error_page_extraction_module import run as run_errors
from screenshot_capture_module import run as run_screens
from supply_chain_module import run as run_supply
from bucket_audit_module import run as run_buckets
from ics_exposure_module import run as run_ics
from reporting_module import generate_reports
from ics_exposure_module import run as run_ics

def main():
    register_module(run_subdomains, "Subdomain Enumeration")
    register_module(run_cert, "Certificate Analysis")
    register_module(run_shodan, "Shodan Search")
    register_module(run_cloud, "Cloud Fingerprinting")
    register_module(run_github, "GitHub Leakage Check")
    register_module(run_wayback, "Wayback JS Analysis")
    register_module(run_paths, "Path Fuzzing")
    register_module(run_errors, "Error Page Recon")
    register_module(run_screens, "Screenshot Capture")
    register_module(run_supply, "Supply Chain Investigation")
    register_module(run_buckets, "Cloud Bucket Audit")
    register_module(run_ics, "ICS Exposure Scan")

    results = run_all_modules()
    generate_reports(results)

    # Final report writing will be handled here in next step
    print("\n[+] Recon complete. Summary of results per module:")
    for k, v in results.items():
        print(f"  - {k}: {'Success' if 'error' not in v else 'Failed'}")

if __name__ == "__main__":
    main()
