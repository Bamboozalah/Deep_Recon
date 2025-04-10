#!/usr/bin/env python3
import subprocess
import logging
import os

def init_logging():
    logging.basicConfig(
        filename='screenshot_capture_module.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    logging.info("Screenshot Capture Module started.")

def run_screenshot_capture(target):
    """
    Invokes an external screenshot tool (such gowitness) to capture a screenshot
    of the provided target URL. Screenshots are saved in a folder called 'screenshots'.
    """
    init_logging()
    print(f"\n[Screenshot Capture Module] Capturing screenshot for target: {target}")
    output_dir = "screenshots"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    # Command to capture a screenshot using gowitness.
    # This uses the 'single' command; can be adjusted.
    cmd = ["gowitness", "single", "--url", target, "--destination", output_dir]
    try:
        subprocess.run(cmd, check=True)
        print(f"Screenshot captured for {target}, saved in directory '{output_dir}'.")
        logging.info("Screenshot capture complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing screenshot for {target}.")
        logging.error(f"Screenshot capture failed: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 screenshot_capture_module.py <target>")
        sys.exit(1)
    target = sys.argv[1]
    run_screenshot_capture(target)
