#!/bin/bash

COMMAND=$1
shift

if [ "$COMMAND" == "generate-report" ]; then
    echo "[+] Generating HTML report..."
    python3 report_generator.py "$@"
elif [ "$COMMAND" == "--domain" ] || [ "$COMMAND" == "--input" ]; then
    echo "[+] Running deep recon scan..."
    python3 deep_recon_v2.py "$COMMAND" "$@"
else
    echo "Usage:"
    echo "  docker run -v \$(pwd):/app reconbox --domain example.com [--mode full|fast]"
    echo "  docker run -v \$(pwd):/app reconbox --input subdomains.csv"
    echo "  docker run -v \$(pwd):/app reconbox generate-report --input results.csv --screenshots screenshots/"
fi
