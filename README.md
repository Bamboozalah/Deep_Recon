# Deep_Recon
Deep_Recon is a Dockerized OSINT automation tool that is designed for lazy analysts who don't like switching tools but need insight into asset exposure, cloud misconfigurations, and supply chain visibility.
Note: subfinder is a deep scanner, if you want a more discrete/faster scan use assetfinder or leverage an external tool that can export results into a csv for Deep_Recon to process.


---
## What does it do? 

- Integrated subdomain enumeration (subfinder or assetfinder)
- Risk scoring, cloud/tech stack detection
- Error page extraction
- Pivot suggestion engine (GitHub dorks, S3 hunt, path fuzzing)
- Full HTML report with:
  - Sortable triage table
  - Pie charts: risk, stack, cloud
  - Screenshots embedded for high-value targets


---


# Deep_Recon - Dockerized OSINT Recon Tool

## Instructions

### 🔧 Build the Docker Image
```bash
docker build -t reconbox .
```

### Run a Recon Scan
#### Subdomain Enumeration (default: subfinder)
```bash
docker run --rm -v $(pwd):/app reconbox --domain example.com
```

#### Fast Enumeration (assetfinder)
```bash
docker run --rm -v $(pwd):/app reconbox --domain example.com --mode fast
```

#### CSV-Based Scan
```bash
docker run --rm -v $(pwd):/app reconbox --input your_subdomains.csv
```

> Output files:
> - `recon_results_*.csv`: full results
> - `classified_recon_table_*.txt`: readable triage summary

---

### Generate HTML Report
```bash
docker run --rm -v $(pwd):/app reconbox generate-report --input recon_results_example.com.csv --screenshots screenshots/
```

This will generate:
- `recon_results_example.com_report.html` — interactive, dark-mode dashboard
- Includes screenshots only for `HIGH` and `CRITICAL` targets

> Screenshots should be named like `subdomain.example.com.png` and placed in the `screenshots/` directory.

---

## What does it do? 

- Integrated subdomain enumeration (subfinder or assetfinder)
- Risk scoring, cloud/tech stack detection
- Error page extraction
- Pivot suggestion engine (GitHub dorks, S3 hunt, path fuzzing)
- Full HTML report with:
  - Sortable triage table
  - Pie charts: risk, stack, cloud
  - Screenshots embedded for high-value targets

---

##Directory Structure
```
.
├── Dockerfile
├── entrypoint.sh
├── deep_recon_v2.py
├── report_generator.py
├── report_template.html
├── requirements.txt
├── screenshots/
│   └── login.example.com.png
├── recon_results_example.com.csv
├── recon_results_example.com_report.html
```

---

##Dependencies (included in Docker)
- `subfinder`, `assetfinder`
- `requests`, `pandas`, `jinja2`, `plotly`, `bs4`


Bless this mess, pull requests by invite only at the moment--its me not you. Will be public after more people test and find it useful.

