# Deep_Recon — Grid Intelligence & Exposure Reconnaissance Toolkit

**Deep_Recon** is a modular, CLI-driven reconnaissance framework designed to assist security researchers and analysts in mapping external exposure of internet-connected infrastructure, with a focus on energy, utilities, and critical sectors.

It combines passive data collection, open-source intelligence (OSINT), and optional third-party API integrations to support responsible threat analysis, technical discovery, and reporting.

---

## Key Features

-  Subdomain enumeration and TLS certificate analysis
-  Cloud bucket audits (AWS, Azure, GCP)
-  Exposure checks for ICS/SCADA devices using public data
-  Tech stack and cloud provider fingerprinting
-  GitHub secrets search and historical JS analysis
-  Supply chain mapping via third-party domain analysis
-  Visual screenshots of exposed services
-  HTML, CSV, and JSON reporting with summaries and severity filters

---

## Enrichment Framework

Deep Recon features a centralized **enrichment pipeline** that ensures each module can contribute to and benefit from shared intelligence throughout a recon session.

#### How It Works

- Modules like **Subdomain Enumeration**, **Certificate Analysis**, and **Grid IP Harvester** populate foundational information (e.g., domains, IPs, ASNs).
- Follow-on modules such as **Shodan Queries**, **ICS Exposure Checks**, and **Cloud Detection** automatically consume this enrichment.
- Data collection is restricted to once per session and reused where needed, minimizing redundant queries and improving performance.

#### Benefits

- **Context-aware scans**: Modules are more intelligent when they are aware of what has already been discovered.
- **Modular independence**: Each module can operate independently but cooperates when part of a pipeline.
- **Seamless reporting**: Enrichment ensures the final output has consistent, comprehensive intelligence across categories.

This system is designed to support scalable reconnaissance and research workflows and to make it easier for analysts to trace how individual findings connect across layers of exposure.

---

## Use Cases

- **Cyber Threat Intelligence (CTI):** Map internet-facing assets for attribution or exposure analysis.
- **Blue Team Reconnaissance:** Understand your organization’s shadow IT and third-party risks.
- **Incident Response Preparation:** Identify publicly accessible infrastructure for proactive monitoring.
- **Grid Sector Research:** Enrich public data for energy-sector exposure reports or analysis.

>**Note:** This tool is intended for lawful and ethical use in research and internal assessments only. Unauthorized scanning of networks you do not own or have permission to test is strictly prohibited.

---

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`
- Third-party tools (installed separately):
  - [`subfinder`](https://github.com/projectdiscovery/subfinder)
  - [`assetfinder`](https://github.com/tomnomnom/assetfinder)

---

## Setup

```bash
# Clone the repository
git clone https://github.com/your-username/Deep_Recon.git
cd Deep_Recon

# Install dependencies
pip install -r requirements.txt

# Install subfinder & assetfinder separately (if needed)

# Create API key config
mkdir config
echo "SHODAN_API_KEY=your_key" > config/api_keys.env
echo "GITHUB_TOKEN=your_token" >> config/api_keys.env

#Run Deep_Recon
python3 deep_recon_cli.py
```
---
## You’ll be guided through an interactive menu to:
-  Input a domain
-  Run specific modules or the full pipeline
-  Generate detailed reports


