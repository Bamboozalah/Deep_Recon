# Deep_Recon
Deep_Recon is an OSINT automation tool designed for lazy analysts who don't like switching tools but need insight into asset exposure, cloud misconfigurations, and supply chain visibility, etc.
---

This tool can...should:
- **Find Hidden Web Addresses:** Look for secret subdomains (like secret pages on a website).
- **Check Old Website Files:** Look at old versions of website code to see if any secrets are left behind.
- **Read Website Certificates:** See who a website’s certificate is from and get extra info like IP addresses.
- **Search GitHub for Secrets:** Look for leaked passwords, secret API keys, and other secret codes.
- **Hit up Shodan for Info:** Find out if a website or device has any open doors (open ports) or known problems.
- **Take Screenshots:** Capture images of websites, especially if they look suss.
- **Look for Error Pages:** Find pages that serve errors to find broken stuff or misconfigurations.
- **Detect Cloud Services:** Determine what cloud provider the target uses (limited to AWS, Azure, or Google Cloud, atm).
- **Fuzz for Hidden Pages:** Try common paths (like `/admin` or `/login`) to see if there are secret pages.
- **Search for Supply Chain Secrets:** Look for systems or devices that might be vulnerable (like SCADA or industrial control systems).

Deep_Recon will compile all the necessary information into a PDF and HTML report with charts, risk ratings, MITRE ATT&CK mapping, and screenshots

## What Do You Need?

Before you can use Deep_Recon, you need to install a few things:

### Python Dependencies
Deep_Recon uses some extra Python tools. Run pip3 install -r requirements.txt to install:
- requests
- reportlab
- jinja2
- shodan
- boto3
### External Tools
You also need to install these:
- **subfinder:** Helps find hidden web addresses.
- **assetfinder:** Another tool for hidden web addresses.
- **gowitness:** Takes pictures (screenshots) of websites.

Check the **dependencies.txt** file for links and instructions.

After installing the dependencies, external tools, and fetching your API keys run python3 deep_recon_cli.py to get started.



