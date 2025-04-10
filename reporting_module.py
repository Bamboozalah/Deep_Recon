#!/usr/bin/env python3
"""
reporting_module.py

This module collects report data from various Deep_Recon modules (e.g. subdomains, vulnerabilities,
certificate data, GitHub findings, Shodan results, screenshots, error page extraction, cloud detection, path fuzzing,
and supply chain detection), then generates:
  - A PDF report that includes MITRE ATT&CK mapping for vulnerabilities.
  - An HTML report featuring risk-rating sortable tables, charts (via Chart.js), and embedded screenshots.

The module is designed to be invoked from the Deep_Recon CLI (or run standalone with a sample data file).
"""

import os
import json
import time
from datetime import datetime

# Import ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet

# Import Jinja2 for HTML templating
from jinja2 import Template

# ----------------------------
# Helper: MITRE ATT&CK Mapping Dictionary
# ----------------------------
# In a real implementation, the mapping would be derived from a comprehensive database.
MITRE_MAPPING = {
    "eval(" : "T1059.001 - Command and Scripting Interpreter: JavaScript",
    "document.write(" : "Potential Dynamic Code Generation (Check for XSS)",
    "password" : "Credential Exposure Risk",
    "api[_-]?key" : "Sensitive API Key Disclosure",
    "secret" : "Sensitive Information Exposure"
}

# ----------------------------
# PDF Report Generation
# ----------------------------
def generate_pdf_report(report_data, output_filename="DeepRecon_Report.pdf"):
    """
    Generates a PDF report from the provided report_data dictionary.
    This PDF includes:
    • Global data summary including MITRE mappings for vulnerability findings.
    • Tables of results from each module.
    """
    doc = SimpleDocTemplate(output_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []
    # Title
    title = Paragraph("DeepRecon Report", styles["Title"])
    Story.append(title)
    Story.append(Spacer(1, 12))
    # Global Target and Timestamp
    global_target = report_data.get("global_target", "N/A")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = Paragraph(f"<b>Target:</b> {global_target} &nbsp;&nbsp;&nbsp; <b>Generated:</b> {timestamp}", styles["Normal"])
    Story.append(header)
    Story.append(Spacer(1, 12))
    # Subdomain Enumeration
    subdomains = report_data.get("subdomains", [])
    subdomain_text = f"Subdomains Discovered: {len(subdomains)}<br/>" + "<br/>".join(subdomains)
    Story.append(Paragraph(subdomain_text, styles["Normal"]))
    Story.append(Spacer(1, 12))
    # Vulnerability Findings from Wayback JS, etc.
    wayback_vuln = report_data.get("wayback_vuln", [])
    if wayback_vuln:
        Story.append(Paragraph("<b>Vulnerability Findings (MITRE ATT&CK Mapping):</b>", styles["Heading2"]))
        # Create a table with headers: URL, Pattern, Exploit Mapping, Risk Rating (simulated)
        data = [["URL", "Pattern", "MITRE Mapping", "Risk Rating"]]
        for record in wayback_vuln:
            url = record.get("url", "N/A")
            findings = record.get("findings", [])
            for pattern, exploit in findings:
                mitre = MITRE_MAPPING.get(pattern.strip(), exploit)
                # Simulate a risk rating based on pattern detection (for demo purposes)
                risk = "High" if "T1059.001" in mitre or "Credential" in mitre or "API" in mitre else "Medium"
                data.append([url, pattern, mitre, risk])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.black),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 12))
    else:
        Story.append(Paragraph("No vulnerability findings detected from Wayback JS analysis.", styles["Normal"]))
        Story.append(Spacer(1, 12))
    # Certificate Data Summary
    cert_data = report_data.get("cert_data", [])
    if cert_data:
        Story.append(Paragraph("<b>Certificate Data Findings:</b>", styles["Heading2"]))
        data = [["Target", "Common Name", "Issuer", "Domains"]]
        for record in cert_data:
            target = record.get("target", "N/A")
            cert = record.get("certificate", {})
            common_name = cert.get("common_name", "N/A")
            issuer = cert.get("issuer_name", "N/A")
            names = ", ".join(cert.get("names", []))
            data.append([target, common_name, issuer, names])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 12))
    # GitHub Findings Summary
    github_findings = report_data.get("github_findings", [])
    if github_findings:
        Story.append(Paragraph("<b>GitHub Findings:</b>", styles["Heading2"]))
        data = [["Target", "Keyword", "Total Results"]]
        for item in github_findings:
            target = item.get("target", "N/A")
            keyword = item.get("keyword", "N/A")
            count = item.get("total_count", 0)
            data.append([target, keyword, str(count)])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 12))
    # Shodan Results
    shodan_results = report_data.get("shodan_results", [])
    if shodan_results:
        Story.append(Paragraph("<b>Shodan Results:</b>", styles["Heading2"]))
        data = [["Target", "IP", "Org", "OS", "Open Ports", "Vulnerabilities"]]
        for res in shodan_results:
            target = res.get("target", "N/A")
            ip = res.get("ip", "N/A")
            org = res.get("org", "N/A")
            os_val = res.get("os", "N/A")
            ports = ", ".join(map(str, res.get("open_ports", [])))
            vulns = ", ".join(res.get("vulnerabilities", [])) if res.get("vulnerabilities") else "None"
            data.append([target, ip, org, os_val, ports, vulns])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 12))
    # Screenshots – embed a list of paths
    screenshots = report_data.get("screenshots", [])
    if screenshots:
        Story.append(Paragraph("<b>Screenshot Captures:</b>", styles["Heading2"]))
        for img_path in screenshots:
            if os.path.isfile(img_path):
                try:
                    im = Image(img_path, width=200, height=150)
                    Story.append(im)
                    Story.append(Spacer(1, 12))
                except Exception as e:
                    logging.error(f"Error embedding image {img_path}: {e}")
            else:
                Story.append(Paragraph(f"Image not found: {img_path}", styles["Normal"]))
                Story.append(Spacer(1, 12))
    # Error Pages Summary
    error_pages = report_data.get("error_pages", [])
    if error_pages:
        Story.append(Paragraph("<b>Error Page Extraction Findings:</b>", styles["Heading2"]))
        data = [["URL", "Status Code", "Error Message"]]
        for err in error_pages:
            data.append([err.get("url", "N/A"), str(err.get("status_code", "N/A")), err.get("error_message", "N/A")])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 12))
    # Cloud Detection Data Summary
    cloud_detection = report_data.get("cloud_detection", {})
    if cloud_detection:
        Story.append(Paragraph("<b>Cloud/Techstack Detection:</b>", styles["Heading2"]))
        for target, detection in cloud_detection.items():
            Story.append(Paragraph(f"{target}: {', '.join(detection)}", styles["Normal"]))
            Story.append(Spacer(1, 6))
    # Path Fuzzing Results
    path_fuzzing = report_data.get("path_fuzzing", {})
    if path_fuzzing:
        Story.append(Paragraph("<b>Path Fuzzing Results:</b>", styles["Heading2"]))
        for target, results in path_fuzzing.items():
            Story.append(Paragraph(f"Target: {target}", styles["Normal"]))
            for entry in results:
                Story.append(Paragraph(f"{entry['path']} - Status: {entry['status_code']}", styles["Normal"]))
            Story.append(Spacer(1, 6))
    # Supply Chain Findings
    supply_chain = report_data.get("supply_chain", {})
    if supply_chain:
        Story.append(Paragraph("<b>Supply Chain / Exposed Devices Findings:</b>", styles["Heading2"]))
        for target, findings in supply_chain.items():
            Story.append(Paragraph(f"{target}: {', '.join(findings)}", styles["Normal"]))
            Story.append(Spacer(1, 6))
    Story.append(Spacer(1, 12))
    # Build the PDF document.
    try:
        doc.build(Story)
        print(f"PDF Report generated: {output_filename}")
    except Exception as e:
        print(f"Error generating PDF Report: {e}")

# ----------------------------
# HTML Report Generation
# ----------------------------
def generate_html_report(report_data, output_filename="DeepRecon_Report.html"):
    """
    Generates an HTML report with risk-rated sortable tables, embedded charts, and screenshots.
    Uses Jinja2 templating.
    """
    # Define a basic HTML template with embedded DataTables and Chart.js via CDN.
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>DeepRecon Report</title>
      <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.1/css/jquery.dataTables.css">
      <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
      <script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #5a2d82; }
        .screenshot { max-width: 300px; margin: 10px; }
      </style>
    </head>
    <body>
      <h1>DeepRecon Report</h1>
      <p><strong>Target:</strong> {{ report_data.global_target }} &nbsp;&nbsp;&nbsp;
      <strong>Generated:</strong> {{ timestamp }}</p>
      
      <h2>Subdomains</h2>
      <table id="subdomains_table" class="display">
        <thead><tr><th>Subdomain</th></tr></thead>
        <tbody>
          {% for sub in report_data.subdomains %}
          <tr><td>{{ sub }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Vulnerability Findings (Wayback JS)</h2>
      <table id="vuln_table" class="display">
        <thead><tr>
          <th>URL</th>
          <th>Pattern</th>
          <th>MITRE Mapping</th>
          <th>Risk Rating</th>
        </tr></thead>
        <tbody>
          {% for record in report_data.wayback_vuln %}
            {% for pattern, mapping in record.findings %}
            <tr>
              <td>{{ record.url }}</td>
              <td>{{ pattern }}</td>
              <td>{{ mapping }}</td>
              <td>{{ "High" if "T1059" in mapping or "Credential" in mapping or "API" in mapping else "Medium" }}</td>
            </tr>
            {% endfor %}
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Certificate Data</h2>
      <table id="cert_table" class="display">
        <thead>
          <tr><th>Target</th><th>Common Name</th><th>Issuer</th><th>Domains</th></tr>
        </thead>
        <tbody>
          {% for cert in report_data.cert_data %}
          <tr>
            <td>{{ cert.target }}</td>
            <td>{{ cert.certificate.common_name }}</td>
            <td>{{ cert.certificate.issuer_name }}</td>
            <td>{{ cert.certificate.names | join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>GitHub Findings</h2>
      <table id="github_table" class="display">
        <thead>
          <tr><th>Target</th><th>Keyword</th><th>Total Results</th></tr>
        </thead>
        <tbody>
          {% for item in report_data.github_findings %}
          <tr>
            <td>{{ item.target }}</td>
            <td>{{ item.keyword }}</td>
            <td>{{ item.total_count }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Shodan Results</h2>
      <table id="shodan_table" class="display">
        <thead>
          <tr>
            <th>Target</th>
            <th>IP</th>
            <th>Organization</th>
            <th>OS</th>
            <th>Open Ports</th>
            <th>Vulnerabilities</th>
          </tr>
        </thead>
        <tbody>
          {% for item in report_data.shodan_results %}
          <tr>
            <td>{{ item.target }}</td>
            <td>{{ item.ip }}</td>
            <td>{{ item.org }}</td>
            <td>{{ item.os }}</td>
            <td>{{ item.open_ports | join(', ') }}</td>
            <td>{{ item.vulnerabilities | join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Screenshots</h2>
      {% for img in report_data.screenshots %}
        <img src="{{ img }}" alt="Screenshot" class="screenshot">
      {% endfor %}
      
      <h2>Error Page Extraction</h2>
      <table id="error_table" class="display">
        <thead>
          <tr><th>URL</th><th>Status Code</th><th>Error Message</th></tr>
        </thead>
        <tbody>
          {% for err in report_data.error_pages %}
          <tr>
            <td>{{ err.url }}</td>
            <td>{{ err.status_code }}</td>
            <td>{{ err.error_message }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Cloud Detection</h2>
      <table id="cloud_table" class="display">
        <thead><tr><th>Target</th><th>Detections</th></tr></thead>
        <tbody>
          {% for target, detections in report_data.cloud_detection.items() %}
          <tr>
            <td>{{ target }}</td>
            <td>{{ detections | join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Path Fuzzing Results</h2>
      <table id="fuzz_table" class="display">
        <thead><tr><th>Target</th><th>Path</th><th>Status Code</th></tr></thead>
        <tbody>
          {% for target, paths in report_data.path_fuzzing.items() %}
            {% for entry in paths %}
            <tr>
              <td>{{ target }}</td>
              <td>{{ entry.path }}</td>
              <td>{{ entry.status_code }}</td>
            </tr>
            {% endfor %}
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Supply Chain / Exposed Devices</h2>
      <table id="supply_table" class="display">
        <thead><tr><th>Target</th><th>Findings</th></tr></thead>
        <tbody>
          {% for target, findings in report_data.supply_chain.items() %}
          <tr>
            <td>{{ target }}</td>
            <td>{{ findings | join(', ') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      
      <h2>Vulnerability Chart</h2>
      <canvas id="vulnChart" width="600" height="400"></canvas>
      <script>
        // Prepare sample chart data: count vulnerabilities per module
        var chartData = {
          labels: ["Wayback JS", "GitHub", "Shodan"],
          datasets: [{
            label: 'Vulnerability Count',
            data: [
              {{ report_data.wayback_vuln|length }},
              {{ report_data.github_findings|length }},
              {{ report_data.shodan_results|length }}
            ],
            backgroundColor: [
              'rgba(255, 99, 132, 0.6)',
              'rgba(54, 162, 235, 0.6)',
              'rgba(255, 206, 86, 0.6)'
            ],
            borderWidth: 1
          }]
        };
        var ctx = document.getElementById('vulnChart').getContext('2d');
        var vulnChart = new Chart(ctx, {
          type: 'bar',
          data: chartData,
          options: {
            scales: {
              y: {
                beginAtZero: true
              }
            }
          }
        });
      </script>
      
      <script>
        $(document).ready( function () {
            $('#subdomains_table').DataTable();
            $('#vuln_table').DataTable();
            $('#cert_table').DataTable();
            $('#github_table').DataTable();
            $('#shodan_table').DataTable();
            $('#error_table').DataTable();
            $('#cloud_table').DataTable();
            $('#fuzz_table').DataTable();
            $('#supply_table').DataTable();
        });
      </script>
    </body>
    </html>
    """
    template = Template(template_str)
    html_content = template.render(report_data=report_data, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML Report generated: {output_filename}")
    except Exception as e:
        print(f"Error generating HTML report: {e}")

# ----------------------------
# Main Reporting Function
# ----------------------------
def generate_reports(report_data):
    """
    Main function to generate both PDF and HTML reports.
    Expects report_data to be a dictionary that aggregates data from all modules.
    """
    print("\nGenerating PDF report...")
    generate_pdf_report(report_data)
    print("\nGenerating HTML report...")
    generate_html_report(report_data)

# ----------------------------
# Standalone Main Function (for testing)
# ----------------------------
def main():
    """
    For standalone testing, this main() function loads a sample 'report_data.json'
    file from the current directory (if available) or uses sample data.
    """
    sample_file = "report_data.json"
    if os.path.isfile(sample_file):
        try:
            with open(sample_file, "r") as f:
                report_data = json.load(f)
            print("Loaded report data from report_data.json")
        except Exception as e:
            print(f"Error loading report_data.json: {e}")
            report_data = {}
    else:
        # Generate sample report_data for demonstration purposes.
        report_data = {
            "global_target": "example.com",
            "subdomains": ["blog.example.com", "shop.example.com"],
            "wayback_vuln": [
                {"url": "http://example.com/script.js", "findings": [["eval(", "MITRE T1059.001 - Command and Scripting Interpreter: JavaScript"]]}
            ],
            "cert_data": [
                {"target": "example.com", "certificate": {
                    "common_name": "example.com",
                    "issuer_name": "Let's Encrypt",
                    "entry_timestamp": "2023-04-01T12:00:00",
                    "names": ["example.com", "www.example.com"],
                    "resolved_ips": {"example.com": "93.184.216.34", "www.example.com": "93.184.216.34"}
                }}
            ],
            "github_findings": [
                {"target": "example.com", "keyword": "apikey", "query": "\"example.com\" apikey", "total_count": 2, "items": []}
            ],
            "shodan_results": [
                {"target": "example.com", "ip": "93.184.216.34", "org": "Example Org", "os": "N/A", "open_ports": [80,443], "vulnerabilities": ["CVE-XXXX-YYYY"], "location": {"city": "Los Angeles", "country_name": "United States"}}
            ],
            "screenshots": ["screenshots/gowitness-http_example_com.png"],
            "error_pages": [
                {"url": "http://example.com/404", "status_code": 404, "error_message": "Not Found"}
            ],
            "cloud_detection": {"example.com": ["Cloudflare"]},
            "path_fuzzing": {"example.com": [{"path": "/admin", "status_code": 200}]},
            "supply_chain": {"example.com": ["SCADA system indicator", "Default password exposed"]}
        }
    generate_reports(report_data)

if __name__ == "__main__":
    main()
