import os
import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from jinja2 import Template

def save_json_report(data, base_path):
    out_path = base_path + ".json"
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Saved JSON report to {out_path}")
    return out_path

def save_csv_report(data, base_path):
    out_path = base_path + ".csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Module", "Key", "Field", "Value"])
        for module, content in data.items():
            if isinstance(content, dict):
                for key, fields in content.items():
                    if isinstance(fields, list):
                        for item in fields:
                            for k, v in item.items():
                                writer.writerow([module, key, k, v])
                    elif isinstance(fields, dict):
                        for k, v in fields.items():
                            writer.writerow([module, key, k, v])
                    else:
                        writer.writerow([module, key, "", fields])
            elif isinstance(content, list):
                for idx, item in enumerate(content):
                    if isinstance(item, dict):
                        for k, v in item.items():
                            writer.writerow([module, f"item_{idx}", k, v])
                    else:
                        writer.writerow([module, f"item_{idx}", "", item])
    logging.info(f"Saved CSV report to {out_path}")
    return out_path

def save_html_report(data, base_path):
    out_path = base_path + ".html"
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Deep Recon Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 2em; }
            h2 { background: #333; color: #fff; padding: 0.5em; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 2em; background: #fff; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background: #555; color: white; }
            tr:nth-child(even) { background-color: #eee; }
        </style>
    </head>
    <body>
        <h1>Deep Recon Report</h1>
        {% for module, results in data.items() %}
            <h2>{{ module }}</h2>
            {% if results is mapping %}
                <table>
                    <thead><tr><th>Key</th><th>Field</th><th>Value</th></tr></thead>
                    <tbody>
                    {% for key, fields in results.items() %}
                        {% if fields is mapping %}
                            {% for field, val in fields.items() %}
                                <tr><td>{{ key }}</td><td>{{ field }}</td><td>{{ val }}</td></tr>
                            {% endfor %}
                        {% elif fields is iterable %}
                            {% for item in fields %}
                                {% if item is mapping %}
                                    {% for field, val in item.items() %}
                                        <tr><td>{{ key }}</td><td>{{ field }}</td><td>{{ val }}</td></tr>
                                    {% endfor %}
                                {% else %}
                                    <tr><td>{{ key }}</td><td colspan="2">{{ item }}</td></tr>
                                {% endif %}
                            {% endfor %}
                        {% else %}
                            <tr><td>{{ key }}</td><td colspan="2">{{ fields }}</td></tr>
                        {% endif %}
                    {% endfor %}
                </tbody>
                </table>
            {% elif results is iterable %}
                <table>
                    <thead><tr><th>Item</th><th>Value</th></tr></thead>
                    <tbody>
                    {% for item in results %}
                        {% if item is mapping %}
                            {% for field, val in item.items() %}
                                <tr><td>{{ field }}</td><td>{{ val }}</td></tr>
                            {% endfor %}
                        {% else %}
                            <tr><td colspan="2">{{ item }}</td></tr>
                        {% endif %}
                    {% endfor %}
                </tbody>
                </table>
            {% else %}
                <p>{{ results }}</p>
            {% endif %}
        {% endfor %}
    </body>
    </html>
    """
    template = Template(html_template)
    rendered = template.render(data=data)
    with open(out_path, "w") as f:
        f.write(rendered)
    logging.info(f"Saved HTML report to {out_path}")
    return out_path

def generate_reports(shared_data, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    base = shared_data.get("report_filename", "deep_recon_report")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = os.path.join(output_dir, f"{base}_{timestamp}")

    paths = {
        "html": save_html_report(shared_data, base_path),
        "csv": save_csv_report(shared_data, base_path),
        "json": save_json_report(shared_data, base_path)
    }
    return paths
