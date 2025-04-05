FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl git zip wget build-essential libssl-dev \
    dnsutils subfinder assetfinder \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY deep_recon_v2.py report_generator.py report_template.html entrypoint.sh ./

RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
