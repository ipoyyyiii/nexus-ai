FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:/opt/sqlmap:/opt/commix:/opt/tplmap:/opt/testssl:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    curl \
    git \
    unzip \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip -o nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install commix
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && ln -s /opt/commix/commix.py /usr/local/bin/commix

# Install dalfox
RUN wget -q https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-linux-x86_64.tar.gz \
    && tar -xzf dalfox-v3.1.2-linux-x86_64.tar.gz \
    && mv dalfox-v3.1.2-linux-x86_64/dalfox /usr/local/bin/ \
    && rm -rf dalfox-v3.1.2-linux-x86_64*

# Install tplmap
RUN git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap \
    && sed -i '1s|.*|#!/usr/bin/env python3|' /opt/tplmap/tplmap.py \
    && ln -s /opt/tplmap/tplmap.py /usr/local/bin/tplmap

# Install gobuster
RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    && tar -xzf gobuster_Linux_x86_64.tar.gz \
    && mv gobuster /usr/local/bin/ \
    && rm gobuster_Linux_x86_64.tar.gz

# Install ffuf
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && rm ffuf_2.1.0_linux_amd64.tar.gz

# Install testssl
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install arjun
RUN pip install --no-cache-dir arjun

# Install hydra
RUN apt-get update && apt-get install -y -qq hydra && apt-get clean

# Install katana
RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip \
    && unzip -o katana_1.1.0_linux_amd64.zip \
    && mv katana /usr/local/bin/ \
    && rm katana_1.1.0_linux_amd64.zip

# Install graphql-cop
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop

RUN pip install --no-cache-dir mitmproxy

# Install subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -o subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip

# Install hunter pipeline: httpx / naabu / gowitness / gau / hakrawler / amass
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip \
    && unzip -o httpx_1.6.0_linux_amd64.zip && mv httpx /usr/local/bin/ && rm httpx_1.6.0_linux_amd64.zip || echo "httpx install skipped"
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    && unzip -o naabu_2.3.1_linux_amd64.zip && mv naabu /usr/local/bin/ && rm naabu_2.3.1_linux_amd64.zip || echo "naabu install skipped"
RUN wget -q https://github.com/sensepost/gowitness/releases/download/2.4.2/gowitness-2.4.2-linux-amd64 -O /usr/local/bin/gowitness \
    && chmod +x /usr/local/bin/gowitness || echo "gowitness install skipped"
RUN wget -q https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz \
    && tar -xzf gau_2.2.4_linux_amd64.tar.gz && mv gau /usr/local/bin/ && rm gau_2.2.4_linux_amd64.tar.gz || echo "gau install skipped"
RUN wget -q https://github.com/hakluke/hakrawler/releases/download/2.1/hakrawler -O /usr/local/bin/hakrawler \
    && chmod +x /usr/local/bin/hakrawler || echo "hakrawler install skipped"
RUN wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip \
    && unzip -o amass_linux_amd64.zip && mv amass_linux_amd64/amass /usr/local/bin/ 2>/dev/null || mv amass /usr/local/bin/ 2>/dev/null; rm -rf amass_linux_amd64.zip amass_linux_amd64 || echo "amass install skipped"

# Install wordlists (with retry for flaky networks)
RUN for i in 1 2 3; do git clone --depth 1 --single-branch https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists && break || { echo "SecLists clone attempt $i failed"; rm -rf /opt/wordlists/SecLists; sleep 5; }; done

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir playwright \
    && playwright install chromium \
    && playwright install-deps

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin nexus \
    && mkdir -p /app/reports /app/data /tmp/nexus-home \
    && chown -R nexus:nexus /app /tmp/nexus-home

COPY --chown=nexus:nexus . .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]