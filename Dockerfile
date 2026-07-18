FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:/opt/sqlmap:/opt/commix:/opt/tplmap:/opt/testssl:/opt/jwt_tool:${PATH}"

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

# Install jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

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

# Install subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -o subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip

# Install wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir playwright \
    && playwright install chromium \
    && playwright install-deps

COPY . .

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]