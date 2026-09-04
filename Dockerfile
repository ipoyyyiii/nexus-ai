FROM golang:1.24-alpine@sha256:757779acac4af1b349a20f357c7296097b4a0b89da4ad0e370b339060077282a AS hakrawler-builder

ARG HAKRAWLER_COMMIT=61905593d82e8bac87ff7a7cca32b2adde42bb60
RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git clone --depth 1 --branch 2.1 https://github.com/hakluke/hakrawler.git /src/hakrawler \
    && test "$(git -C /src/hakrawler rev-parse HEAD)" = "${HAKRAWLER_COMMIT}" \
    && cd /src/hakrawler \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/hakrawler .

FROM python:3.11-slim@sha256:ff05d1a05204fb9f7444c435db8e8ec104e587a413280dc9ffc27a4797554182

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:/opt/sqlmap:/opt/commix:/opt/tplmap:/opt/testssl:${PATH}"
# Install Playwright browsers in a shared, read-only location.  The runtime
# containers deliberately run as UID 10001, so relying on /root/.cache makes
# browser workflows fail only after an approved run reaches the worker.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

WORKDIR /app

ARG SQLMAP_COMMIT=cef41c7fa2211434d5694e4338c4e3e443434133
ARG COMMIX_COMMIT=8530a48964007cb9561da47d45f396d9aef38ced
ARG TPLMAP_COMMIT=616b0e527f62dd0930e6346ede6bef79e9bcf717
ARG TESTSSL_COMMIT=1283aff3d49763dffe20bd47c664308c6ec076cf
ARG GRAPHQL_COP_COMMIT=2b7e086efae672f28b419c7fcdfe6b48d846c9dc
ARG SECLISTS_COMMIT=e9d6a61ead7193f05a16194252115da4abb33c0e
ARG WPSCAN_VERSION=3.8.28

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    curl \
    git \
    unzip \
    nmap \
    ruby-full \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip -o nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && git -C /opt/sqlmap fetch --depth 1 origin ${SQLMAP_COMMIT} \
    && git -C /opt/sqlmap checkout --detach ${SQLMAP_COMMIT} \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install commix
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && git -C /opt/commix fetch --depth 1 origin ${COMMIX_COMMIT} \
    && git -C /opt/commix checkout --detach ${COMMIX_COMMIT} \
    && ln -s /opt/commix/commix.py /usr/local/bin/commix

# Install dalfox
RUN wget -q https://github.com/hahwul/dalfox/releases/download/v3.1.2/dalfox-v3.1.2-linux-x86_64.tar.gz \
    && tar -xzf dalfox-v3.1.2-linux-x86_64.tar.gz \
    && mv dalfox-v3.1.2-linux-x86_64/dalfox /usr/local/bin/ \
    && rm -rf dalfox-v3.1.2-linux-x86_64*

# Install tplmap
RUN git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap \
    && git -C /opt/tplmap fetch --depth 1 origin ${TPLMAP_COMMIT} \
    && git -C /opt/tplmap checkout --detach ${TPLMAP_COMMIT} \
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
    && git -C /opt/testssl fetch --depth 1 origin ${TESTSSL_COMMIT} \
    && git -C /opt/testssl checkout --detach ${TESTSSL_COMMIT} \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl

# Install arjun
RUN pip install --no-cache-dir arjun

# Install hydra
RUN apt-get update && apt-get install -y -qq hydra && apt-get clean

# Install WPScan. Keep the version pinned so the external scanner is
# reproducible across backend and worker images.
RUN gem install wpscan --no-document --version "${WPSCAN_VERSION}" \
    && wpscan --version

# Install katana
RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip \
    && unzip -o katana_1.1.0_linux_amd64.zip \
    && mv katana /usr/local/bin/ \
    && rm katana_1.1.0_linux_amd64.zip

# Install graphql-cop
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && git -C /opt/graphql-cop checkout ${GRAPHQL_COP_COMMIT} \
    && ln -s /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop

RUN pip install --no-cache-dir mitmproxy

# Install subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -o subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip

# Install hunter pipeline: httpx / naabu / gowitness / gau / hakrawler / amass
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip \
    && unzip -o httpx_1.6.0_linux_amd64.zip && mv httpx /usr/local/bin/httpx-pd && rm httpx_1.6.0_linux_amd64.zip
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    && unzip -o naabu_2.3.1_linux_amd64.zip && mv naabu /usr/local/bin/ && rm naabu_2.3.1_linux_amd64.zip
RUN wget -q https://github.com/sensepost/gowitness/releases/download/2.4.2/gowitness-2.4.2-linux-amd64 -O /usr/local/bin/gowitness \
    && chmod +x /usr/local/bin/gowitness
RUN wget -q https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_amd64.tar.gz \
    && tar -xzf gau_2.2.4_linux_amd64.tar.gz && mv gau /usr/local/bin/ && rm gau_2.2.4_linux_amd64.tar.gz
COPY --from=hakrawler-builder /out/hakrawler /usr/local/bin/hakrawler
RUN chmod +x /usr/local/bin/hakrawler
RUN wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip \
    && unzip -o amass_linux_amd64.zip \
    && if [ -f amass_Linux_amd64/amass ]; then mv amass_Linux_amd64/amass /usr/local/bin/; \
       elif [ -f amass_linux_amd64/amass ]; then mv amass_linux_amd64/amass /usr/local/bin/; \
       elif [ -f amass ]; then mv amass /usr/local/bin/; \
       else echo 'Amass binary missing from pinned archive' >&2; exit 1; fi \
    && rm -rf amass_linux_amd64.zip amass_linux_amd64 amass_Linux_amd64

# Install wordlists (with retry for flaky networks)
RUN for i in 1 2 3; do \
      git clone --depth 1 --single-branch https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists \
      && git -C /opt/wordlists/SecLists fetch --depth 1 origin ${SECLISTS_COMMIT} \
      && git -C /opt/wordlists/SecLists checkout --detach ${SECLISTS_COMMIT} \
      && break \
      || { echo "SecLists clone attempt $i failed"; rm -rf /opt/wordlists/SecLists; sleep 5; }; \
    done

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir playwright \
    && PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright playwright install chromium \
    && playwright install-deps \
    && chmod -R a+rX /opt/ms-playwright

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin nexus \
    && mkdir -p /app/reports /app/data /tmp/nexus-home \
    && chown -R nexus:nexus /app /tmp/nexus-home

COPY --chown=nexus:nexus . .

# The API and worker never need root at runtime.  External scanners that need
# extra capability run only in the explicit raw-network profile.
USER nexus

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
