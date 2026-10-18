# ReconEngine ASM — all-in-one image (engine + recon toolchain + web UI/API).
#
#   docker build -t reconengine-asm .
#   docker run -p 8000:8000 -v asm-data:/data reconengine-asm
#
# The ASM engine is pure stdlib; this image also bakes in the external scanners
# (subfinder/httpx/dnsx/nuclei/katana/naabu + nmap) so a container is a complete
# scanning node out of the box.

FROM golang:1.23-bookworm AS tools
ENV GOBIN=/tools
RUN mkdir -p /tools && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest

FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 ASM_DB=/data/asm.db
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap whois dnsutils ca-certificates libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tools /tools/* /usr/local/bin/
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && \
    (nuclei -update-templates -silent || true) && \
    useradd -m -u 10001 asm && mkdir -p /data && chown -R asm /data
USER asm
VOLUME ["/data"]
EXPOSE 8000
# Bind to all interfaces inside the container; publish/protect at the edge.
CMD ["python", "-m", "asm", "serve", "--host", "0.0.0.0", "--port", "8000", "--db", "/data/asm.db"]
