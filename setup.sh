#!/bin/bash

# This script installs all required tools for the automation framework

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "============================================"
echo "   R3c0n_engin3 - Setup Script"
echo "   Installing Modules"
echo "============================================"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}" 
   exit 1
fi

# Update system
echo -e "${YELLOW}[*] Updating system packages...${NC}"
apt update -y
apt upgrade -y

# Install dependencies
echo -e "${YELLOW}[*] Installing dependencies...${NC}"
apt install -y \
    git \
    python3 \
    python3-pip \
    golang-go \
    wget \
    curl \
    unzip \
    chromium \
    chromium-driver \
    build-essential \
    libpcap-dev

# Setup Go environment
echo -e "${YELLOW}[*] Setting up Go environment...${NC}"
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Install Python packages
echo -e "${YELLOW}[*] Installing Python packages...${NC}"
pip3 install --upgrade pip
pip3 install colorama requests beautifulsoup4 dnspython

# Create tools directory
TOOLS_DIR="$HOME/bug-bounty-tools"
mkdir -p $TOOLS_DIR
cd $TOOLS_DIR

echo -e "${GREEN}[+] Installing tools in $TOOLS_DIR${NC}"

# ============ SUBDOMAIN ENUMERATION ============
echo -e "${YELLOW}[*] Installing Subdomain Enumeration Tools...${NC}"

# Subfinder
echo "Installing subfinder..."
go install -v 
github.com
/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
echo "Installing amass..."
go install -v 
github.com
/owasp-amass/amass/v4/...@master

# Assetfinder
echo "Installing assetfinder..."
go install 
github.com
/tomnomnom/assetfinder@latest

# Findomain
echo "Installing findomain..."
wget 
https://github.com/
Findomain/Findomain/releases/latest/download/
findomain-linux-i386.zip
unzip 
findomain-linux-i386.zip
chmod +x findomain
mv findomain /usr/local/bin/
rm 
findomain-linux-i386.zip

# dnsx
echo "Installing dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# ============ PORT SCANNING ============
echo -e "${YELLOW}[*] Installing Port Scanning Tools...${NC}"

# Naabu
echo "Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nmap (usually pre-installed on Kali)
apt install -y nmap

# RustScan
echo "Installing rustscan..."
wget 
https://github.com/
RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
dpkg -i rustscan_2.1.1_amd64.deb || apt-get install -f -y
rm rustscan_2.1.1_amd64.deb

# ============ HTTP PROBING ============
echo -e "${YELLOW}[*] Installing HTTP Tools...${NC}"

# httpx
echo "Installing httpx..."
go install -v 
github.com
/projectdiscovery/httpx/cmd/httpx@latest

# ============ CRAWLING & CONTENT DISCOVERY ============
echo -e "${YELLOW}[*] Installing Crawling Tools...${NC}"

# Katana
echo "Installing katana..."
go install 
github.com
/projectdiscovery/katana/cmd/katana@latest

# Gospider
echo "Installing gospider..."
go install 
github.com
/jaeles-project/gospider@latest

# Waybackurls
echo "Installing waybackurls..."
go install 
github.com
/tomnomnom/waybackurls@latest

# Gau
echo "Installing gau..."
go install 
github.com
/lc/gau/v2/cmd/gau@latest

# Hakrawler
echo "Installing hakrawler..."
go install 
github.com
/hakluke/hakrawler@latest

# ============ PARAMETER DISCOVERY ============
echo -e "${YELLOW}[*] Installing Parameter Tools...${NC}"

# Paramspider
echo "Installing paramspider..."
git clone 
https://github.com/
devanshbatham/ParamSpider
cd ParamSpider
pip3 install .
cd ..

# Arjun
echo "Installing arjun..."
pip3 install arjun

# ============ FUZZING ============
echo -e "${YELLOW}[*] Installing Fuzzing Tools...${NC}"

# ffuf
echo "Installing ffuf..."
go install 
github.com
/ffuf/ffuf/v2@latest

# ============ JAVASCRIPT ANALYSIS ============
echo -e "${YELLOW}[*] Installing JavaScript Tools...${NC}"

# LinkFinder
echo "Installing linkfinder..."
git clone 
https://github.com/
GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
python3 
setup.py
 install
cd ..

# subjs
echo "Installing subjs..."
go install 
github.com
/lc/subjs@latest

# ============ VULNERABILITY SCANNERS ============
echo -e "${YELLOW}[*] Installing Vulnerability Scanners...${NC}"

# Nuclei
echo "Installing nuclei..."
go install -v 
github.com
/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Nuclei Templates
echo "Installing nuclei templates..."
nuclei -update-templates

# Dalfox (XSS Scanner)
echo "Installing dalfox..."
go install 
github.com
/hahwul/dalfox/v2@latest

# SQLMap
echo "Installing sqlmap..."
apt install -y sqlmap

# XSStrike
echo "Installing xsstrike..."
git clone 
https://github.com/
s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt
cd ..

# Corsy (CORS Scanner)
echo "Installing corsy..."
git clone 
https://github.com/
s0md3v/Corsy.git
cd Corsy
pip3 install -r requirements.txt
cd ..

# ============ UTILITY TOOLS ============
echo -e "${YELLOW}[*] Installing Utility Tools...${NC}"

# anew (for deduplication)
echo "Installing anew..."
go install -v 
github.com
/tomnomnom/anew@latest

# uro (URL deduplication)
echo "Installing uro..."
pip3 install uro

# qsreplace
echo "Installing qsreplace..."
go install 
github.com
/tomnomnom/qsreplace@latest

# unfurl
echo "Installing unfurl..."
go install 
github.com
/tomnomnom/unfurl@latest

# jq (JSON processor)
apt install -y jq

# ============ WORDLISTS ============
echo -e "${YELLOW}[*] Installing Wordlists...${NC}"

# SecLists
echo "Installing SecLists..."
git clone 
https://github.com/
danielmiessler/SecLists.git /usr/share/wordlists/SecLists

# ============ CLEANUP ============
echo -e "${YELLOW}[*] Cleaning up...${NC}"
apt autoremove -y
apt autoclean -y

# Set permissions
chmod +x /usr/local/bin/* 2>/dev/null

echo -e "${GREEN}"
echo "============================================"
echo "   Installation Complete!"
echo "============================================"
echo -e "${NC}"
echo -e "${GREEN}[+] All tools installed successfully!${NC}"
echo -e "${YELLOW}[!] Please run: source ~/.bashrc${NC}"
echo -e "${YELLOW}[!] Or restart your terminal for changes to take effect${NC}"
echo ""
echo -e "${GREEN}Installed tools location: $TOOLS_DIR${NC}"
echo -e "${GREEN}Go binaries location: $GOPATH/bin${NC}"
echo ""
echo -e "${YELLOW}To verify installation, run:${NC}"
echo "  subfinder -version"
echo "  nuclei -version"
echo "  httpx -version"
echo ""
echo -e "${GREEN}Ready to use BugHunter Pro!${NC}"
