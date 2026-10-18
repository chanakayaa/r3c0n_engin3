#!/usr/bin/env bash
#
# ReconEngine ASM - toolchain installer (Debian / Ubuntu / Kali / WSL)
#
# Installs the external CLIs the recon + scan pipeline drives. Run it as your
# NORMAL user (NOT with sudo) - it calls sudo itself only for apt packages, so
# the Go tools land in *your* ~/go/bin instead of /root/go/bin.
#
#   bash setup.sh
#
set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${YELLOW}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
err()   { echo -e "${RED}[!]${NC} $*"; }

echo -e "${GREEN}"
echo "============================================"
echo "   ReconEngine ASM - Toolchain Setup"
echo "============================================"
echo -e "${NC}"

# --- Must NOT be root: Go tools must install into the real user's home -------
if [ "$(id -u)" -eq 0 ]; then
    err "Run this as your normal user, not with sudo."
    err "It will call sudo itself for apt. Otherwise Go tools install to"
    err "/root/go/bin and won't be on your PATH."
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    err "This installer targets Debian/Ubuntu/Kali (apt). For other distros,"
    err "install the tools listed in the README manually."
    exit 1
fi

SUDO="sudo"

# ============ APT PACKAGES ====================================================
info "Installing base packages via apt (you may be prompted for your password)"
$SUDO apt-get update -y
$SUDO apt-get install -y \
    git curl wget unzip jq \
    golang-go \
    nmap whois dnsutils \
    sslscan whatweb \
    python3 python3-pip pipx \
    build-essential libpcap-dev \
    || err "some apt packages failed - continuing"

# feroxbuster ships in apt on newer Ubuntu/Kali; best-effort.
$SUDO apt-get install -y feroxbuster 2>/dev/null \
    && ok "feroxbuster installed" \
    || err "feroxbuster not in apt here - install from its releases if needed"

# ============ GO ENVIRONMENT ==================================================
export GOPATH="${GOPATH:-$HOME/go}"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:$GOBIN"
mkdir -p "$GOBIN"

if ! command -v go >/dev/null 2>&1; then
    err "Go is not available even after apt; cannot install Go-based tools."
else
    ok "Using $(go version)"
fi

# ============ GO TOOLS ========================================================
# name<TAB>module@version  (install loop continues past individual failures)
GO_TOOLS=(
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
  "assetfinder|github.com/tomnomnom/assetfinder@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "anew|github.com/tomnomnom/anew@latest"
  "qsreplace|github.com/tomnomnom/qsreplace@latest"
  "unfurl|github.com/tomnomnom/unfurl@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "ffuf|github.com/ffuf/ffuf/v2@latest"
  "dalfox|github.com/hahwul/dalfox/v2@latest"
  "gospider|github.com/jaeles-project/gospider@latest"
  "hakrawler|github.com/hakluke/hakrawler@latest"
  "subjs|github.com/lc/subjs@latest"
)

if command -v go >/dev/null 2>&1; then
    for entry in "${GO_TOOLS[@]}"; do
        name="${entry%%|*}"; mod="${entry##*|}"
        info "go install $name"
        GOBIN="$GOBIN" go install -v "$mod" 2>/dev/null \
            && ok "$name" || err "$name failed (skipped)"
    done

    # amass is large; install separately so a failure doesn't stop the rest.
    info "go install amass (large, may take a while)"
    GOBIN="$GOBIN" go install -v github.com/owasp-amass/amass/v4/...@master \
        2>/dev/null && ok "amass" || err "amass failed (optional, skipped)"
fi

# ============ PYTHON CLI TOOLS (via pipx, PEP 668-safe) =======================
if command -v pipx >/dev/null 2>&1; then
    pipx ensurepath >/dev/null 2>&1 || true
    for pkg in theHarvester wafw00f arjun uro; do
        info "pipx install $pkg"
        pipx install "$pkg" >/dev/null 2>&1 && ok "$pkg" \
            || err "$pkg failed (skipped)"
    done
else
    err "pipx unavailable; skipping theHarvester/wafw00f/arjun/uro"
fi

# ============ NUCLEI TEMPLATES ================================================
if command -v nuclei >/dev/null 2>&1; then
    info "Updating nuclei templates"
    nuclei -update-templates -silent 2>/dev/null && ok "nuclei templates updated" \
        || err "nuclei template update failed (run 'nuclei -update-templates' later)"
fi

# ============ PATH PERSISTENCE ===============================================
RC="$HOME/.bashrc"; [ -n "${ZSH_VERSION:-}" ] && RC="$HOME/.zshrc"
if ! grep -q 'go/bin' "$RC" 2>/dev/null; then
    {
        echo ''
        echo '# ReconEngine ASM toolchain'
        echo 'export GOPATH=$HOME/go'
        echo 'export PATH=$PATH:$HOME/go/bin'
    } >> "$RC"
    ok "Added \$HOME/go/bin to PATH in $RC"
fi

# ============ VERIFY ==========================================================
echo ""
info "Verifying core tools (needed by the ASM pipeline):"
MISSING=0
for t in subfinder httpx dnsx nmap nuclei whatweb sslscan; do
    if command -v "$t" >/dev/null 2>&1 || [ -x "$GOBIN/$t" ]; then
        ok "$t"
    else
        err "$t MISSING"; MISSING=$((MISSING+1))
    fi
done

echo ""
echo -e "${GREEN}============================================${NC}"
ok "Setup finished."
echo -e "${YELLOW}[!] Open a new shell or run:  source $RC${NC}"
echo -e "${YELLOW}[!] Then verify:  which subfinder httpx nmap nuclei${NC}"
[ "$MISSING" -gt 0 ] && err "$MISSING core tool(s) missing - re-run or install them manually."
echo -e "${GREEN}============================================${NC}"
