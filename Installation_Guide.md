# 🛠 Installation Guide

ReconEngine requires several open-source reconnaissance tools.
To simplify installation, a **`setup.sh` script** is provided that installs and configures all dependencies automatically.

> ⚠️ **Root access is required only for installation**, not for running the framework.

---

## 📋 System Requirements

* **OS:** Kali Linux / Ubuntu (22.04+ recommended)
* **Python:** 3.9+
* **Privileges:** Root access (for setup only)
* **Internet:** Required during installation

---

## 📦 Installation Steps

### 1️⃣ Clone the Repository

```bash
git clone git@github.com:chanakayaa/r3c0n_engin3.git
cd r3c0n_engin3
```

---

### 2️⃣ Run Setup Script (Required – as your normal user)

The setup script installs all required tools and dependencies. **Do not run it
with `sudo`** — it calls `sudo` itself only for the apt packages, so the Go
tools install into *your* `~/go/bin` (running it as root would put them in
`/root/go/bin`, off your PATH).

```bash
chmod +x setup.sh
bash setup.sh
```

When it finishes, open a new shell (or `source ~/.bashrc`) so `~/go/bin` is on
your PATH, then verify:

```bash
which subfinder httpx nmap nuclei
```

🔹 This will install:

* Python dependencies
* `httpx`
* `subfinder`
* `assetfinder`
* `amass`
* `dnsx`
* `asnmap`
* `wafw00f`
* `whatweb`
* `sslscan`
* `katana`
* `feroxbuster`
* `theHarvester`
* `nmap`
* Other supporting utilities

⏳ Installation may take several minutes depending on network speed.

---

### 3️⃣ Verify Installation

After setup completes, you should be able to run:

```bash
httpx -h
whatweb -h
nmap --version
```

If these commands work, setup is successful ✅

---

## 🚀 Running ReconEngine

### 4️⃣ Run Recon (Normal User)

> ❗ **Do NOT run recon as root unless required for specific scans**

```bash
python3 asm.py scan -t example.com --crawl --dirs
```

📂 Output will be generated under:

```text
results/example.com_TIMESTAMP/
```

---

## 📊 Generate the Detailed Report

### 5️⃣ Generate HTML Report (After Recon Completes)

Once recon finishes, generate the interactive report:

```bash
python3 report.py results/example.com_TIMESTAMP
```

---

### 6️⃣ View the Report

Open the report in a browser:

```bash
firefox results/example.com_TIMESTAMP/reports/detailed_report.html
```

The report includes:

* Executive summary
* Expandable module-wise results
* Terminal-style raw evidence
* Scan outputs

---

## 🧹 Optional: Re-run Setup

If tools are missing or broken, re-run:

```bash
bash setup.sh
```

---

## ⚠️ Important Notes

* **Authorized testing only**
* Some tools may rate-limit or behave differently on corporate networks
* Use VPN / lab environment when required
* ASNMAP would require one API Key so set the key before running the script
* Run ASNMAP it would guide you to get the FreeAPI Key

---

## 🧠 Tip (Best Practice)

```bash
# Install the toolchain once (as your normal user, NOT sudo)
bash setup.sh

# Run an ASM pass, then view the prioritized findings / report
python3 asm.py scan -t target.com
python3 asm.py findings -t target.com --min-severity medium
python3 asm.py report -t target.com -o report.html
```

---

## 🛑 Disclaimer

> ReconEngine is intended **only for authorized security testing**.
> The author is not responsible for misuse or illegal activity.


