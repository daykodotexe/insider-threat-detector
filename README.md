# Insider Threat Detector v1.0

A lightweight Windows-based monitoring tool that identifies potentially malicious activity by scanning running processes and analyzing command-line arguments using **psutil** and **YAML-based rules**.

## Features

* Real‑time process scanning
* Detection of 100+ suspicious commands (PowerShell, certutil, mimikatz, curl, bitsadmin, etc.)
* Risk level classification: low / medium / high for each keyword
* Whitelist support to reduce false positives (e.g., explorer.exe, chrome.exe)
* Configurable scan interval (`SCAN_INTERVAL`)
* Ctrl+C exits cleanly
* JSON logging with timestamps (`logs/alerts.json`)
* Easy to customize detection rules (`rules.yaml`)
* Detection of encoded PowerShell commands
* Fully Windows‑compatible

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/daykodotexe/insider-threat-detector.git
cd insider-threat-detector
```

### 2. (Optional) Create and activate a virtual environment

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1    # PowerShell
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the detector:

```bash
python src/main.py
```

Alerts will appear in:

```
logs/alerts.json
```

## Custom Rules

Modify `rules.yaml` to add or remove suspicious keywords.

* Each keyword can have a risk level: low / medium / high
* Changes take effect immediately on next scan
* No code changes needed

Example:

```yaml
suspicious_keywords:
  - keyword: "mimikatz"
    risk: "high"
  - keyword: "netstat"
    risk: "low"
  - keyword: "powershell"
    risk: "medium"
```


