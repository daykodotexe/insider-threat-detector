# Insider Threat Detector

A lightweight Windows-based monitoring tool that identifies potentially malicious activity by scanning running processes and analyzing command-line arguments using **psutil** and **YAML-based rules**.

## Features

* Real‑time process scanning
* Detection of suspicious commands (PowerShell, certutil, mimikatz, etc.)
* JSON logging with timestamps (`logs/alerts.json`)
* Easy to customize detection rules (`rules.yaml`)
* Fully Windows‑compatible

## Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
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
python main.py
```

Alerts will appear in:

```
logs/alerts.json
```

## Custom Rules

Modify `rules.yaml` to add or remove suspicious keywords.
New keywords are detected automatically—no code changes needed.
