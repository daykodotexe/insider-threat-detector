# Insider Threat Detector

Detect suspicious processes on Windows by scanning running processes and matching command-line keywords (psutil + yaml).

## Features
- Scans running processes in real-time
- Detects suspicious commands like PowerShell, certutil, mimikatz, etc.
- Logs alerts with timestamps to `logs/alerts.json`
- Fully Windows-compatible

## Installation
1. Clone the repo:
git clone <your-repo-url>
Create and activate a virtual environment (optional but recommended):

bash
python -m venv .venv
.venv\Scripts\Activate.ps1   # PowerShell
Install dependencies:

bash
pip install -r requirements.txt