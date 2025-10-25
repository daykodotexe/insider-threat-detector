import psutil
import yaml
from colorama import Fore, Style, init
import time
import os
import json

init(autoreset=True)

# Paths for logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")

# Load previous logs if they exist
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
else:
    logs = []

def load_rules(file_path):
    """Load suspicious keywords from rules.yaml"""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)['suspicious_keywords']

def check_processes(rules):
    """Scan running processes and detect suspicious activity"""
    print(Fore.CYAN + "\n🔍 Scanning running processes...\n")
    found = False

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            for rule in rules:
                if rule.lower() in cmdline.lower():
                    found = True
                    print(Fore.RED + f"[ALERT] Suspicious process found:")
                    print(Fore.YELLOW + f"PID: {proc.info['pid']} | Name: {proc.info['name']}")
                    print(Fore.MAGENTA + f"Cmdline: {cmdline}\n")

                    # Log alert with timestamp
                    alert_entry = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmdline": cmdline,
                        "matched_keyword": rule,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    logs.append(alert_entry)
                    with open(LOG_FILE, "w") as f:
                        json.dump(logs, f, indent=2)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not found:
        print(Fore.GREEN + "✅ No suspicious processes found.\n")

if __name__ == "__main__":
    rules = load_rules("rules.yaml")
    while True:
        check_processes(rules)
        time.sleep(5)
