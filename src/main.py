import psutil
import yaml
from colorama import Fore, Style, init
import time
import os
import json
import re

init(autoreset=True)

# paths for logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")

# load previous logs if they exist
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
else:
    logs = []

# config
SCAN_INTERVAL = 5 
WHITELIST = ["explorer.exe", "chrome.exe", "svchost.exe"]  # processes to ignore

def load_rules(file_path):
    """
    load suspicious keywords from rules.yaml.
    expected format:
    suspicious_keywords:
      - keyword: "mimikatz"
        risk: "high"
      - keyword: "netstat"
        risk: "low"
    """
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)['suspicious_keywords']
        
        rules_dict = {item['keyword']: item.get('risk', 'medium') for item in data}
        return rules_dict

def check_processes(rules):
    """scan running processes and detect suspicious activity"""
    print(Fore.CYAN + "\n🔍 scanning running processes...\n")
    found = False

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info['name']
            if not name or name.lower() in WHITELIST:
                continue

            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''

            for rule, risk in rules.items():
                
                if rule.lower() in cmdline.lower() or re.search(r'-enc [A-Za-z0-9+/=]{20,}', cmdline):
                    found = True
                    color = Fore.GREEN
                    if risk.lower() == 'medium':
                        color = Fore.YELLOW
                    elif risk.lower() == 'high':
                        color = Fore.RED

                    # alerts
                    if color == Fore.GREEN:
                        print(color + f"[alert] suspicious process found:")
                        print(color + f"pid: {proc.info['pid']} | name: {name.lower()}")
                        print(color + f"cmdline: {cmdline.lower()}")
                        print(color + f"matched keyword: {rule.lower()} | risk: {risk.lower()}\n")
                    else:
                        print(color + f"[alert] suspicious process found:")
                        print(Fore.YELLOW + f"PID: {proc.info['pid']} | Name: {name}")
                        print(Fore.MAGENTA + f"Cmdline: {cmdline}")
                        print(Fore.CYAN + f"Matched keyword: {rule} | Risk: {risk}\n")

                    
                    alert_entry = {
                        "pid": proc.info['pid'],
                        "name": name,
                        "cmdline": cmdline,
                        "matched_keyword": rule,
                        "risk": risk,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    logs.append(alert_entry)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # save all logs after scanning
    if found:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    else:
        print(Fore.GREEN + "✅ no suspicious processes found.\n")

if __name__ == "__main__":
    rules = load_rules("rules.yaml")
    try:
        while True:
            check_processes(rules)
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\nexiting insider threat detector. stay safe!")
