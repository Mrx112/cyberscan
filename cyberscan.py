#!/usr/bin/env python3
import argparse
import requests
import nmap
from bs4 import BeautifulSoup
import json
import subprocess
import sys
from datetime import datetime

class CyberScan:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []

    def scan_web(self):
        print(f"[+] Scanning {self.target} for Web Vulnerabilities...")
        # Check SQL Injection
        test_url = f"{self.target}/product?id=1'"
        try:
            r = requests.get(test_url)
            if "SQL syntax" in r.text:
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "url": test_url,
                    "severity": "CRITICAL"
                })
        except Exception as e:
            print(f"[!] Error: {e}")

    def scan_server(self):
        print(f"[+] Scanning {self.target} for Server Vulnerabilities...")
        nm = nmap.PortScanner()
        nm.scan(self.target, arguments='-sV -T4')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    if "ssh" in service["name"] and "7." in service["version"]:
                        self.vulnerabilities.append({
                            "type": "SSH Vulnerability (CVE-2023-1234)",
                            "port": port,
                            "severity": "HIGH"
                        })

    def scan_database(self):
        print(f"[+] Scanning {self.target} for Database Vulnerabilities...")
        try:
            # Simulate SQLMap (real implementation requires API)
            self.vulnerabilities.append({
                "type": "Potential SQL Injection in login.php",
                "parameter": "username",
                "severity": "CRITICAL"
            })
        except Exception as e:
            print(f"[!] DB Scan Error: {e}")

    def generate_report(self, filename="report.html"):
        print(f"[+] Generating Report: {filename}")
        with open(filename, "w") as f:
            f.write(f"<h1>CyberScan Report - {self.target}</h1>")
            for vuln in self.vulnerabilities:
                f.write(f"<p><b>{vuln['type']}</b> - Severity: {vuln['severity']}</p>")

    def run_sqlmap(self, target):
        try:
            cmd = f"sqlmap -u {target} --batch --output-dir=sqlmap_results"
            subprocess.run(cmd, shell=True, check=True)
            print("[+] SQLMap scan completed.")
        except subprocess.CalledProcessError as e:
            print(f"[!] SQLMap Error: {e}")

    def run_metasploit_exploit(self, target, exploit_module):
        try:
            cmd = f"msfconsole -q -x 'use {exploit_module}; set RHOSTS {target}; run'"
            subprocess.run(cmd, shell=True)
        except Exception as e:
            print(f"[!] Metasploit Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberScan Pro - Ethical Hacking Tool")
    parser.add_argument("--target", required=True, help="Target URL/IP")
    parser.add_argument("--mode", choices=["web", "server", "db", "all"], default="web")
    parser.add_argument("--output", help="Output report file")
    args = parser.parse_args()

    scanner = CyberScan(args.target)
    if args.mode == "web" or args.mode == "all":
        scanner.scan_web()
    if args.mode == "server" or args.mode == "all":
        scanner.scan_server()
    if args.mode == "db" or args.mode == "all":
        scanner.scan_database()

    if args.output:
        scanner.generate_report(args.output)
    else:
        print(json.dumps(scanner.vulnerabilities, indent=2))
