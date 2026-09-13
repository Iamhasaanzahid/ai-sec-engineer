#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY AI SECURITY ENGINEER - AUTONOMOUS AGENT SYSTEM v22.0 (Full Human-Analyst Feature Set)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Author: Muhammad Hassaan Zahid

WHAT'S NEW IN v22.0 vs v21.2
──────────────────────────────
A human SOC/pentest analyst doing a legitimate, authorized recon engagement
typically does more than DNS + banner + CVE lookup. This version adds the
rest of that workflow as additional autonomous agents, all still passive
or lightly-active (no exploitation, no brute force, no credential attacks):

  Agent 1  - Reconnaissance (DNS, subdomains, banners)           [existing, kept]
  Agent 2  - WHOIS / Domain Intelligence                         [NEW]
  Agent 3  - TLS/SSL Certificate & Cipher Analysis                [NEW]
  Agent 4  - HTTP Security Header Grading (A-F, like securityheaders.com) [NEW]
  Agent 5  - Lightweight Port Reconnaissance (top 20 TCP ports)   [NEW]
  Agent 6  - WAF / CDN Fingerprinting                             [NEW]
  Agent 7  - Sensitive-Path Exposure Check (robots.txt, .env, .git/, etc.) [NEW]
  Agent 8  - IP Geolocation & ASN Context                         [NEW]
  Agent 9  - Threat Intelligence Triage (VirusTotal, AbuseIPDB)   [existing, kept]
  Agent 10 - NVD Vulnerability Correlation                        [existing, kept]
  Agent 11 - Attack-Surface Risk Scoring (weighted composite)      [NEW]
  Agent 12 - AI Executive Remediation Strategy (Groq LLM)         [existing, kept]

Safety posture (unchanged / strengthened):
  - Hard SSRF guard: refuses private/loopback/link-local/reserved/multicast IPs.
  - No exploitation, no payload delivery, no brute-forcing, no credential attacks.
  - Port check is a plain TCP connect probe on a short, fixed allow-list of
    well-known ports - equivalent to what any browser/curl does - not a
    scanner sweep.
  - Sensitive-path check only requests well-known static paths (robots.txt,
    sitemap.xml, .env, .git/HEAD, etc.) with GET and reports only HTTP status
    + content-length, never dumps file content.
  - Every module is meant for infrastructure you are authorized to test
    (your own assets or in-scope bug bounty targets). Users are responsible
    for authorization.
"""

import streamlit as st
import requests
import pandas as pd
import json
import logging
import time
import ipaddress
import ssl
import socket
import re
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Any, Callable, Tuple
from dataclasses import dataclass, asdict, field

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

# ==========================================
# 0. CORE SAFETY & CONFIGURATION
# ==========================================

class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass


def assert_public_host(hostname: str) -> None:
    """SSRF guard using standard socket library."""
    try:
        clean_host = hostname.replace('https://', '').replace('http://', '').split('/')[0]
        infos = socket.getaddrinfo(clean_host, None)
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                raise ScopeViolation(f"Target '{hostname}' resolves to non-public IP ({ip_str}).")
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host: {e}")


def with_retry(fn: Callable, *args, retries: int = 3, backoff: float = 2.0, **kwargs):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
            else:
                logger.error(f"Max retries reached: {e}")
        except Exception as e:
            raise e
    raise last_exc


# Fixed, small, well-known port allow-list — this is reconnaissance, not a scanner sweep.
COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/wp-config.php.bak",
    "/config.json", "/.aws/credentials", "/.DS_Store", "/backup.zip",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/server-status", "/phpinfo.php", "/.htpasswd", "/id_rsa",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": 15,
    "Content-Security-Policy": 20,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "X-XSS-Protection": 5,
}

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "aws waf / cloudfront": ["x-amz-cf-id", "x-amzn-requestid"],
    "imperva / incapsula": ["x-iinfo", "incap_ses"],
    "f5 big-ip asm": ["x-waf-event-info", "big-ip"],
}

# ==========================================
# 1. DATA MODELS & SCHEMAS
# ==========================================

@dataclass
class VulnerabilityRecord:
    cve_id: str
    title: str
    cvss_score: float
    severity: str
    description: str
    remediation: str
    match_confidence: str


@dataclass
class AgenticReasoning:
    agent: str
    task: str
    evidence: str
    interpretation: str
    confidence: str


@dataclass
class PortResult:
    port: int
    service: str
    open: bool
    banner: str = ""


@dataclass
class PathCheckResult:
    path: str
    status_code: int
    content_length: int
    exposed: bool


# ==========================================
# 2. AI / DATA CONNECTORS (APIs)
# ==========================================

class AIConnectors:
    def __init__(self):
        self.vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
        self.nvd_key = st.secrets.get("NVD_API_KEY", "")
        self.groq_key = st.secrets.get("GROQ_API_KEY", "")
        self.shodan_key = st.secrets.get("SHODAN_API_KEY", "")
        self.hibp_key = st.secrets.get("HIBP_API_KEY", "")

    def query_virustotal(self, indicator: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {"error": "VirusTotal API Key missing."}
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip else \
              f"https://www.virustotal.com/api/v3/domains/{indicator}"
        try:
            resp = with_retry(requests.get, url, headers={'x-apikey': self.vt_key}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"VT Error: {resp.status_code}"}
        except Exception as e:
            return {"error": f"VT Connection Failed: {e}"}

    def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.abuse_key:
            return {"error": "AbuseIPDB API Key missing."}
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return {"error": "Invalid IP format."}
        try:
            resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                               headers={'Key': self.abuse_key, 'Accept': 'application/json'},
                               params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"AbuseIPDB Error: {resp.status_code}"}
        except Exception as e:
            return {"error": f"AbuseIPDB Connection Failed: {e}"}

    def query_shodan(self, ip: str) -> Dict[str, Any]:
        if not self.shodan_key:
            return {"error": "Shodan API Key missing (optional)."}
        try:
            resp = with_retry(requests.get, f"https://api.shodan.io/shodan/host/{ip}",
                               params={"key": self.shodan_key}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"Shodan Error: {resp.status_code}"}
        except Exception as e:
            return {"error": f"Shodan Connection Failed: {e}"}

    def query_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Free, no-key IP geolocation + ASN context via ip-api.com."""
        try:
            resp = with_retry(requests.get, f"http://ip-api.com/json/{ip}",
                               params={"fields": "status,country,regionName,city,isp,org,as,query"},
                               timeout=8)
            return resp.json() if resp.status_code == 200 else {"error": f"Geo Error: {resp.status_code}"}
        except Exception as e:
            return {"error": f"Geo Connection Failed: {e}"}

    def query_whois(self, domain: str) -> Dict[str, Any]:
        """Lightweight WHOIS via RDAP (no extra dependency needed)."""
        try:
            resp = with_retry(requests.get, f"https://rdap.org/domain/{domain}", timeout=10)
            if resp.status_code != 200:
                return {"error": f"RDAP Error: {resp.status_code}"}
            data = resp.json()
            events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
            registrar = "Unknown"
            for entity in data.get('entities', []):
                if 'registrar' in entity.get('roles', []):
                    vcard = entity.get('vcardArray', [None, []])[1]
                    for field_ in vcard:
                        if field_[0] == 'fn':
                            registrar = field_[3]
            return {
                "registrar": registrar,
                "created": events.get('registration', 'Unknown'),
                "last_changed": events.get('last changed', 'Unknown'),
                "expires": events.get('expiration', 'Unknown'),
                "status": data.get('status', []),
            }
        except Exception as e:
            return {"error": f"WHOIS/RDAP Failed: {e}"}

    def check_hibp_domain(self, domain: str) -> Dict[str, Any]:
        """Optional breach-exposure context for the domain (requires HIBP key)."""
        if not self.hibp_key:
            return {"error": "HIBP API Key missing (optional)."}
        try:
            resp = with_retry(requests.get, "https://haveibeenpwned.com/api/v3/breaches",
                               params={"domain": domain},
                               headers={"hibp-api-key": self.hibp_key}, timeout=10)
            return {"breaches": resp.json()} if resp.status_code == 200 else {"breaches": []}
        except Exception as e:
            return {"error": f"HIBP Failed: {e}"}

    def search_nvd(self, keyword: str, max_results: int = 5) -> List[VulnerabilityRecord]:
        if not keyword:
            return []
        vulns = []
        try:
            params = {'keywordSearch': keyword, 'resultsPerPage': max_results}
            headers = {'apiKey': self.nvd_key} if self.nvd_key else {}
            resp = with_retry(requests.get, "https://services.nvd.nist.gov/rest/json/cves/2.0",
                               params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    descs = cve.get('descriptions', [])
                    desc = descs[0].get('value', 'No description') if descs else 'No description'
                    metrics = cve.get('metrics', {})

                    cvss_data = {}
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']

                    score = float(cvss_data.get('baseScore', 0.0))
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')

                    vulns.append(VulnerabilityRecord(
                        cve_id=cve_id, title=cve_id, cvss_score=score, severity=severity,
                        description=desc, remediation=f"Apply vendor patch for {cve_id}.",
                        match_confidence="keyword"
                    ))
        except Exception as e:
            logger.error(f"NVD Error: {e}")
        return sorted(vulns, key=lambda x: x.cvss_score, reverse=True)

    def call_groq(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096,
                  temperature: float = 0.2) -> str:
        if not self.groq_key:
            return "ERROR: Groq API Key missing in secrets."
        try:
            payload = {
                'model': 'llama-3.1-70b-versatile',
                'messages': [{'role': 'system', 'content': system_prompt},
                             {'role': 'user', 'content': user_prompt}],
                'temperature': temperature,
                'max_tokens': max_tokens
            }
            resp = with_retry(requests.post, "https://api.groq.com/openai/v1/chat/completions",
                               json=payload,
                               headers={'Authorization': f'Bearer {self.groq_key}',
                                        'Content-Type': 'application/json'}, timeout=60)
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
            return f"ERROR: Groq API returned {resp.status_code}: {resp.text}"
        except Exception as e:
            return f"ERROR: Groq Connection Failed: {e}"


# ==========================================
# 3. AUTONOMOUS AGENT ENGINE
# ==========================================

class AutonomousSecurityEngineer:
    def __init__(self, target: str):
        self.target = target.replace('https://', '').replace('http://', '').split('/')[0]
        self.connectors = AIConnectors()
        self.memory: Dict[str, Any] = {'target': self.target}
        self.reasoning_log: List[AgenticReasoning] = []

    def _log(self, task: str, evidence: str, interpretation: str, confidence: str):
        logger.info(f"Agent Reasoning [{task}]: {interpretation} (Confidence: {confidence})")
        self.reasoning_log.append(AgenticReasoning("SecurityEngineer", task, evidence, interpretation, confidence))

    # ---------- Pipeline orchestration ----------

    def run_pipeline(self):
        if not self.target:
            return
        steps: List[Tuple[str, Callable]] = [
            ("Agent 1: 🌐 Performing Authorized Reconnaissance...", self.perform_recon),
            ("Agent 2: 📇 Pulling WHOIS / Domain Intelligence...", self.perform_whois),
            ("Agent 3: 🔒 Analyzing TLS/SSL Certificate...", self.perform_tls_analysis),
            ("Agent 4: 🧾 Grading HTTP Security Headers...", self.perform_header_grading),
            ("Agent 5: 🔌 Probing Common TCP Ports...", self.perform_port_recon),
            ("Agent 6: 🧱 Fingerprinting WAF / CDN...", self.perform_waf_detection),
            ("Agent 7: 📂 Checking Sensitive Path Exposure...", self.perform_sensitive_path_check),
            ("Agent 8: 🌍 Resolving IP Geolocation / ASN...", self.perform_geolocation),
            ("Agent 9: 🛡️ Triaging Threat Intelligence...", self.perform_threat_triage),
            ("Agent 10: 🔬 Researching NVD Vulnerabilities...", self.perform_vulnerability_research),
            ("Agent 11: 📊 Scoring Composite Attack Surface Risk...", self.perform_risk_scoring),
            ("Agent 12: 🧠 Synthesizing AI Remediation Strategy...", self.perform_remediation_reasoning),
        ]
        with st.status(f"🚀 Launching Autonomous AI Security Engineer for: {self.target}...", expanded=True) as status:
            for label, fn in steps:
                if 'error' in self.memory:
                    break
                st.write(label)
                fn()
            if 'error' in self.memory:
                status.update(label="❌ Autonomous Pipeline Failed", state="error")
            else:
                status.update(label="✅ Autonomous Pipeline Completed", state="complete", expanded=False)

    # ---------- Agent 1: Recon (kept) ----------

    def perform_recon(self):
        try:
            assert_public_host(self.target)
            infos = socket.getaddrinfo(self.target, None)
            ips = list(set(addr[4][0] for addr in infos if addr[0] == socket.AF_INET))
            self.memory['ips'] = ips
            self._log("DNS Resolution", f"{self.target} resolved to {', '.join(ips)}",
                       "Target is publicly resolvable.", "High")

            subdomains = []
            try:
                resp = with_retry(requests.get, f"https://crt.sh/?q=%25.{self.target}&output=json", timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = list(set(entry['name_value'].strip() for entry in data
                                           if self.target in entry['name_value']))
            except Exception as e:
                logger.warning(f"crt.sh failed: {e}")
            self.memory['subdomains'] = subdomains[:100]
            self._log("Subdomain Enumeration", f"Found {len(subdomains)} certificates.",
                       "Expanded attack surface mapped.", "Medium")

            try:
                resp = requests.get(f"https://{self.target}", timeout=5, verify=False, allow_redirects=True)
                self.memory['_last_response_headers'] = dict(resp.headers)
                banner = resp.headers.get('Server', 'Unknown')
                powered_by = resp.headers.get('X-Powered-By', 'Unknown')
                self.memory['tech_stack'] = {'Server': banner, 'X-Powered-By': powered_by}
                self._log("Banner Grabbing", f"Server: {banner}, X-Powered-By: {powered_by}",
                           "Underlying technology identified.", "Medium")
            except Exception as e:
                self.memory['tech_stack'] = {'Server': 'Unknown', 'X-Powered-By': 'Unknown'}
                self.memory['_last_response_headers'] = {}
                self._log("Banner Grabbing", f"HTTP connection failed: {e}",
                           "Could not grab banners via HTTP.", "Low")
        except ScopeViolation as e:
            self.memory['error'] = str(e)
            self._log("Scope Check", str(e), "TARGET OUT OF SCOPE. Halting.", "High")
        except Exception as e:
            self.memory['error'] = str(e)
            self._log("Reconnaissance", str(e), "Reconnaissance phase failed.", "High")

    # ---------- Agent 2: WHOIS ----------

    def perform_whois(self):
        whois_data = self.connectors.query_whois(self.target)
        self.memory['whois'] = whois_data
        if 'error' in whois_data:
            self._log("WHOIS Lookup", whois_data['error'], "Registration data unavailable.", "Low")
        else:
            self._log("WHOIS Lookup",
                       f"Registrar: {whois_data.get('registrar')}, Created: {whois_data.get('created')}",
                       "Domain provenance and age established (younger domains carry higher risk weight).",
                       "Medium")

    # ---------- Agent 3: TLS/SSL ----------

    def perform_tls_analysis(self):
        result: Dict[str, Any] = {}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    not_after = cert.get('notAfter')
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    result = {
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "expires": not_after,
                        "days_until_expiry": days_left,
                        "protocol": ssock.version(),
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                    }
            self.memory['tls'] = result
            weak = result['protocol'] in ("TLSv1", "TLSv1.1", "SSLv3")
            interp = "Certificate valid and modern TLS in use."
            if days_left < 15:
                interp = f"Certificate expires in {days_left} days — renewal required soon."
            if weak:
                interp = f"Outdated protocol {result['protocol']} negotiated — deprecate legacy TLS."
            self._log("TLS/SSL Analysis",
                       f"Protocol: {result['protocol']}, Cipher: {result['cipher_suite']}, Expiry: {not_after}",
                       interp, "High")
        except Exception as e:
            self.memory['tls'] = {"error": str(e)}
            self._log("TLS/SSL Analysis", str(e), "Could not establish TLS session (port 443 closed or non-HTTPS host).", "Low")

    # ---------- Agent 4: Security Header Grading ----------

    def perform_header_grading(self):
        headers = self.memory.get('_last_response_headers', {})
        present, missing = [], []
        score = 0
        max_score = sum(SECURITY_HEADERS.values())
        for h, weight in SECURITY_HEADERS.items():
            if h in headers:
                present.append(h)
                score += weight
            else:
                missing.append(h)
        pct = round((score / max_score) * 100) if max_score else 0
        grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 50 else "D" if pct >= 25 else "F"
        self.memory['header_grade'] = {"grade": grade, "score_pct": pct, "present": present, "missing": missing}
        self._log("HTTP Security Header Grading",
                   f"Present: {present} | Missing: {missing}",
                   f"Overall header hygiene grade: {grade} ({pct}%). Missing headers widen the client-side attack surface.",
                   "High")

    # ---------- Agent 5: Port Recon ----------

    def _check_port(self, ip: str, port: int) -> PortResult:
        service = COMMON_PORTS[port]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                res = s.connect_ex((ip, port))
                return PortResult(port=port, service=service, open=(res == 0))
        except Exception:
            return PortResult(port=port, service=service, open=False)

    def perform_port_recon(self):
        ips = self.memory.get('ips', [])
        if not ips:
            self.memory['ports'] = []
            return
        ip = ips[0]
        results: List[PortResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(self._check_port, ip, p) for p in COMMON_PORTS]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())
        results.sort(key=lambda r: r.port)
        self.memory['ports'] = [asdict(r) for r in results]
        open_ports = [r for r in results if r.open]
        risky_open = [r for r in open_ports if r.service in
                      ("Telnet", "FTP", "RDP", "MySQL", "PostgreSQL", "Redis", "MongoDB")]
        interp = f"{len(open_ports)} of {len(COMMON_PORTS)} checked ports open."
        if risky_open:
            interp += f" ⚠️ Potentially risky exposed services: {[r.service for r in risky_open]}."
        self._log("Port Reconnaissance", f"Open: {[r.port for r in open_ports]}", interp,
                   "High" if risky_open else "Medium")

    # ---------- Agent 6: WAF/CDN Fingerprint ----------

    def perform_waf_detection(self):
        headers = {k.lower(): v for k, v in self.memory.get('_last_response_headers', {}).items()}
        header_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        detected = []
        for name, sigs in WAF_SIGNATURES.items():
            if any(sig in header_blob for sig in sigs):
                detected.append(name)
        self.memory['waf'] = detected
        interp = f"Detected protection layer(s): {detected}." if detected else \
                 "No common WAF/CDN signature detected from headers — origin may be directly exposed."
        self._log("WAF/CDN Fingerprinting", header_blob[:200], interp, "Medium")

    # ---------- Agent 7: Sensitive Path Exposure ----------

    def _check_path(self, path: str) -> PathCheckResult:
        try:
            resp = requests.get(f"https://{self.target}{path}", timeout=5, verify=False, allow_redirects=False)
            exposed = resp.status_code == 200 and path not in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
            return PathCheckResult(path=path, status_code=resp.status_code,
                                    content_length=len(resp.content or b""), exposed=exposed)
        except Exception:
            return PathCheckResult(path=path, status_code=0, content_length=0, exposed=False)

    def perform_sensitive_path_check(self):
        results: List[PathCheckResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(self._check_path, p) for p in SENSITIVE_PATHS]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())
        self.memory['sensitive_paths'] = [asdict(r) for r in results]
        exposed = [r for r in results if r.exposed]
        interp = f"⚠️ {len(exposed)} sensitive path(s) returned HTTP 200: {[r.path for r in exposed]}." if exposed \
                 else "No commonly-exposed sensitive files/paths found (200 OK) among checked list."
        self._log("Sensitive Path Exposure Check", f"Checked {len(SENSITIVE_PATHS)} known paths.", interp,
                   "High" if exposed else "Medium")

    # ---------- Agent 8: Geolocation / ASN ----------

    def perform_geolocation(self):
        ips = self.memory.get('ips', [])
        geo_data = {}
        for ip in ips[:3]:
            geo_data[ip] = self.connectors.query_ip_geolocation(ip)
        self.memory['geolocation'] = geo_data
        summary = "; ".join(f"{ip}: {v.get('country', v.get('error', 'n/a'))}, {v.get('org', '')}"
                             for ip, v in geo_data.items())
        self._log("IP Geolocation / ASN Context", summary,
                   "Hosting jurisdiction and provider/ASN context established for risk & compliance framing.",
                   "Medium")

    # ---------- Agent 9: Threat Triage (kept) ----------

    def perform_threat_triage(self):
        targets_to_triage = list(self.memory.get('ips', []))
        if not re.match(r'^\d+\.\d+\.\d+\.\d+', self.target):
            targets_to_triage.append(self.target)

        intel_reports = {}
        shodan_reports = {}
        for item in targets_to_triage:
            vt_res = self.connectors.query_virustotal(item)
            abuse_res = self.connectors.query_abuseipdb(item)
            intel_reports[item] = {'vt': vt_res, 'abuse': abuse_res}

            if re.match(r'^\d+\.\d+\.\d+\.\d+$', item):
                shodan_reports[item] = self.connectors.query_shodan(item)

            risk = "Low"
            m_count = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            abuse_score = abuse_res.get('data', {}).get('abuseConfidenceScore', 0)
            if m_count > 0 or abuse_score > 0:
                risk = "Medium"
            if m_count > 5 or abuse_score > 50:
                risk = "High"
            self._log(f"Threat Triage: {item}", f"VT Malicious: {m_count}, Abuse Score: {abuse_score}%",
                       f"Indicator risk assessed as {risk}.", "High")

        self.memory['threat_intel'] = intel_reports
        self.memory['shodan'] = shodan_reports
        self.memory['hibp'] = self.connectors.check_hibp_domain(self.target)

    # ---------- Agent 10: NVD (kept) ----------

    def perform_vulnerability_research(self):
        keywords = []
        tech = self.memory.get('tech_stack', {})
        if tech.get('X-Powered-By') != 'Unknown':
            keywords.append(tech.get('X-Powered-By'))
        if tech.get('Server') != 'Unknown':
            keywords.append(tech.get('Server').split('/')[0])
        keywords.append(self.target.split('.')[0])

        all_cves = []
        for kw in list(set(keywords)):
            cves = self.connectors.search_nvd(kw)
            all_cves.extend(cves)
            self._log(f"NVD Search: {kw}", f"Found {len(cves)} CVEs",
                       f"Correlated {kw} with known vulnerabilities.", "Medium" if cves else "High")

        unique_cves = {cve.cve_id: cve for cve in all_cves}
        self.memory['vulnerabilities'] = list(unique_cves.values())

    # ---------- Agent 11: Composite Risk Scoring ----------

    def perform_risk_scoring(self):
        score = 0
        reasons = []

        header_pct = self.memory.get('header_grade', {}).get('score_pct', 100)
        score += (100 - header_pct) * 0.25
        if header_pct < 100:
            reasons.append(f"Header hygiene gap ({header_pct}%)")

        risky_ports = [p for p in self.memory.get('ports', []) if p['open'] and
                       p['service'] in ("Telnet", "FTP", "RDP", "MySQL", "PostgreSQL", "Redis", "MongoDB")]
        if risky_ports:
            score += 20 * len(risky_ports)
            reasons.append(f"{len(risky_ports)} risky service(s) exposed")

        exposed_paths = [p for p in self.memory.get('sensitive_paths', []) if p['exposed']]
        if exposed_paths:
            score += 25 * len(exposed_paths)
            reasons.append(f"{len(exposed_paths)} sensitive path(s) exposed")

        tls = self.memory.get('tls', {})
        if tls.get('protocol') in ("TLSv1", "TLSv1.1", "SSLv3"):
            score += 15
            reasons.append("Legacy TLS protocol")
        if isinstance(tls.get('days_until_expiry'), int) and tls['days_until_expiry'] < 15:
            score += 10
            reasons.append("TLS certificate expiring soon")

        if not self.memory.get('waf'):
            score += 5
            reasons.append("No WAF/CDN signature detected")

        high_cves = [v for v in self.memory.get('vulnerabilities', []) if v.cvss_score >= 7.0]
        if high_cves:
            score += 10 * len(high_cves)
            reasons.append(f"{len(high_cves)} high/critical CVE(s) correlated")

        score = min(round(score), 100)
        level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
        self.memory['risk_score'] = {"score": score, "level": level, "reasons": reasons}
        self._log("Composite Attack-Surface Risk Scoring", "; ".join(reasons) or "No major issues detected",
                   f"Overall attack-surface risk rated {level} ({score}/100).", "High")

    # ---------- Agent 12: AI Remediation (kept, richer context) ----------

    def perform_remediation_reasoning(self):
        context = {
            "target": self.target,
            "tech_stack": self.memory.get('tech_stack', {}),
            "whois": self.memory.get('whois', {}),
            "tls": self.memory.get('tls', {}),
            "header_grade": self.memory.get('header_grade', {}),
            "open_ports": [p for p in self.memory.get('ports', []) if p['open']],
            "waf": self.memory.get('waf', []),
            "exposed_paths": [p for p in self.memory.get('sensitive_paths', []) if p['exposed']],
            "geolocation": self.memory.get('geolocation', {}),
            "threat_intel": self.memory.get('threat_intel', {}),
            "risk_score": self.memory.get('risk_score', {}),
            "top_cves": [asdict(v) for v in self.memory.get('vulnerabilities', [])[:5]],
        }
        system_prompt = (
            "You are an elite Autonomous AI Security Engineer performing an authorized security "
            "assessment. Analyze the provided telemetry across recon, WHOIS, TLS, HTTP headers, "
            "open ports, WAF posture, exposed paths, geolocation, threat intel, and CVEs. Produce a "
            "professional, risk-prioritized executive report with: (1) executive summary, (2) key "
            "findings ranked by severity, (3) concrete remediation steps per finding, (4) a suggested "
            "90-day hardening roadmap. Be precise and actionable, and do not include any exploit code."
        )
        ai_response = self.connectors.call_groq(
            system_prompt, f"Analyze this telemetry and produce the report:\n{json.dumps(context, default=str)}")
        self.memory['ai_report'] = ai_response
        self._log("AI Remediation Strategy", "Full telemetry synthesized by Groq AI model",
                   "Generated automated tactical security guidance and executive report.", "High")


# ==========================================
# 4. STREAMLIT USER INTERFACE
# ==========================================

def main():
    st.set_page_config(page_title="MHZALY AI Security Engineer", page_icon="🛡️", layout="wide")

    st.markdown("# 🛡️ MHZALY AI Security Engineer")
    st.markdown(
        "<p style='color: #9ca3af;'>Autonomous multi-agent platform: recon, WHOIS, TLS, header grading, "
        "port checks, WAF fingerprinting, exposure checks, geolocation, threat intel, CVE correlation, "
        "composite risk scoring, and AI-driven remediation — for infrastructure you are authorized to test.</p>",
        unsafe_allow_html=True)

    with st.sidebar:
        st.subheader("🔑 API Configuration Status")
        st.write(f"**VirusTotal API:** {'✅ Active' if st.secrets.get('VIRUSTOTAL_API_KEY') else '⚠️ Missing'}")
        st.write(f"**AbuseIPDB API:** {'✅ Active' if st.secrets.get('ABUSEIPDB_API_KEY') else '⚠️ Missing'}")
        st.write(f"**NVD API:** {'✅ Active' if st.secrets.get('NVD_API_KEY') else '⚠️ Optional/Standard'}")
        st.write(f"**Groq AI Engine:** {'✅ Active' if st.secrets.get('GROQ_API_KEY') else '⚠️ Missing'}")
        st.write(f"**Shodan API:** {'✅ Active' if st.secrets.get('SHODAN_API_KEY') else '⚠️ Optional'}")
        st.write(f"**HIBP API:** {'✅ Active' if st.secrets.get('HIBP_API_KEY') else '⚠️ Optional'}")
        st.markdown("---")
        st.info("Place keys in Streamlit secrets. Only scan/test infrastructure you own or are authorized to test.")

    target_input = st.text_input("Target Domain or IP Address", placeholder="e.g., example.com or 8.8.8.8")

    if st.button("🚀 Launch Autonomous AI Security Engineer", use_container_width=True):
        if not target_input:
            st.warning("Please specify a valid target domain or IP address.")
        else:
            engine = AutonomousSecurityEngineer(target_input)
            engine.run_pipeline()

            if 'error' in engine.memory:
                st.error(f"Pipeline Halted: {engine.memory['error']}")
            else:
                st.success("Autonomous Security Assessment Complete!")

                risk = engine.memory.get('risk_score', {})
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk Level", risk.get('level', 'N/A'))
                c2.metric("Risk Score", f"{risk.get('score', 0)}/100")
                c3.metric("Header Grade", engine.memory.get('header_grade', {}).get('grade', 'N/A'))
                c4.metric("Open Ports", len([p for p in engine.memory.get('ports', []) if p['open']]))

                tabs = st.tabs([
                    "🧠 AI Executive Report", "🔍 Reasoning Trace", "🌐 Recon & Assets",
                    "📇 WHOIS", "🔒 TLS/SSL", "🧾 Header Grade", "🔌 Ports",
                    "🧱 WAF/CDN", "📂 Exposure Check", "🌍 Geolocation",
                    "🛡️ Threat Intel", "🔬 CVEs", "📊 Risk Score",
                ])

                with tabs[0]:
                    st.markdown("### Executive Strategy & Remediation")
                    st.markdown(engine.memory.get('ai_report', 'No report generated.'))
                    report_markdown = f"""# AI SECURITY ENGINEER ASSESSMENT REPORT
**Target:** `{engine.target}`
**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
**Risk Level:** {risk.get('level', 'N/A')} ({risk.get('score', 0)}/100)

## Executive Summary & AI Strategy
{engine.memory.get('ai_report', 'N/A')}
"""
                    st.download_button("📥 Download Assessment Report (.md)", data=report_markdown,
                                        file_name=f"ai_security_report_{engine.target}.md",
                                        mime="text/markdown", use_container_width=True)

                with tabs[1]:
                    st.markdown("### Agentic Reasoning Trace")
                    for r in engine.reasoning_log:
                        with st.expander(f"Task: {r.task} (Confidence: {r.confidence})"):
                            st.write(f"**Evidence:** {r.evidence}")
                            st.write(f"**Interpretation:** {r.interpretation}")

                with tabs[2]:
                    st.markdown("### Reconnaissance & Assets")
                    st.write(f"**Resolved IPs:** {engine.memory.get('ips', [])}")
                    st.write(f"**Tech Stack:** {engine.memory.get('tech_stack', {})}")
                    subdomains = engine.memory.get('subdomains', [])
                    if subdomains:
                        st.markdown(f"**Enumerated Subdomains ({len(subdomains)}):**")
                        st.dataframe(pd.DataFrame({'Subdomain': subdomains}), use_container_width=True)

                with tabs[3]:
                    st.markdown("### WHOIS / Domain Intelligence")
                    st.json(engine.memory.get('whois', {}))

                with tabs[4]:
                    st.markdown("### TLS/SSL Certificate Analysis")
                    st.json(engine.memory.get('tls', {}))

                with tabs[5]:
                    st.markdown("### HTTP Security Header Grade")
                    hg = engine.memory.get('header_grade', {})
                    st.write(f"**Grade:** {hg.get('grade')} ({hg.get('score_pct')}%)")
                    st.write(f"**Present:** {hg.get('present')}")
                    st.write(f"**Missing:** {hg.get('missing')}")

                with tabs[6]:
                    st.markdown("### Port Reconnaissance (top 20 well-known ports)")
                    ports = engine.memory.get('ports', [])
                    if ports:
                        st.dataframe(pd.DataFrame(ports), use_container_width=True)

                with tabs[7]:
                    st.markdown("### WAF / CDN Fingerprint")
                    st.write(engine.memory.get('waf', []) or "No signature detected.")

                with tabs[8]:
                    st.markdown("### Sensitive Path Exposure Check")
                    paths = engine.memory.get('sensitive_paths', [])
                    if paths:
                        st.dataframe(pd.DataFrame(paths), use_container_width=True)

                with tabs[9]:
                    st.markdown("### IP Geolocation / ASN Context")
                    st.json(engine.memory.get('geolocation', {}))

                with tabs[10]:
                    st.markdown("### Threat Intelligence Triage")
                    st.json(engine.memory.get('threat_intel', {}))
                    if engine.memory.get('shodan'):
                        st.markdown("**Shodan (optional):**")
                        st.json(engine.memory.get('shodan', {}))
                    if engine.memory.get('hibp'):
                        st.markdown("**HIBP Domain Breach Context (optional):**")
                        st.json(engine.memory.get('hibp', {}))

                with tabs[11]:
                    st.markdown("### Correlated NVD Vulnerabilities")
                    cves = engine.memory.get('vulnerabilities', [])
                    if cves:
                        st.dataframe(pd.DataFrame([asdict(c) for c in cves]), use_container_width=True)
                    else:
                        st.info("No matching high-confidence CVEs found for the fingerprinted stack.")

                with tabs[12]:
                    st.markdown("### Composite Attack-Surface Risk Score")
                    st.json(engine.memory.get('risk_score', {}))


if __name__ == "__main__":
    main()
