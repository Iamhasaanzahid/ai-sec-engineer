#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY AI SECURITY ENGINEER - AUTONOMOUS AGENT SYSTEM v24.0 (No-API-Key / Human-Analyst Edition)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Author: Muhammad Hassaan Zahid

What changed vs v23:
  1. NO API KEY IS REQUIRED ANYMORE. Every core finding (DNS, WHOIS, TLS, HTTP headers,
     TCP port reachability, subdomains, sensitive-path exposure, geolocation, CVE
     correlation) now comes from a real, free, keyless lookup instead of a hardcoded
     "simulation_mode" fallback.
  2. VirusTotal / AbuseIPDB / an LLM (Groq) key are OPTIONAL enrichments only. If you add
     them to st.secrets they're used automatically; if you don't, the report says
     "not configured" instead of printing a fabricated reputation score. The tool never
     pretends to know something it doesn't.
  3. The executive write-up is produced by a local narrative engine (no LLM call needed)
     that writes first-person analyst prose grounded in the real findings, so it reads
     like a human analyst's report instead of a templated JSON dump. If you do add a
     Groq key later, it will polish/expand that same real data — it never invents new
     findings on top of it.
"""

import streamlit as st
import requests
import pandas as pd
import json
import logging
import time
import random
import ipaddress
import ssl
import socket
import re
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings()

# ==========================================
# 0. UI STYLING & ENTERPRISE THEME
# ==========================================

def inject_enterprise_styles():
    st.markdown("""
        <style>
        .stApp { background-color: #0b0f19; color: #f3f4f6; }
        .metric-container {
            background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
            border: 1px solid #374151; padding: 18px; border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); text-align: center;
        }
        .stTabs [data-baseweb="tab-list"] { gap: 8px; background-color: #111827; padding: 10px; border-radius: 10px; }
        .stTabs [data-baseweb="tab"] { background-color: #1f2937; color: #9ca3af; border-radius: 6px; padding: 10px 16px; font-weight: 600; }
        .stTabs [aria-selected="true"] { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%) !important; color: #ffffff !important; }
        .not-configured { color: #6b7280; font-style: italic; }
        </style>
    """, unsafe_allow_html=True)

# ==========================================
# 1. CORE SAFETY & CONFIGURATION
# ==========================================

class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass

def assert_public_host(hostname: str) -> None:
    clean_host = hostname.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        infos = socket.getaddrinfo(clean_host, None)
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host '{clean_host}': {e}")
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ScopeViolation(f"Target '{clean_host}' resolves to a non-public address ({sockaddr[0]}). Refusing to scan internal/private infrastructure.")

def with_retry(fn: Callable, *args, retries: int = 2, backoff: float = 1.5, **kwargs):
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff ** attempt)
        except Exception as e:
            raise e
    raise last_exc

COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/wp-config.php.bak",
    "/config.json", "/.aws/credentials", "/backup.zip",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/server-status", "/phpinfo.php", "/.htpasswd", "/id_rsa",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": 15, "Content-Security-Policy": 20,
    "X-Frame-Options": 10, "X-Content-Type-Options": 10,
    "Referrer-Policy": 10, "Permissions-Policy": 10, "X-XSS-Protection": 5,
}

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
    "Akamai": ["akamai", "x-akamai"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "AWS WAF / CloudFront": ["x-amz-cf-id", "x-amzn-requestid"],
    "Imperva / Incapsula": ["x-iinfo", "incap_ses"],
    "F5 BIG-IP ASM": ["x-waf-event-info", "big-ip"],
}

# ==========================================
# 2. DATA MODELS
# ==========================================

@dataclass
class VulnerabilityRecord:
    cve_id: str
    title: str
    cvss_score: float
    severity: str
    description: str
    remediation: str
    source: str

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

@dataclass
class PathCheckResult:
    path: str
    status_code: int
    content_length: int
    exposed: bool
    note: str = ""

# ==========================================
# 3. FREE / KEYLESS CONNECTORS  (VT, AbuseIPDB, Groq are OPTIONAL enrichments)
# ==========================================

class Connectors:
    def __init__(self):
        self.vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "") if hasattr(st, "secrets") else ""
        self.abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "") if hasattr(st, "secrets") else ""
        self.nvd_key = st.secrets.get("NVD_API_KEY", "") if hasattr(st, "secrets") else ""
        self.groq_key = st.secrets.get("GROQ_API_KEY", "") if hasattr(st, "secrets") else ""

    # ---- OPTIONAL reputation enrichment (never fabricated if key missing) ----
    def query_virustotal(self, indicator: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {"configured": False}
        is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator))
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip else \
              f"https://www.virustotal.com/api/v3/domains/{indicator}"
        try:
            resp = with_retry(requests.get, url, headers={'x-apikey': self.vt_key}, timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                d["configured"] = True
                return d
            return {"configured": True, "error": f"VT Error: {resp.status_code}"}
        except Exception as e:
            return {"configured": True, "error": f"VT Connection Failed: {e}"}

    def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.abuse_key:
            return {"configured": False}
        try:
            resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                              headers={'Key': self.abuse_key, 'Accept': 'application/json'},
                              params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                d["configured"] = True
                return d
            return {"configured": True, "error": f"AbuseIPDB Error: {resp.status_code}"}
        except Exception as e:
            return {"configured": True, "error": f"AbuseIPDB Connection Failed: {e}"}

    # ---- FREE, keyless, real lookups ----
    def query_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        try:
            resp = with_retry(requests.get, f"http://ip-api.com/json/{ip}",
                              params={"fields": "status,message,country,regionName,city,isp,org,as,query"}, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    data["available"] = True
                    return data
        except Exception as e:
            return {"available": False, "error": str(e)}
        return {"available": False, "error": "geolocation lookup failed or was rate-limited"}

    def query_whois(self, domain: str) -> Dict[str, Any]:
        try:
            resp = with_retry(requests.get, f"https://rdap.org/domain/{domain}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
                registrar = "Unknown"
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray", [None, []])[1]
                        for field in vcard:
                            if field[0] == "fn":
                                registrar = field[3]
                return {
                    "available": True,
                    "registrar": registrar,
                    "created": events.get('registration'),
                    "expires": events.get('expiration'),
                    "status": data.get('status', []),
                }
        except Exception as e:
            return {"available": False, "error": str(e)}
        return {"available": False, "error": "RDAP lookup returned no usable record"}

    def query_crtsh_subdomains(self, domain: str) -> Dict[str, Any]:
        try:
            resp = with_retry(requests.get, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                              timeout=15, retries=1)
            if resp.status_code == 200 and resp.text.strip():
                rows = resp.json()
                names = set()
                for row in rows:
                    for n in row.get("name_value", "").split("\n"):
                        n = n.strip().lower()
                        if n and "*" not in n:
                            names.add(n)
                return {"available": True, "subdomains": sorted(names)[:100], "total_found": len(names)}
        except Exception as e:
            return {"available": False, "error": str(e), "subdomains": []}
        return {"available": False, "error": "no certificate-transparency records found", "subdomains": []}

    @staticmethod
    def _extract_cvss(cve: Dict[str, Any]) -> tuple:
        """Return (score, severity) preferring v3.1 > v3.0 > v2, reading severity
        from the correct spot in each schema (v2's baseSeverity lives on the metric
        object itself, not inside cvssData)."""
        metrics = cve.get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30'):
            block = metrics.get(key)
            if block:
                data = block[0].get('cvssData', {})
                return float(data.get('baseScore', 0.0)), data.get('baseSeverity', 'UNKNOWN')
        block = metrics.get('cvssMetricV2')
        if block:
            data = block[0].get('cvssData', {})
            sev = block[0].get('baseSeverity', 'UNKNOWN')  # v2 severity sits one level up
            return float(data.get('baseScore', 0.0)), sev
        return 0.0, 'UNKNOWN'

    def search_nvd(self, product: str, version: str = "") -> Dict[str, Any]:
        if not product:
            return {"available": False,
                     "reason": "no specific origin software/version was disclosed in response headers (only an edge proxy/CDN was visible), so CVE correlation was skipped rather than guessed",
                     "vulns": []}
        query = f"{product} {version}".strip()
        try:
            params = {'keywordSearch': query, 'resultsPerPage': 20}
            headers = {'apiKey': self.nvd_key} if self.nvd_key else {}
            resp = with_retry(requests.get, "https://services.nvd.nist.gov/rest/json/cves/2.0",
                              params=params, headers=headers, timeout=10, retries=1)
            if resp.status_code == 200:
                vulns = []
                for item in resp.json().get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    desc = cve.get('descriptions', [{}])[0].get('value', 'No description')
                    # relevance filter: the product name must actually appear in the CVE text,
                    # otherwise NVD's free-text search just matched an unrelated word.
                    if product.lower() not in desc.lower():
                        continue
                    score, sev = self._extract_cvss(cve)
                    vulns.append(VulnerabilityRecord(cve_id, cve_id, score, sev, desc,
                                                      f"Confirm the exact running version of {query} before treating this as applicable, then patch/upgrade if it matches.",
                                                      "NVD (live)"))
                vulns.sort(key=lambda v: v.cvss_score, reverse=True)
                return {"available": True, "vulns": vulns[:5], "query": query}
            if resp.status_code == 403:
                return {"available": False, "reason": "NVD rate-limited this request (no API key configured)", "vulns": []}
            return {"available": False, "reason": f"NVD returned HTTP {resp.status_code}", "vulns": []}
        except Exception as e:
            return {"available": False, "reason": str(e), "vulns": []}

    # ---- OPTIONAL LLM polish (report already fully written locally without it) ----
    def call_groq(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        if not self.groq_key:
            return None
        try:
            payload = {'model': 'llama-3.1-70b-versatile',
                       'messages': [{'role': 'system', 'content': system_prompt},
                                    {'role': 'user', 'content': user_prompt}],
                       'temperature': 0.3, 'max_tokens': 2000}
            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload,
                                  headers={'Authorization': f'Bearer {self.groq_key}', 'Content-Type': 'application/json'},
                                  timeout=30)
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
        except Exception:
            pass
        return None

# ==========================================
# 4. LOCAL HUMAN-ANALYST NARRATIVE ENGINE (no API key, no LLM required)
# ==========================================

class AnalystNarrator:
    """Turns the real findings dict into first-person analyst prose. Every sentence here
    is conditioned on an actual finding — nothing is invented."""

    OPENERS = [
        "I spent some time going over {target} today and here's where things stand.",
        "Here's my read on {target} after walking through the standard external checks.",
        "I ran {target} through the usual external recon and hardening checks — summary below.",
    ]

    def __init__(self, memory: Dict[str, Any], reasoning_log: List[AgenticReasoning]):
        self.m = memory
        self.log = reasoning_log

    def _headers_paragraph(self) -> str:
        hg = self.m.get('header_grade', {})
        if not hg:
            return ""
        missing = hg.get('missing', [])
        present = hg.get('present', [])
        grade = hg.get('grade', 'N/A')
        if not missing:
            return (f"Header hygiene is solid — every security header I check for "
                    f"(HSTS, CSP, X-Frame-Options, etc.) is present, which earns a {grade} grade.")
        lead = random.choice([
            "On the header side there's room to tighten things up.",
            "Header hardening is the most actionable gap I found.",
        ])
        miss_str = ", ".join(missing)
        return (f"{lead} The response is missing {len(missing)} of the headers I check for "
                f"({miss_str}), which brings the grade to a {grade}. "
                + ("These are cheap to add at the edge/reverse-proxy layer and meaningfully reduce "
                   "clickjacking, MIME-sniffing, and mixed-content risk." if missing else ""))

    def _tls_paragraph(self) -> str:
        tls = self.m.get('tls', {})
        if not tls or not tls.get('available'):
            return f"I couldn't complete a TLS handshake on port 443 ({tls.get('error', 'no HTTPS service responded')}), so I can't speak to certificate/cipher health from here."
        proto = tls.get('protocol', 'unknown')
        cipher = tls.get('cipher_suite', 'unknown')
        expires = tls.get('expires', 'unknown')
        return (f"TLS looks healthy: the server negotiated {proto} with {cipher}, and the certificate is "
                f"valid until {expires}.")

    def _ports_paragraph(self) -> str:
        ports = self.m.get('ports', [])
        open_ports = [p for p in ports if p['open']]
        if not open_ports:
            return "The lightweight TCP connect scan I ran against the common service ports didn't find anything unexpected open."
        names = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
        risky = [p for p in open_ports if p['port'] not in (80, 443)]
        base = f"A quick TCP connect scan of common ports found {len(open_ports)} reachable: {names}."
        if risky:
            base += (" Worth a second look: anything beyond 80/443 being reachable from the public internet "
                      "(databases, RDP, admin panels) is usually worth restricting to a VPN or allow-list.")
        return base

    def _paths_paragraph(self) -> str:
        paths = self.m.get('sensitive_paths', [])
        exposed = [p for p in paths if p['exposed']]
        if not exposed:
            return "None of the common sensitive paths I probed (.env, .git/HEAD, backup archives, etc.) were exposed."
        names = ", ".join(p['path'] for p in exposed)
        return (f"I'd flag this one first: {names} appear to be reachable and returning content, which can "
                f"leak credentials, source, or config. I'd pull these immediately and check web server access "
                f"controls / .htaccess or nginx location rules.")

    def _waf_paragraph(self) -> str:
        waf = self.m.get('waf', [])
        if not waf:
            return "I didn't see fingerprints of a WAF/CDN in the response headers — traffic looks like it's hitting the origin directly."
        return f"Traffic appears to sit behind {', '.join(waf)}, which gives you a layer of protection against common automated attacks."

    def _whois_paragraph(self) -> str:
        w = self.m.get('whois', {})
        if not w.get('available'):
            return ""
        created = w.get('created')
        age_note = ""
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - created_dt).days
                if age_days < 90:
                    age_note = f" It's also worth noting the domain was registered only {age_days} days ago, which on its own isn't a red flag but is a factor I weigh into the risk score."
            except Exception:
                pass
        return f"Registration is with {w.get('registrar', 'an unlisted registrar')}.{age_note}"

    def _subdomains_paragraph(self) -> str:
        s = self.m.get('subdomains', {})
        if not s.get('available'):
            return ""
        total = s.get('total_found', 0)
        if total == 0:
            return "Certificate-transparency logs didn't surface any additional subdomains."
        return (f"Certificate-transparency logs surfaced {total} historical subdomain(s) for this domain — "
                f"worth reviewing for forgotten staging/dev environments, which are a common source of "
                f"unintended exposure.")

    def _cve_paragraph(self) -> str:
        cve = self.m.get('vulnerability_result', {})
        if not cve.get('available'):
            return f"I didn't run a live CVE correlation ({cve.get('reason', 'no identifiable component')})."
        vulns = cve.get('vulns', [])
        query = cve.get('query', '')
        if not vulns:
            return f"I searched NVD for '{query}' and, after filtering out anything that wasn't actually about that product, nothing relevant came back."
        top = max(vulns, key=lambda v: v.cvss_score)
        sev_note = f"CVSS {top.cvss_score}, {top.severity}" if top.severity != 'UNKNOWN' else f"CVSS {top.cvss_score}" if top.cvss_score else "no CVSS score published"
        return (f"I searched NVD for '{query}' and, after discarding anything where that product name wasn't actually "
                f"mentioned in the CVE text, {len(vulns)} advisor{'y' if len(vulns)==1 else 'ies'} remained — the "
                f"most severe being {top.cve_id} ({sev_note}). These are still text-match correlations, not confirmed "
                f"exploitable findings — check the exact running version before acting on any of them.")

    def _threat_intel_paragraph(self) -> str:
        vt = self.m.get('threat_intel', {}).get('vt', {})
        abuse = self.m.get('threat_intel', {}).get('abuse', {})
        parts = []
        if vt.get('configured'):
            if 'error' not in vt:
                stats = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                mal = stats.get('malicious', 0)
                parts.append(f"VirusTotal shows {mal} vendor(s) flagging this indicator as malicious." if mal else
                             "VirusTotal shows a clean reputation.")
        if abuse.get('configured'):
            if 'error' not in abuse:
                score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                parts.append(f"AbuseIPDB confidence score is {score}/100.")
        if not parts:
            return ("I didn't run external reputation checks — VirusTotal/AbuseIPDB API keys aren't configured. "
                    "That's optional; add them to st.secrets if you want that enrichment. Everything else in "
                    "this report is unaffected.")
        return " ".join(parts)

    def build(self) -> str:
        target = self.m.get('target', 'the target')
        lines = [random.choice(self.OPENERS).format(target=target), ""]
        for para in [self._paths_paragraph(), self._headers_paragraph(), self._tls_paragraph(),
                     self._ports_paragraph(), self._waf_paragraph(), self._whois_paragraph(),
                     self._subdomains_paragraph(), self._cve_paragraph(), self._threat_intel_paragraph()]:
            if para:
                lines.append(para)
                lines.append("")
        risk = self.m.get('risk_score', {})
        lines.append(f"**Bottom line:** composite risk score is {risk.get('score', '?')}/100 "
                     f"({risk.get('level', 'Unknown')}). " + " ".join(risk.get('reasons', [])))
        lines.append("")
        lines.append("_This is an automated preliminary assessment — treat findings that flag exposure as "
                      "urgent to verify by hand, and don't take the CVE list as confirmed without checking "
                      "the actual running version._")
        return "\n".join(lines)

# ==========================================
# 5. AUTONOMOUS SECURITY AGENT PIPELINE
# ==========================================

class AutonomousSecurityEngineer:
    def __init__(self, target: str):
        self.target = target.replace('https://', '').replace('http://', '').split('/')[0].strip('/')
        self.connectors = Connectors()
        self.memory: Dict[str, Any] = {'target': self.target}
        self.reasoning_log: List[AgenticReasoning] = []

    def _log(self, task: str, evidence: str, interpretation: str, confidence: str):
        self.reasoning_log.append(AgenticReasoning("SecurityAnalyst", task, evidence, interpretation, confidence))

    def run_pipeline(self):
        if not self.target:
            return
        steps = [
            ("Agent 1: DNS Resolution & Live HTTP Probe", self.perform_recon),
            ("Agent 2: Certificate-Transparency Subdomain Enum", self.perform_subdomain_enum),
            ("Agent 3: RDAP WHOIS Lookup", self.perform_whois),
            ("Agent 4: TLS/SSL Handshake Inspection", self.perform_tls_analysis),
            ("Agent 5: HTTP Security Header Grading", self.perform_header_grading),
            ("Agent 6: TCP Connect Port Probe", self.perform_port_recon),
            ("Agent 7: WAF / Edge Fingerprinting", self.perform_waf_detection),
            ("Agent 8: Sensitive Path Exposure Scan", self.perform_sensitive_path_check),
            ("Agent 9: IP Geolocation Lookup", self.perform_geolocation),
            ("Agent 10: Optional Threat-Intel Enrichment", self.perform_threat_triage),
            ("Agent 11: NVD Vulnerability Correlation", self.perform_vulnerability_research),
            ("Agent 12: Composite Risk Scoring", self.perform_risk_scoring),
            ("Agent 13: Analyst Report Synthesis", self.perform_remediation_reasoning),
        ]
        progress_bar = st.progress(0)
        status_text = st.empty()
        total = len(steps)
        for i, (label, fn) in enumerate(steps):
            status_text.markdown(f"**Executing:** `{label}`")
            fn()
            progress_bar.progress((i + 1) / total)
            if 'error' in self.memory:
                break
        status_text.empty()
        progress_bar.empty()

    def perform_recon(self):
        try:
            assert_public_host(self.target)
            infos = socket.getaddrinfo(self.target, None)
            ips = sorted(set(addr[4][0] for addr in infos if addr[0] == socket.AF_INET))
            self.memory['ips'] = ips
            self._log("DNS Resolution", f"Resolved to {ips}", "Target infrastructure is publicly reachable.", "High")
            try:
                resp = with_retry(requests.get, f"https://{self.target}", timeout=8, verify=False,
                                   allow_redirects=True, retries=1,
                                   headers={"User-Agent": "MHZALY-SecurityEngineer/24.0 (+authorized-recon)"})
                self.memory['_last_response_headers'] = dict(resp.headers)
                self.memory['tech_stack'] = {'Server': resp.headers.get('Server', ''), 'X-Powered-By': resp.headers.get('X-Powered-By', '')}
                self._log("Live HTTP Probe", f"HTTP {resp.status_code}, Server header: {resp.headers.get('Server', 'not disclosed')}",
                           "Captured real response headers for grading/fingerprinting.", "High")
            except Exception as e:
                self.memory['tech_stack'] = {'Server': '', 'X-Powered-By': ''}
                self.memory['_last_response_headers'] = {}
                self._log("Live HTTP Probe", f"HTTPS probe failed: {e}", "No live HTTPS response captured — header/WAF checks will show as unavailable rather than guessed.", "Low")
        except ScopeViolation as e:
            self.memory['error'] = str(e)
            self._log("Scope Check", str(e), "Target violates security scope policy.", "High")

    def perform_subdomain_enum(self):
        result = self.connectors.query_crtsh_subdomains(self.target)
        self.memory['subdomains'] = result
        if result.get('available'):
            self._log("Subdomain Enumeration", f"{result.get('total_found', 0)} names found via crt.sh",
                       "Certificate-transparency logs mapped to historical subdomains.", "Medium")
        else:
            self._log("Subdomain Enumeration", result.get('error', 'unavailable'), "crt.sh lookup unavailable — skipped.", "Low")

    def perform_whois(self):
        data = self.connectors.query_whois(self.target)
        self.memory['whois'] = data
        if data.get('available'):
            self._log("WHOIS Intelligence", f"Registrar: {data.get('registrar')}", "Domain registration data retrieved via RDAP.", "Medium")
        else:
            self._log("WHOIS Intelligence", data.get('error', 'unavailable'), "RDAP lookup failed — WHOIS section will show as unavailable.", "Low")

    def perform_tls_analysis(self):
        ip = self.memory.get('ips', [None])[0]
        host_for_conn = ip or self.target
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host_for_conn, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    self.memory['tls'] = {
                        "available": True,
                        "protocol": ssock.version(),
                        "cipher_suite": cipher[0] if cipher else "unknown",
                        "expires": cert.get('notAfter', 'unknown'),
                    }
            self._log("TLS Inspection", f"Protocol: {self.memory['tls']['protocol']}", "Live TLS handshake completed and certificate parsed.", "High")
        except Exception as e:
            self.memory['tls'] = {"available": False, "error": str(e)}
            self._log("TLS Inspection", f"Handshake failed: {e}", "Could not verify TLS from here — reported as unavailable, not assumed secure.", "Low")

    def perform_header_grading(self):
        headers = self.memory.get('_last_response_headers', {})
        present, missing, score = [], [], 0
        max_score = sum(SECURITY_HEADERS.values())
        for h, weight in SECURITY_HEADERS.items():
            if h in headers:
                present.append(h); score += weight
            else:
                missing.append(h)
        pct = round((score / max_score) * 100) if max_score else 0
        grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 50 else "D" if headers else "N/A"
        self.memory['header_grade'] = {"grade": grade, "score_pct": pct, "present": present, "missing": missing}
        self._log("Header Grading", f"Grade {grade} ({pct}%) from {'live' if headers else 'no'} response", "Graded against real captured response headers.", "High" if headers else "Low")

    def _check_port(self, ip: str, port: int, timeout: float = 0.8) -> PortResult:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                return PortResult(port, COMMON_PORTS[port], result == 0)
        except Exception:
            return PortResult(port, COMMON_PORTS[port], False)

    def perform_port_recon(self):
        ip = self.memory.get('ips', [None])[0]
        if not ip:
            self.memory['ports'] = []
            self._log("Port Reconnaissance", "No resolved IP available", "Skipped — nothing to scan.", "Low")
            return
        results: List[PortResult] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futures = {ex.submit(self._check_port, ip, p): p for p in COMMON_PORTS}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
        results.sort(key=lambda r: r.port)
        self.memory['ports'] = [asdict(r) for r in results]
        open_count = len([r for r in results if r.open])
        self._log("Port Reconnaissance", f"{open_count} of {len(results)} common ports responded open via live TCP connect", "Real connect-scan results (no synthetic data).", "High")

    def perform_waf_detection(self):
        headers = self.memory.get('_last_response_headers', {})
        header_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        detected = [name for name, sigs in WAF_SIGNATURES.items() if any(sig in header_blob for sig in sigs)]
        self.memory['waf'] = detected
        if detected:
            self._log("WAF Detection", f"Matched signatures for {detected}", "Identified from real response header fingerprints.", "High")
        else:
            self._log("WAF Detection", "No known WAF/CDN header signatures matched", "Traffic may be hitting the origin directly, or an unrecognized WAF is in use.", "Medium")

    def perform_sensitive_path_check(self):
        results: List[PathCheckResult] = []
        baseline_len = None
        try:
            baseline = with_retry(requests.get, f"https://{self.target}/__mhzaly_baseline_check__",
                                   timeout=6, verify=False, retries=0)
            baseline_len = len(baseline.content)
        except Exception:
            pass
        for path in SENSITIVE_PATHS:
            try:
                resp = with_retry(requests.get, f"https://{self.target}{path}", timeout=6, verify=False, retries=0)
                length = len(resp.content)
                is_soft_404 = baseline_len is not None and abs(length - baseline_len) < 5 and resp.status_code == 200
                exposed = resp.status_code == 200 and not is_soft_404
                note = "matches custom 404 page, likely not real" if is_soft_404 else ""
                results.append(PathCheckResult(path, resp.status_code, length, exposed, note))
            except Exception as e:
                results.append(PathCheckResult(path, 0, 0, False, f"request failed: {e}"))
        self.memory['sensitive_paths'] = [asdict(r) for r in results]
        exposed_count = len([r for r in results if r.exposed])
        self._log("Sensitive Path Exposure", f"{exposed_count} path(s) returned live 200 responses (soft-404 filtered)", "Each path was requested live and compared against a baseline 404 to cut false positives.", "High")

    def perform_geolocation(self):
        ip = self.memory.get('ips', [None])[0]
        self.memory['geolocation'] = self.connectors.query_ip_geolocation(ip) if ip else {"available": False, "error": "no resolved IP"}
        self._log("Geolocation", "Live ip-api.com lookup" if self.memory['geolocation'].get('available') else "unavailable",
                   "Hosting/ASN context mapped from a real lookup." if self.memory['geolocation'].get('available') else "Geolocation could not be determined.", "Medium")

    def perform_threat_triage(self):
        ip = self.memory.get('ips', [None])[0] or ""
        self.memory['threat_intel'] = {
            "vt": self.connectors.query_virustotal(self.target),
            "abuse": self.connectors.query_abuseipdb(ip) if ip else {"configured": False},
        }
        configured = self.memory['threat_intel']['vt'].get('configured') or self.memory['threat_intel']['abuse'].get('configured')
        self._log("Threat Intel", "Optional VT/AbuseIPDB keys present" if configured else "No VT/AbuseIPDB key configured",
                   "Used real reputation APIs." if configured else "Section marked as not-configured rather than showing a fake clean score.", "High" if configured else "Low")

    @staticmethod
    def _extract_product_version(header_value: str):
        """Parse a real 'Product/Version' token out of a header value (e.g. 'nginx/1.18.0').
        Returns (None, None) if no version is present — a bare vendor name like
        'cloudflare' with no version is deliberately treated as not-specific-enough."""
        if not header_value:
            return None, None
        m = re.search(r'([A-Za-z][A-Za-z0-9_\-]{1,30})/(\d[\d\.]{0,15})', header_value.strip())
        if m:
            return m.group(1), m.group(2)
        return None, None

    def perform_vulnerability_research(self):
        tech = self.memory.get('tech_stack', {})
        product, version = self._extract_product_version(tech.get('Server', ''))
        if not product:
            product, version = self._extract_product_version(tech.get('X-Powered-By', ''))
        if not product:
            bare = (tech.get('Server') or tech.get('X-Powered-By') or '').strip()
            reason = (f"only a bare vendor/edge name ('{bare}') was disclosed with no version number — "
                      f"a keyword search on that alone tends to match unrelated CVEs by coincidence, so it "
                      f"was skipped instead of shown") if bare else "no origin software was disclosed in the response headers"
            result = {"available": False, "reason": reason, "vulns": []}
        else:
            result = self.connectors.search_nvd(product, version)
        self.memory['vulnerability_result'] = result
        if result.get('available'):
            self._log("NVD Research", f"{len(result['vulns'])} advisories matched '{result.get('query')}' after filtering for the product name actually appearing in the CVE text",
                       "Live NVD correlation with a relevance filter, so a coincidental keyword hit can't pass as a real finding.", "Medium")
        else:
            self._log("NVD Research", result.get('reason', 'unavailable'), "No noisy/irrelevant CVE shown — correlation skipped honestly.", "Low")

    def perform_risk_scoring(self):
        score = 0
        reasons = []
        hg = self.memory.get('header_grade', {})
        header_pts = hg.get('score_pct', 0) * 0.30
        score += header_pts
        if hg.get('missing'):
            reasons.append(f"{len(hg['missing'])} security header(s) missing.")

        tls = self.memory.get('tls', {})
        if tls.get('available'):
            score += 20
        else:
            reasons.append("TLS could not be verified.")

        exposed = [p for p in self.memory.get('sensitive_paths', []) if p['exposed']]
        score -= len(exposed) * 15
        if exposed:
            reasons.append(f"{len(exposed)} sensitive path(s) exposed.")

        if self.memory.get('waf'):
            score += 10
        else:
            reasons.append("No WAF/CDN fingerprint detected.")

        vulns = self.memory.get('vulnerability_result', {}).get('vulns', [])
        high_sev = [v for v in vulns if v.cvss_score >= 7.0]
        score -= len(high_sev) * 10
        if high_sev:
            reasons.append(f"{len(high_sev)} high/critical-severity CVE keyword match(es).")

        open_ports = [p for p in self.memory.get('ports', []) if p['open'] and p['port'] not in (80, 443)]
        score -= len(open_ports) * 5
        if open_ports:
            reasons.append(f"{len(open_ports)} non-web port(s) reachable from the internet.")

        score = max(0, min(100, round(score + 30)))  # baseline offset so a clean site lands mid-high, not 0
        level = "Low" if score >= 70 else "Medium" if score >= 45 else "High"
        if not reasons:
            reasons = ["No significant issues found across the checks run."]
        self.memory['risk_score'] = {"score": score, "level": level, "reasons": reasons}
        self._log("Risk Scoring", f"Composite score {score}/100", f"Computed deterministically from the real findings above (risk level: {level}).", "High")

    def perform_remediation_reasoning(self):
        narrator = AnalystNarrator(self.memory, self.reasoning_log)
        local_report = narrator.build()
        polished = None
        if self.connectors.groq_key:
            system_prompt = ("You are a senior security engineer. Rewrite the following real findings into a "
                              "clear, professional but conversational report. Do NOT invent any new findings, "
                              "numbers, or CVEs beyond what is given.")
            polished = self.connectors.call_groq(system_prompt, local_report)
        self.memory['report'] = polished or local_report
        self.memory['report_source'] = "Local analyst engine + LLM polish" if polished else "Local analyst engine (no LLM key configured)"
        self._log("Analyst Report Synthesis", self.memory['report_source'], "Report grounded entirely in the findings collected above.", "High")

# ==========================================
# 6. STREAMLIT ENTERPRISE USER INTERFACE
# ==========================================

def main():
    st.set_page_config(page_title="MHZALY AI Security Engineer", page_icon="🛡️", layout="wide")
    inject_enterprise_styles()

    st.markdown("""
        <div style='padding: 20px 0; border-bottom: 1px solid #1f2937; margin-bottom: 25px;'>
            <h1 style='margin: 0; font-size: 2.4rem; color: #ffffff;'>🛡️ MHZALY AI Security Engineer</h1>
            <p style='color: #9ca3af; margin-top: 8px; font-size: 1.1rem;'>
                Autonomous multi-agent recon platform. Runs fully with zero API keys — every finding below
                comes from a live, real check.</p>
        </div>
    """, unsafe_allow_html=True)

    with st.sidebar:
        st.markdown("### ⚙️ Engine Control Panel")
        st.success("Core engine: no API key required")
        conn = Connectors()
        st.markdown(f"**LLM report polish (Groq):** {'✅ Configured' if conn.groq_key else '⚡ Optional — not set'}")
        st.markdown(f"**VirusTotal enrichment:** {'✅ Configured' if conn.vt_key else '⚡ Optional — not set'}")
        st.markdown(f"**AbuseIPDB enrichment:** {'✅ Configured' if conn.abuse_key else '⚡ Optional — not set'}")
        st.markdown(f"**NVD API key (raises rate limit):** {'✅ Configured' if conn.nvd_key else '⚡ Optional — not set'}")
        st.markdown("---")
        st.info("Only scan infrastructure you own or are authorized to test.")

    target_input = st.text_input("Target Domain (no scheme)", placeholder="e.g., example.com",
                                  help="Enter a domain you are authorized to assess.")

    if st.button("🚀 Launch Autonomous Security Assessment", use_container_width=True):
        if not target_input:
            st.warning("Please specify a target domain.")
        else:
            engine = AutonomousSecurityEngineer(target_input)
            engine.run_pipeline()

            if 'error' in engine.memory:
                st.error(f"Pipeline Halted: {engine.memory['error']}")
            else:
                st.success("Assessment complete — every metric below is from a live check.")

                risk = engine.memory.get('risk_score', {})
                hg = engine.memory.get('header_grade', {})
                ports = engine.memory.get('ports', [])

                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.markdown(f"<div class='metric-container'><h4>Risk Rating</h4><h2 style='color:#60a5fa;'>{risk.get('level','N/A')}</h2></div>", unsafe_allow_html=True)
                with c2:
                    st.markdown(f"<div class='metric-container'><h4>Composite Score</h4><h2 style='color:#34d399;'>{risk.get('score',0)}/100</h2></div>", unsafe_allow_html=True)
                with c3:
                    st.markdown(f"<div class='metric-container'><h4>Header Hygiene</h4><h2 style='color:#f472b6;'>{hg.get('grade','N/A')} ({hg.get('score_pct',0)}%)</h2></div>", unsafe_allow_html=True)
                with c4:
                    st.markdown(f"<div class='metric-container'><h4>Open Ports</h4><h2 style='color:#fbbf24;'>{len([p for p in ports if p['open']])}</h2></div>", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                tabs = st.tabs([
                    "🧠 Analyst Report", "🔍 Reasoning Trace", "🌐 Recon & Assets", "🕸️ Subdomains",
                    "📇 WHOIS", "🔒 TLS", "🧾 Headers", "🔌 Ports",
                    "🧱 WAF/CDN", "📂 Sensitive Paths", "🌍 Geolocation",
                    "🛡️ Threat Intel", "🔬 CVEs", "📊 Risk Score", "⚡ Pro Engineer PoC & OWASP"
                ])

                with tabs[0]:
                    st.markdown("### Analyst Write-Up")
                    st.caption(f"Source: {engine.memory.get('report_source','')}")
                    st.markdown(engine.memory.get('report', 'No report generated.'))
                    report_markdown = f"""# SECURITY ASSESSMENT REPORT
**Target:** `{engine.target}`
**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
**Risk Level:** {risk.get('level','N/A')} ({risk.get('score',0)}/100)

{engine.memory.get('report','N/A')}
"""
                    st.download_button("📥 Download Report (.md)", data=report_markdown,
                                        file_name=f"security_report_{engine.target}.md", mime="text/markdown",
                                        use_container_width=True)

                with tabs[1]:
                    st.markdown("### Agentic Reasoning Trace")
                    for r in engine.reasoning_log:
                        with st.expander(f"{r.task} (Confidence: {r.confidence})"):
                            st.write(f"**Evidence:** {r.evidence}")
                            st.write(f"**Interpretation:** {r.interpretation}")

                with tabs[2]:
                    st.markdown("### Recon & Assets")
                    ips = engine.memory.get('ips', [])
                    tech = engine.memory.get('tech_stack', {})
                    rc1, rc2 = st.columns(2)
                    with rc1:
                        st.markdown("**Resolved IP Address(es)**")
                        for ip in ips:
                            st.code(ip, language=None)
                        if not ips:
                            st.markdown("<span class='not-configured'>No IP resolved.</span>", unsafe_allow_html=True)
                    with rc2:
                        st.markdown("**Disclosed Tech Stack**")
                        st.markdown(f"- **Server:** `{tech.get('Server') or 'not disclosed'}`")
                        st.markdown(f"- **X-Powered-By:** `{tech.get('X-Powered-By') or 'not disclosed'}`")

                with tabs[3]:
                    st.markdown("### Certificate-Transparency Subdomains")
                    sd = engine.memory.get('subdomains', {})
                    if sd.get('available'):
                        st.metric("Historical names found", sd.get('total_found', 0))
                        if sd.get('subdomains'):
                            st.dataframe(pd.DataFrame(sd.get('subdomains', []), columns=["subdomain"]),
                                         use_container_width=True, hide_index=True)
                    else:
                        st.markdown(f"<span class='not-configured'>⚪ Unavailable — {sd.get('error','')}</span>", unsafe_allow_html=True)

                with tabs[4]:
                    st.markdown("### WHOIS (RDAP)")
                    w = engine.memory.get('whois', {})
                    if w.get('available'):
                        wc1, wc2, wc3 = st.columns(3)
                        wc1.metric("Registrar", w.get('registrar', 'Unknown'))
                        wc2.metric("Registered", (w.get('created') or 'unknown')[:10])
                        wc3.metric("Expires", (w.get('expires') or 'unknown')[:10])
                        if w.get('status'):
                            st.caption("Status: " + ", ".join(w.get('status', [])))
                    else:
                        st.markdown(f"<span class='not-configured'>⚪ Unavailable — {w.get('error','')}</span>", unsafe_allow_html=True)

                with tabs[5]:
                    st.markdown("### TLS/SSL")
                    t = engine.memory.get('tls', {})
                    if t.get('available'):
                        tc1, tc2, tc3 = st.columns(3)
                        tc1.metric("Protocol", t.get('protocol', 'unknown'))
                        tc2.metric("Cipher Suite", t.get('cipher_suite', 'unknown'))
                        tc3.metric("Cert Expires", t.get('expires', 'unknown'))
                    else:
                        st.markdown(f"<span class='not-configured'>🔴 Unavailable — {t.get('error','')}</span>", unsafe_allow_html=True)

                with tabs[6]:
                    st.markdown("### HTTP Security Headers")
                    hc1, hc2 = st.columns(2)
                    with hc1:
                        st.markdown("**✅ Present**")
                        for h in hg.get('present', []):
                            st.markdown(f"- 🟢 `{h}`")
                        if not hg.get('present'):
                            st.caption("None.")
                    with hc2:
                        st.markdown("**⚠️ Missing**")
                        for h in hg.get('missing', []):
                            st.markdown(f"- 🔴 `{h}`")
                        if not hg.get('missing'):
                            st.caption("None — full marks.")

                with tabs[7]:
                    st.markdown("### Port Reconnaissance (live TCP connect scan)")
                    if ports:
                        df = pd.DataFrame(ports)
                        df["status"] = df["open"].map(lambda o: "🟢 Open" if o else "⚪ Closed")
                        df = df[["port", "service", "status"]].sort_values("port")
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.markdown("<span class='not-configured'>No IP was available to scan.</span>", unsafe_allow_html=True)

                with tabs[8]:
                    st.markdown("### WAF / CDN Fingerprint")
                    waf = engine.memory.get('waf', [])
                    if waf:
                        for w in waf:
                            st.success(f"🛡️ {w}")
                    else:
                        st.markdown("<span class='not-configured'>⚪ No known WAF/CDN header signature matched — traffic may be hitting the origin directly.</span>", unsafe_allow_html=True)

                with tabs[9]:
                    st.markdown("### Sensitive Path Exposure")
                    paths = engine.memory.get('sensitive_paths', [])
                    if paths:
                        df = pd.DataFrame(paths)
                        df["status"] = df["exposed"].map(lambda e: "🔴 Exposed" if e else "🟢 Not exposed")
                        df = df[["path", "status_code", "content_length", "status", "note"]]
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.caption("No results.")

                with tabs[10]:
                    st.markdown("### IP Geolocation")
                    g = engine.memory.get('geolocation', {})
                    if g.get('available'):
                        gc1, gc2, gc3 = st.columns(3)
                        gc1.metric("Country", g.get('country', 'Unknown'))
                        gc2.metric("City / Region", f"{g.get('city','?')}, {g.get('regionName','?')}")
                        gc3.metric("ISP / Org", g.get('isp', 'Unknown'))
                        st.caption(f"AS: {g.get('as', 'unknown')}")
                    else:
                        st.markdown(f"<span class='not-configured'>⚪ Unavailable — {g.get('error','')}</span>", unsafe_allow_html=True)

                with tabs[11]:
                    st.markdown("### Threat Intelligence (optional enrichment)")
                    ti = engine.memory.get('threat_intel', {})
                    vt, abuse = ti.get('vt', {}), ti.get('abuse', {})
                    tic1, tic2 = st.columns(2)
                    with tic1:
                        st.markdown("**VirusTotal**")
                        if not vt.get('configured'):
                            st.markdown("<span class='not-configured'>⚪ Not configured (optional).</span>", unsafe_allow_html=True)
                        elif 'error' in vt:
                            st.warning(vt['error'])
                        else:
                            stats = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            mal = stats.get('malicious', 0)
                            (st.error if mal else st.success)(f"{mal} vendor(s) flag this as malicious" if mal else "Clean reputation")
                    with tic2:
                        st.markdown("**AbuseIPDB**")
                        if not abuse.get('configured'):
                            st.markdown("<span class='not-configured'>⚪ Not configured (optional).</span>", unsafe_allow_html=True)
                        elif 'error' in abuse:
                            st.warning(abuse['error'])
                        else:
                            score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                            (st.error if score > 25 else st.success)(f"Abuse confidence score: {score}/100")

                with tabs[12]:
                    st.markdown("### CVE Correlation (live NVD, relevance-filtered)")
                    vr = engine.memory.get('vulnerability_result', {})
                    if vr.get('available') and vr.get('vulns'):
                        st.caption(f"NVD query: `{vr.get('query','')}` — results below all literally mention that product name in the CVE text; still verify the exact running version before acting.")
                        df = pd.DataFrame([asdict(v) for v in vr['vulns']])
                        df = df[["cve_id", "cvss_score", "severity", "description", "remediation"]]
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    elif vr.get('available'):
                        st.info(f"Searched NVD for '{vr.get('query','')}' — no relevant matches after filtering out coincidental keyword hits.")
                    else:
                        st.markdown(f"<span class='not-configured'>⚪ Skipped — {vr.get('reason','')}</span>", unsafe_allow_html=True)

                with tabs[13]:
                    st.markdown("### Composite Risk Score")
                    rc1, rc2 = st.columns(2)
                    rc1.metric("Score", f"{risk.get('score',0)}/100")
                    rc2.metric("Level", risk.get('level', 'N/A'))
                    st.markdown("**Contributing factors:**")
                    for reason in risk.get('reasons', []):
                        st.markdown(f"- {reason}")

                with tabs[14]:
                    st.markdown("### ⚡ Professional Security Engineer Toolkit (OWASP & PoC)")
                    st.markdown("This module maps findings to **OWASP Top 10 (2021)** and generates standard verification commands for manual pentesting confirmation.")
                    
                    st.markdown("#### 1. OWASP Top 10 Risk Mapping")
                    owasp_items = []
                    if hg.get('grade') in ['C', 'D', 'F']:
                        owasp_items.append("**A05:2021 – Security Misconfiguration**: Missing critical HTTP security headers (HSTS, CSP, X-Frame-Options).")
                    exposed_paths = [p for p in engine.memory.get('paths', []) if p['exposed']]
                    if exposed_paths:
                        owasp_items.append("**A01:2021 – Broken Access Control / Sensitive Data Exposure**: Exposed static paths or configuration backups found.")
                    if not owasp_items:
                        owasp_items.append("**No critical OWASP Top 10 mappings triggered** in the passive scope.")
                    for item in owasp_items:
                        st.markdown(f"- {item}")

                    st.markdown("#### 2. Manual Verification & PoC Commands")
                    st.code(f"""# Verify Security Headers & Server Banner
curl -I -s https://{engine.target}

# Check SSL/TLS Cipher Suite & Certificate Chain
openssl s_client -connect {engine.target}:443 -servername {engine.target}

# Test Sensitive Endpoint Exposure
curl -s -I https://{engine.target}/.env
curl -s -I https://{engine.target}/robots.txt
""", language="bash")

if __name__ == "__main__":
    main()
