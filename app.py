#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY AI SECURITY ENGINEER - AUTONOMOUS AGENT SYSTEM v21.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is a complete, self-contained Autonomous AI Security Engineer platform.
It integrates Deep Recon, Threat Intel Triage, NVD Correlation, and
Autonomous Remediation Reasoning into a single, powerful agentic loop.

Author: Muhammad Hassaan Zahid
"""

import streamlit as st
import requests
import pandas as pd
import json
import logging
import time
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import socket
import dns.resolver
import re
import urllib.parse
import concurrent.futures
import hmac

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable insecure request warnings for offensive reconnaissance
requests.packages.urllib3.disable_warnings()

# ==========================================
# 0. CORE SAFETY & CONFIGURATION
# ==========================================

class ScopeViolation(Exception):
    """Raised when a target resolves to a disallowed internal/metadata address."""
    pass

def assert_public_host(hostname: str) -> None:
    """SSRF guard. Resolves `hostname` and raises ScopeViolation if it lands on a private IP."""
    try:
        clean_host = hostname.replace('https://', '').replace('http://', '').split('/')[0]
        infos = socket.getaddrinfo(clean_host, None)
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or
                    ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                raise ScopeViolation(f"Target '{hostname}' resolves to non-public IP ({ip_str}). Refusing to scan internal/reserved network space.")
    except socket.gaierror as e:
        raise ScopeViolation(f"Could not resolve host: {e}")
    except ValueError:
        continue # Should not happen with getaddrinfo

def with_retry(fn: Callable, *args, retries: int = 3, backoff: float = 2.0, **kwargs):
    """Simple retry with exponential backoff for flaky/rate-limited HTTP calls."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn(*args, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.TooManyRequests) as e:
            last_exc = e
            if attempt < retries:
                sleep_time = backoff ** attempt
                logger.warning(f"Retrying in {sleep_time:.1f} seconds due to: {e}")
                time.sleep(sleep_time)
            else:
                logger.error(f"Max retries reached. Last error: {e}")
        except Exception as e:
            logger.error(f"Non-retryable exception: {e}")
            raise e # Don't retry on other exceptions
    raise last_exc

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
    match_confidence: str # cpe or keyword

@dataclass
class AgenticReasoning:
    agent: str
    task: str
    evidence: str
    interpretation: str
    confidence: str # Low, Medium, High

# ==========================================
# 2. AI CONNECTORS (APIs)
# ==========================================

class AIConnectors:
    """Handles all external API communications securely."""
    def __init__(self):
        self.vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
        self.nvd_key = st.secrets.get("NVD_API_KEY", "")
        self.groq_key = st.secrets.get("GROQ_API_KEY", "")
        self.headers_ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) MHZALY-AI-Sec-Eng/21.0'}

    def query_virustotal(self, indicator: str) -> Dict[str, Any]:
        """Queries VirusTotal for domain/IP reputation."""
        if not self.vt_key: return {"error": "VirusTotal API Key missing."}
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip else \
              f"https://www.virustotal.com/api/v3/domains/{indicator}"
        try:
            resp = with_retry(requests.get, url, headers={'x-apikey': self.vt_key}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"VT Error: {resp.status_code}"}
        except Exception as e: return {"error": f"VT Connection Failed: {e}"}

    def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Queries AbuseIPDB for IP reputation."""
        if not self.abuse_key: return {"error": "AbuseIPDB API Key missing."}
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip): return {"error": "Invalid IP format for AbuseIPDB."}
        try:
            resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                             headers={'Key': self.abuse_key, 'Accept': 'application/json'},
                             params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"AbuseIPDB Error: {resp.status_code}"}
        except Exception as e: return {"error": f"AbuseIPDB Connection Failed: {e}"}

    def search_nvd(self, keyword: str, max_results: int = 5) -> List[VulnerabilityRecord]:
        """Searches NIST NVD for CVEs related to a keyword."""
        if not keyword: return []
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
                    
                    # Prefer CVSS v3.1, fallback to v3.0, then v2
                    cvss_data = {}
                    if 'cvssMetricV31' in metrics: cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    elif 'cvssMetricV30' in metrics: cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    elif 'cvssMetricV2' in metrics: cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    
                    score = float(cvss_data.get('baseScore', 0.0))
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    vulns.append(VulnerabilityRecord(
                        cve_id=cve_id,
                        title=cve_id,
                        cvss_score=score,
                        severity=severity,
                        description=desc,
                        remediation=f"Review official NVD advisory for {cve_id} and apply vendor patches.",
                        match_confidence="keyword"
                    ))
            elif resp.status_code == 403:
                 logger.warning("NVD API Key missing or rate limit exceeded (403).")
        except Exception as e: logger.error(f"NVD Error: {e}")
        return sorted(vulns, key=lambda x: x.cvss_score, reverse=True)

    def call_groq(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.2) -> str:
        """Calls Groq API for AI reasoning."""
        if not self.groq_key: return "ERROR: Groq API Key missing in secrets."
        try:
            payload = {
                'model': 'llama-3.1-70b-versatile', # Using a powerful model for reasoning
                'messages': [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}],
                'temperature': temperature,
                'max_tokens': max_tokens,
                'top_p': 0.9,
            }
            resp = with_retry(requests.post, "https://api.groq.com/openai/v1/chat/completions",
                             json=payload, headers={'Authorization': f'Bearer {self.groq_key}', 'Content-Type': 'application/json'}, timeout=60)
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content']
            else:
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

    def _log_reasoning(self, task: str, evidence: str, interpretation: str, confidence: str):
        """Logs agent thought process."""
        logger.info(f"Agent Reasoning [{task}]: {interpretation} (Confidence: {confidence})")
        self.reasoning_log.append(AgenticReasoning("SecurityEngineer", task, evidence, interpretation, confidence))

    def run_pipeline(self):
        """Executes the full autonomous Purple Team pipeline."""
        if not self.target: return

        with st.status(f"🚀 Launching Autonomous AI Security Engineer for: {self.target}...", expanded=True) as status:
            
            # Agent 1: Autonomous Recon
            st.write("Agent 1: 🌐 Performing Authorized Reconnaissance...")
            self.perform_recon()
            
            # Agent 2: Autonomous Threat Triage
            if 'error' not in self.memory:
                st.write("Agent 2: 🛡️ Triaging Threat Intelligence...")
                self.perform_threat_triage()
            
            # Agent 3: Autonomous Vuln Research
            if 'error' not in self.memory:
                st.write("Agent 3: 🔬 Researching NVD Vulnerabilities...")
                self.perform_vulnerability_research()
                
            # Agent 4: Autonomous Remediation Strategist
            if 'error' not in self.memory:
                st.write("Agent 4: 🧠 Synthesizing Remediation Strategy...")
                self.perform_remediation_reasoning()
            
            if 'error' in self.memory:
                status.update(label="❌ Autonomous Pipeline Failed", state="error")
            else:
                status.update(label="✅ Autonomous Pipeline Completed", state="complete", expanded=False)

    def perform_recon(self):
        """Agent 1 Implementation: Recon"""
        try:
            assert_public_host(self.target)
            
            # 1. DNS Resolution
            answers = dns.resolver.resolve(self.target, 'A')
            ips = [str(r) for r in answers]
            self.memory['ips'] = ips
            self._log_reasoning("DNS Resolution", f"{self.target} resolved to {', '.join(ips)}", "Target is publicly resolvable.", "High")

            # 2. Subdomain Enumeration (crt.sh)
            subdomains = []
            try:
                resp = with_retry(requests.get, f"https://crt.sh/?q=%25.{self.target}&output=json", timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = list(set(entry['name_value'].strip() for entry in data if self.target in entry['name_value']))
            except Exception as e: logger.warning(f"crt.sh failed: {e}")
            self.memory['subdomains'] = subdomains[:100] # Limit to top 100
            self._log_reasoning("Subdomain Enumeration", f"Found {len(subdomains)} certificates.", "Expanded attack surface mapped.", "Medium")

            # 3. Banner Grabbing (Tech Stack)
            try:
                resp = requests.get(f"https://{self.target}", timeout=5, verify=False, allow_redirects=True)
                banner = resp.headers.get('Server', 'Unknown')
                powered_by = resp.headers.get('X-Powered-By', 'Unknown')
                self.memory['tech_stack'] = {'Server': banner, 'X-Powered-By': powered_by}
                self._log_reasoning("Banner Grabbing", f"Server: {banner}, X-Powered-By: {powered_by}", "Underlying technology identified.", "Medium")
            except Exception as e:
                 self.memory['tech_stack'] = {'Server': 'Unknown', 'X-Powered-By': 'Unknown'}
                 self._log_reasoning("Banner Grabbing", f"HTTP connection failed: {e}", "Could not grab banners via HTTP.", "Low")

        except ScopeViolation as e:
            self.memory['error'] = str(e)
            self._log_reasoning("Scope Check", str(e), "TARGET OUT OF SCOPE. Halting.", "High")
        except Exception as e:
            self.memory['error'] = str(e)
            self._log_reasoning("Reconnaissance", str(e), "Reconnaissance phase failed.", "High")

    def perform_threat_triage(self):
        """Agent 2 Implementation: Triage"""
        if 'error' in self.memory: return
        
        targets_to_triage = self.memory.get('ips', [])
        if not re.match(r'^\d+\.\d+\.\d+\.\d+', self.target): # If not IP, add target itself
             targets_to_triage.append(self.target)

        intel_reports = {}
        for item in targets_to_triage:
            vt_res = self.connectors.query_virustotal(item)
            abuse_res = self.connectors.query_abuseipdb(item)
            
            report = {'vt': vt_res, 'abuse': abuse_res}
            intel_reports[item] = report
            
            # Quick heuristic risk assessment
            risk = "Low"
            m_count = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            abuse_score = abuse_res.get('data', {}).get('abuseConfidenceScore', 0)
            
            if m_count > 0 or abuse_score > 0:
                risk = "Medium"
            if m_count > 5 or abuse_score > 50:
                risk = "High"

            self._log_reasoning(f"Threat Triage: {item
