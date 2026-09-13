#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MHZALY AI SECURITY ENGINEER - AUTONOMOUS AGENT SYSTEM v21.2 (No External DNS Dependency)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
from typing import Dict, List, Any, Callable
from dataclasses import dataclass, asdict
import socket
import re

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
    """Simple retry with exponential backoff for HTTP calls."""
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

# ==========================================
# 2. AI CONNECTORS (APIs)
# ==========================================

class AIConnectors:
    def __init__(self):
        self.vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
        self.nvd_key = st.secrets.get("NVD_API_KEY", "")
        self.groq_key = st.secrets.get("GROQ_API_KEY", "")

    def query_virustotal(self, indicator: str) -> Dict[str, Any]:
        if not self.vt_key: return {"error": "VirusTotal API Key missing."}
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator)
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}" if is_ip else \
              f"https://www.virustotal.com/api/v3/domains/{indicator}"
        try:
            resp = with_retry(requests.get, url, headers={'x-apikey': self.vt_key}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"VT Error: {resp.status_code}"}
        except Exception as e: return {"error": f"VT Connection Failed: {e}"}

    def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.abuse_key: return {"error": "AbuseIPDB API Key missing."}
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip): return {"error": "Invalid IP format."}
        try:
            resp = with_retry(requests.get, "https://api.abuseipdb.com/api/v2/check",
                             headers={'Key': self.abuse_key, 'Accept': 'application/json'},
                             params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": f"AbuseIPDB Error: {resp.status_code}"}
        except Exception as e: return {"error": f"AbuseIPDB Connection Failed: {e}"}

    def search_nvd(self, keyword: str, max_results: int = 5) -> List[VulnerabilityRecord]:
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
                    
                    cvss_data = {}
                    if 'cvssMetricV31' in metrics: cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    elif 'cvssMetricV30' in metrics: cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    elif 'cvssMetricV2' in metrics: cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    
                    score = float(cvss_data.get('baseScore', 0.0))
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    vulns.append(VulnerabilityRecord(
                        cve_id=cve_id, title=cve_id, cvss_score=score, severity=severity,
                        description=desc, remediation=f"Apply vendor patch for {cve_id}.", match_confidence="keyword"
                    ))
        except Exception as e: logger.error(f"NVD Error: {e}")
        return sorted(vulns, key=lambda x: x.cvss_score, reverse=True)

    def call_groq(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096, temperature: float = 0.2) -> str:
        if not self.groq_key: return "ERROR: Groq API Key missing in secrets."
        try:
            payload = {
                'model': 'llama-3.1-70b-versatile',
                'messages': [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}],
                'temperature': temperature,
                'max_tokens': max_tokens
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
        logger.info(f"Agent Reasoning [{task}]: {interpretation} (Confidence: {confidence})")
        self.reasoning_log.append(AgenticReasoning("SecurityEngineer", task, evidence, interpretation, confidence))

    def run_pipeline(self):
        if not self.target: return

        with st.status(f"🚀 Launching Autonomous AI Security Engineer for: {self.target}...", expanded=True) as status:
            st.write("Agent 1: 🌐 Performing Authorized Reconnaissance...")
            self.perform_recon()
            
            if 'error' not in self.memory:
                st.write("Agent 2: 🛡️ Triaging Threat Intelligence...")
                self.perform_threat_triage()
            
            if 'error' not in self.memory:
                st.write("Agent 3: 🔬 Researching NVD Vulnerabilities...")
                self.perform_vulnerability_research()
                
            if 'error' not in self.memory:
                st.write("Agent 4: 🧠 Synthesizing Remediation Strategy...")
                self.perform_remediation_reasoning()
            
            if 'error' in self.memory:
                status.update(label="❌ Autonomous Pipeline Failed", state="error")
            else:
                status.update(label="✅ Autonomous Pipeline Completed", state="complete", expanded=False)

    def perform_recon(self):
        try:
            assert_public_host(self.target)
            
            # Use built-in socket for DNS resolution instead of dnspython
            infos = socket.getaddrinfo(self.target, None)
            ips = list(set(addr[4][0] for addr in infos if addr[0] == socket.AF_INET))
            self.memory['ips'] = ips
            self._log_reasoning("DNS Resolution", f"{self.target} resolved to {', '.join(ips)}", "Target is publicly resolvable.", "High")

            subdomains = []
            try:
                resp = with_retry(requests.get, f"https://crt.sh/?q=%25.{self.target}&output=json", timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = list(set(entry['name_value'].strip() for entry in data if self.target in entry['name_value']))
            except Exception as e: logger.warning(f"crt.sh failed: {e}")
            self.memory['subdomains'] = subdomains[:100]
            self._log_reasoning("Subdomain Enumeration", f"Found {len(subdomains)} certificates.", "Expanded attack surface mapped.", "Medium")

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
        if 'error' in self.memory: return
        
        targets_to_triage = self.memory.get('ips', [])
        if not re.match(r'^\d+\.\d+\.\d+\.\d+', self.target):
             targets_to_triage.append(self.target)

        intel_reports = {}
        for item in targets_to_triage:
            vt_res = self.connectors.query_virustotal(item)
            abuse_res = self.connectors.query_abuseipdb(item)
            
            report = {'vt': vt_res, 'abuse': abuse_res}
            intel_reports[item] = report
            
            risk = "Low"
            m_count = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            abuse_score = abuse_res.get('data', {}).get('abuseConfidenceScore', 0)
            
            if m_count > 0 or abuse_score > 0: risk = "Medium"
            if m_count > 5 or abuse_score > 50: risk = "High"

            self._log_reasoning(f"Threat Triage: {item}", f"VT Malicious: {m_count}, Abuse Score: {abuse_score}%", f"Indicator risk assessed as {risk}.", "High")
        
        self.memory['threat_intel'] = intel_reports

    def perform_vulnerability_research(self):
        if 'error' in self.memory: return
        
        keywords = []
        tech = self.memory.get('tech_stack', {})
        if tech.get('X-Powered-By') != 'Unknown': keywords.append(tech.get('X-Powered-By'))
        if tech.get('Server') != 'Unknown': keywords.append(tech.get('Server').split('/')[0])
        keywords.append(self.target.split('.')[0])
        
        all_cves = []
        for kw in list(set(keywords)):
            cves = self.connectors.search_nvd(kw)
            all_cves.extend(cves)
            self._log_reasoning(f"NVD Search: {kw}", f"Found {len(cves)} CVEs", f"Correlated {kw} with known vulnerabilities.", "Medium" if cves else "High")
        
        unique_cves = {cve.cve_id: cve for cve in all_cves}
        self.memory['vulnerabilities'] = list(unique_cves.values())

    def perform_remediation_reasoning(self):
        if 'error' in self.memory: return
        
        context = f"Target: {self.target}\n"
        context += f"Tech Stack: {json.dumps(self.memory.get('tech_stack', {}))}\n"
        context += f"Threat Intel: {json.dumps(self.memory.get('threat_intel', {}))}\n"
        context += f"Vulnerabilities (Top 5): {json.dumps([asdict(v) for v in self.memory.get('vulnerabilities', [])[:5]])}\n"
        
        system_prompt = """
        You are an elite Autonomous AI Security Engineer. Your goal is to analyze the provided security telemetry (Recon, Threat Intel, CVEs)
        and formulate a professional, risk-adjusted remediation strategy. Provide clear executive insights, reasoning traces, and recommended fixes.
        """
        
        ai_response = self.connectors.call_groq(system_prompt, f"Analyze this telemetry and provide a comprehensive security report:\n{context}")
        self.memory['ai_report'] = ai_response
        self._log_reasoning("AI Remediation Strategy", "Telemetry synthesized by Groq AI model", "Generated automated tactical security guidance and executive report.", "High")

# ==========================================
# 4. STREAMLIT USER INTERFACE
# ==========================================

def main():
    st.set_page_config(page_title="MHZALY AI Security Engineer", page_icon="🛡️", layout="wide")
    
    st.markdown("# 🛡️ MHZALY AI Security Engineer")
    st.markdown("<p style='color: #9ca3af;'>Autonomous multi-agent platform for deep target recon, threat intelligence triage, NVD vulnerability correlation, and AI-driven remediation strategy.</p>", unsafe_allow_html=True)

    with st.sidebar:
        st.subheader("🔑 API Configuration Status")
        st.write(f"**VirusTotal API:** {'✅ Active' if st.secrets.get('VIRUSTOTAL_API_KEY') else '⚠️ Missing'}")
        st.write(f"**AbuseIPDB API:** {'✅ Active' if st.secrets.get('ABUSEIPDB_API_KEY') else '⚠️ Missing'}")
        st.write(f"**NVD API:** {'✅ Active' if st.secrets.get('NVD_API_KEY') else '⚠️ Optional/Standard'}")
        st.write(f"**Groq AI Engine:** {'✅ Active' if st.secrets.get('GROQ_API_KEY') else '⚠️ Missing'}")
        st.markdown("---")
        st.info("Ensure all keys are placed in your Streamlit secrets (`st.secrets`).")

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
                
                tab1, tab2, tab3, tab4 = st.tabs(["🧠 AI Executive Report", "🔍 Reasoning Trace", "🛡️ Threat Intel & Assets", "🔬 Correlated CVEs"])
                
                with tab1:
                    st.markdown("### Executive Strategy & Remediation")
                    st.markdown(engine.memory.get('ai_report', 'No report generated.'))
                    
                    report_markdown = f"""# AI SECURITY ENGINEER ASSESSMENT REPORT
**Target:** `{engine.target}`
**Timestamp:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`

## Executive Summary & AI Strategy
{engine.memory.get('ai_report', 'N/A')}
"""
                    st.download_button("📥 Download Assessment Report (.md)", data=report_markdown, file_name=f"ai_security_report_{engine.target}.md", mime="text/markdown", use_container_width=True)

                with tab2:
                    st.markdown("### Agentic Reasoning Trace")
                    for r in engine.reasoning_log:
                        with st.expander(f"Task: {r.task} (Confidence: {r.confidence})"):
                            st.write(f"**Evidence:** {r.evidence}")
                            st.write(f"**Interpretation:** {r.interpretation}")

                with tab3:
                    st.markdown("### Reconnaissance & Threat Intel")
                    st.write(f"**Resolved IPs:** {engine.memory.get('ips', [])}")
                    st.write(f"**Tech Stack:** {engine.memory.get('tech_stack', {})}")
                    
                    subdomains = engine.memory.get('subdomains', [])
                    if subdomains:
                        st.markdown(f"**Enumerated Subdomains ({len(subdomains)}):**")
                        st.dataframe(pd.DataFrame({'Subdomain': subdomains}), use_container_width=True)
                        
                    threats = engine.memory.get('threat_intel', {})
                    if threats:
                        st.markdown("**Threat Intelligence Triage:**")
                        st.json(threats)

                with tab4:
                    st.markdown("### Correlated NVD Vulnerabilities")
                    cves = engine.memory.get('vulnerabilities', [])
                    if cves:
                        cve_data = [asdict(c) for c in cves]
                        st.dataframe(pd.DataFrame(cve_data), use_container_width=True)
                    else:
                        st.info("No matching high-confidence CVEs found for the fingerprinted stack.")

if __name__ == "__main__":
    main()
