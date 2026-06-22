import os
import re
import requests
import pandas as pd
from pydantic import BaseModel, Field
from typing import List

# --- AI EXTRACTION DATA MODELS ---
class IoC(BaseModel):
    indicator: str = Field(description="The specific indicator, e.g., an IP address, domain, or file hash.")
    type: str = Field(description="The type of indicator, e.g., 'IPv4', 'Domain', 'SHA256'.")

class ThreatIntelReport(BaseModel):
    threat_actors: List[str] = Field(description="Known threat actors, ransomware gangs, or APT groups.")
    targeted_industries: List[str] = Field(description="Specific industries, sectors, or regions targeted.")
    iocs: List[IoC] = Field(description="List of all Indicators of Compromise extracted.")
    summary: str = Field(description="A concise 2-3 sentence executive summary of the threat.")

def scrape_messy_html(url: str) -> str:
    """Extracts clean text paragraphs natively without BeautifulSoup."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    
    html_content = response.text
    html_content = re.sub(r'<(script|style|nav|footer|header|aside).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    paragraphs = re.findall(r'<p[^>]*>(.*?)</p>', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    clean_text = []
    for p in paragraphs:
        text_only = re.sub(r'<[^>]+>', '', p).strip()
        if text_only:
            clean_text.append(text_only)
            
    return "\n".join(clean_text)

def extract_threat_intel(raw_text: str, source_url: str) -> ThreatIntelReport:
    """Uses standard REST requests to bypass SDK dependency limits."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("API Key is missing. Please enter it in the Deep Analysis tab.")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={api_key}"
    
    prompt = f"""
    You are an expert Threat Intelligence Analyst for the Aegis360 platform. 
    Analyze the following raw OSINT text and extract the required intelligence. 
    
    CRITICAL INSTRUCTIONS:
    - If a field is not explicitly present in the text, return an empty list.
    - Do not invent, assume, or infer IoCs; only extract exact matches found in the text.
    - Defang all IoCs in your textual summary, but keep them intact in the structured 'iocs' array.
    - You must output valid JSON matching the exact schema requested.
    
    Source URL: {source_url}
    Raw Text:
    {raw_text}
    """
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1
        }
    }
    
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status() 
    
    data = response.json()
    extracted_text = data['candidates'][0]['content']['parts'][0]['text']
    
    return ThreatIntelReport.model_validate_json(extracted_text)

def get_osint_feeds():
    feeds = [
        {"Source": "TLDR Sec", "Headline": "Critical Zero-Day vulnerabilities discovered in widely used OpenSSL libraries", "Severity": "High", "Category": "Vulnerability"},
        {"Source": "Risky Biz", "Headline": "Active cyber espionage campaign targets critical health sector infrastructure via VPN flaws", "Severity": "Critical", "Category": "Campaign"},
        {"Source": "SANS ISC", "Headline": "Daily Stormcast indicates a massive localized spike in port 22 scanner activity", "Severity": "Medium", "Category": "Scanning"},
        {"Source": "Unsupervised Learning", "Headline": "Defensive paradigms shifting radically as AI-driven prompt injection vectors mature", "Severity": "Low", "Category": "Research"}
    ]
    return pd.DataFrame(feeds)
