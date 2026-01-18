import subprocess
import json
import os
import requests
from slither import Slither

# --- CONFIGURATION ---
TIMEOUT_SLITHER = 300
TIMEOUT_ECHIDNA = 600
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- HELPER: GEMINI CLIENT ---


def query_gemini(prompt):
    if not GEMINI_API_KEY:
        return None
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        headers = {"Content-Type": "application/json"}

        res = requests.post(url, json=payload, headers=headers, timeout=30)
        if res.status_code == 200:
            return res.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None
    return None

# --- FEATURE 1: AUTO-SURGEON (AI REMEDIATION) ---


def generate_fix(issue, source_code):
    print(f"🚑 Generating fix for: {issue['description'][:50]}...")

    prompt = f"""
    You are a Solidity Security Expert.
    
    VULNERABILITY: {issue['description']}
    FILE: {issue['file']}
    
    BROKEN CODE SNIPPET:
    {source_code}
    
    TASK:
    Rewrite the code to FIX this specific vulnerability.
    1. Return ONLY the fixed Solidity code block.
    2. Do NOT explain.
    3. Keep comments minimal.
    """

    fix = query_gemini(prompt)
    if fix:
        return fix.replace("```solidity", "").replace("```", "").strip()
    return "Fix generation failed."

# --- FEATURE 2: THE JUDGE (FALSE POSITIVE FILTER) ---


def check_false_positive(issue, source_code):
    # Only check High/Critical to save time/cost
    if issue['severity'] not in ["High", "Critical"]:
        return False

    print(f"⚖️ Judging validity of: {issue['description'][:50]}...")

    prompt = f"""
    You are a Senior Smart Contract Auditor.
    
    A static analysis tool flagged this code as a vulnerability.
    
    VULNERABILITY: {issue['description']}
    CODE:
    {source_code}
    
    QUESTION: Is this a REAL vulnerability or a FALSE POSITIVE?
    - If it is a real risk, answer "REAL".
    - If it is a false positive (e.g., protected by modifiers, non-reentrant logic), answer "FALSE".
    
    ANSWER (Single Word):
    """

    verdict = query_gemini(prompt)
    if verdict and "FALSE" in verdict.upper():
        print("🚫 AI dismissed this as a False Positive.")
        return True
    return False

# --- FEATURE 3: GAS OPTIMIZATION REPORT ---


def get_gas_report(slither_results):
    print("⛽ Compiling Gas Report...")
    # Slither detectors that relate to gas
    gas_detectors = [
        "external-function", "const-functions", "immutable-states",
        "dead-code", "cache-array-length", "similar-functions"
    ]

    savings = []
    for i in slither_results:
        if i['check'] in gas_detectors:
            savings.append(i)

    return savings

# --- MAIN SCAN LOGIC ---


def step_slither_enhanced():
    # 1. Run Standard Slither
    cmd = ["slither", ".", "--json", "-"]
    stdout = run_command(cmd)

    issues = []
    gas_issues = []

    if stdout:
        try:
            start = stdout.find('{')
            end = stdout.rfind('}') + 1
            data = json.loads(stdout[start:end])

            # Helper to get source
