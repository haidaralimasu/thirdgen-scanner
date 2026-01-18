import subprocess
import json
import os
import requests
import sys

# --- CONFIGURATION ---
TIMEOUT_SLITHER = 300
TIMEOUT_ECHIDNA = 600
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- HELPER: RUN COMMAND ---


def run_command(command):
    try:
        # Check if tool exists first
        if not command or not command[0]:
            return None
        return subprocess.run(command, capture_output=True, text=True, timeout=300).stdout
    except Exception as e:
        print(f"⚠️ Command failed: {e}")
        return None

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

# --- HELPER: GET SOURCE CODE (Moved here to fix Syntax Error) ---


def get_src(element):
    try:
        path = element['source_mapping']['filename_absolute']
        if os.path.exists(path):
            with open(path, 'r') as f:
                return f.read()
    except:
        pass
    return ""

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
    """

    fix = query_gemini(prompt)
    if fix:
        return fix.replace("```solidity", "").replace("```", "").strip()
    return None

# --- FEATURE 2: THE JUDGE (FALSE POSITIVE FILTER) ---


def check_false_positive(issue, source_code):
    if issue['severity'] not in ["High", "Critical"]:
        return False

    print(f"⚖️ Judging validity of: {issue['description'][:50]}...")

    prompt = f"""
    You are a Senior Smart Contract Auditor.
    VULNERABILITY: {issue['description']}
    CODE:
    {source_code}
    
    QUESTION: Is this a REAL vulnerability or a FALSE POSITIVE?
    Answer "REAL" or "FALSE".
    """

    verdict = query_gemini(prompt)
    if verdict and "FALSE" in verdict.upper():
        print("🚫 AI dismissed this as a False Positive.")
        return True
    return False

# --- MAIN SCAN LOGIC ---


def step_slither_enhanced():
    print("🔍 Running Slither...")
    cmd = ["slither", ".", "--json", "-"]
    stdout = run_command(cmd)

    issues = []
    gas_issues = []

    if stdout:
        try:
            # Parse JSON output from Slither
            # Slither sometimes outputs logs before JSON, so we find the first '{'
            start = stdout.find('{')
            end = stdout.rfind('}') + 1
            if start == -1 or end == -1:
                return [], []

            json_str = stdout[start:end]
            data = json.loads(json_str)

            detectors = data.get("results", {}).get("detectors", [])

            for i in detectors:
                check_type = i.get("check", "Unknown")

                # Basic issue object
                minified = {
                    "tool": "slither",
                    "severity": i.get("impact", "Unknown"),
                    "file": i.get("elements", [{}])[0].get("source_mapping", {}).get("filename_relative", "Unknown"),
                    "description": i.get("description", ""),
                    "check": check_type
                }

                # A. Gas Optimization Path
                gas_detectors = ["external-function", "const-functions",
                                 "immutable-states", "dead-code", "cache-array-length"]
                if check_type in gas_detectors:
                    minified['severity'] = "Optimization"
                    gas_issues.append(minified)
                    continue

                # B. Security Path
                if GEMINI_API_KEY and minified['severity'] in ["High", "Critical"]:
                    element = i.get("elements", [{}])[0]
                    src = get_src(element)

                    if src:
                        # 1. AI Filter
                        if check_false_positive(minified, src):
                            continue
                        # 2. AI Fix
                        minified['fix'] = generate_fix(minified, src)

                issues.append(minified)

        except Exception as e:
            print(f"⚠️ Error parsing Slither output: {e}")

    return issues, gas_issues

# --- GENERATE MARKDOWN REPORT ---


def generate_report(security_issues, gas_issues):
    md = ["# 🛡️ Security & Gas Report"]

    # 1. SECURITY SECTION
    md.append(f"\n## 🔴 Security Findings ({len(security_issues)})")
    if not security_issues:
        md.append("✅ No security vulnerabilities found.")
    else:
        for i in security_issues:
            sev = i['severity']
            md.append(f"### {sev}: {i['check']}")
            md.append(f"**File:** `{i['file']}`")
            md.append(f"**Description:** {i['description']}")

            if i.get('fix'):
                md.append(
                    "\n<details><summary><b>🤖 AI Suggested Fix (Click to view)</b></summary>")
                md.append(f"\n```solidity\n{i['fix']}\n```\n")
                md.append("</details>\n")
            md.append("---")

    # 2. GAS OPTIMIZATION SECTION
    md.append(f"\n## ⛽ Gas Optimizations ({len(gas_issues)})")
    if not gas_issues:
        md.append("✅ Code is fully optimized.")
    else:
        md.append("| Optimization | File | Savings Hint |")
        md.append("|---|---|---|")
        for i in gas_issues:
            desc = i['description'].split(":")[0]
            md.append(f"| {i['check']} | `{i['file']}` | {desc} |")

    return "\n".join(md)

# --- POST COMMENT TO GITHUB ---


def post_github_comment(report_body):
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    pr_num = os.getenv("GITHUB_REF").split("/")[-2]  # refs/pull/123/merge

    # Check if this is a PR run
    if not token or not repo or "pull" not in os.getenv("GITHUB_REF", ""):
        print("ℹ️ Not a PR or no token. Skipping comment.")
        return

    print(f"💬 Posting comment to PR #{pr_num}...")
    url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 1. Find existing bot comment to update (avoid spam)
    try:
        existing_comments = requests.get(url, headers=headers).json()
        for comment in existing_comments:
            if "🛡️ Security & Gas Report" in comment.get("body", ""):
                # Update existing
                update_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment['id']}"
                requests.patch(update_url, json={
                               "body": report_body}, headers=headers)
                print("✅ Comment updated!")
                return
    except:
        pass

    # 2. Create new comment
    requests.post(url, json={"body": report_body}, headers=headers)
    print("✅ Comment posted!")

# --- MAIN ---


def main():
    print("🚀 STARTING ENHANCED SCAN...")

    # 1. Run Slither
    sec_issues, gas_issues = step_slither_enhanced()

    # 2. Generate Report
    report = generate_report(sec_issues, gas_issues)

    # 3. Post to GitHub
    post_github_comment(report)

    # 4. Save to file (for debugging)
    with open("report.md", "w") as f:
        f.write(report)


if __name__ == "__main__":
    main()
