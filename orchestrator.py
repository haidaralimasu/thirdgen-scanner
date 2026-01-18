import subprocess
import json
import os
import requests
import sys
import glob

# --- CONFIGURATION & CONSTANTS ---
TIMEOUT_SLITHER = 300
TIMEOUT_MYTHRIL = 600
TIMEOUT_ADERYN = 120
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Default paths to ignore if config is missing
DEFAULT_EXCLUDES = ["lib/", "node_modules/", "test/", "script/", "mock/"]

# --- HELPER: LOAD CONFIG ---


def load_config():
    config = {
        "exclude_paths": DEFAULT_EXCLUDES,
        "solc_version": "0.8.25"
    }

    if os.path.exists("thirdgen.config.json"):
        try:
            with open("thirdgen.config.json", "r") as f:
                user_conf = json.load(f)
                if "exclude_paths" in user_conf:
                    config["exclude_paths"] = user_conf["exclude_paths"]
        except Exception as e:
            print(f"⚠️ Could not load config: {e}")

    return config

# --- HELPER: RUN COMMAND ---


def run_command(command, timeout=300):
    try:
        if not command or not command[0]:
            return None
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

# --- HELPER: GEMINI CLIENT ---


def query_gemini(prompt):
    if not GEMINI_API_KEY:
        return None
    try:
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        headers = {"Content-Type": "application/json"}
        # Increased timeout for long POCs
        res = requests.post(url, json=payload, headers=headers, timeout=45)
        if res.status_code == 200:
            return res.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None
    return None

# --- HELPER: GET SOURCE CODE ---


def get_src(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return f.read()
    except:
        pass
    return ""

# --- FEATURE: ELITE ANALYSIS (The "Best in Market" Prompt) ---


def analyze_issue(issue, source_code, issue_id):
    print(f"🧠 Analyzing Issue {issue_id}: {issue['description'][:50]}...")

    prompt = f"""
    You are an Elite Smart Contract Security Researcher (top ranking on Code4rena/Sherlock).
    You have found a Critical Vulnerability. Your job is to write the Audit Report.

    --- CONTEXT ---
    VULNERABILITY TYPE: {issue['description']}
    FILE: {issue['file']}
    SOURCE CODE:
    {source_code}

    --- TASK ---
    Write a rigorous audit finding in the EXACT format below.
    
    --- REQUIRED FORMAT ---
    
    ### {issue_id} [Short Title of Bug]

    **Description:**
    (Deep technical explanation of the root cause. Trace the execution flow. Explain WHY it is broken, referencing specific variables and lines.)

    **Vulnerable Code:**
    ```solidity
    (Quote ONLY the specific lines that cause the bug. Do not dump the whole file.)
    ```

    **Proof of Concept (POC):**
    (Write a complete, standalone Foundry test case. Assume 'Forge' environment. The test must demonstrate the exploit, e.g., stealing funds or freezing the contract.)
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    import "forge-std/Test.sol";
    import "../src/{issue['file'].split('/')[-1]}";

    contract ExploitTest is Test {{
        // Setup and run exploit
        function testExploit() public {{
            // ... your exploit logic here ...
        }}
    }}
    ```

    **Recommendation:**
    (Provide the specific architectural fix or code change required to prevent this.)
    """

    analysis = query_gemini(prompt)
    if analysis:
        # Remove any main markdown wrappers if Gemini adds them
        clean = analysis.replace("```markdown", "").strip()
        # If the AI included the header "### H-01", remove it so we can control formatting
        if clean.startswith("###"):
            clean = "\n".join(clean.split("\n")[1:])
        return clean
    return None

# --- STEP 1: SLITHER ---


def step_slither(exclude_paths):
    print("🔍 Running Slither...")
    cmd = ["slither", ".", "--json", "-"]
    stdout = run_command(cmd, TIMEOUT_SLITHER)
    issues = []

    if stdout:
        try:
            start = stdout.find('{')
            end = stdout.rfind('}') + 1
            if start != -1:
                data = json.loads(stdout[start:end])
                for i in data.get("results", {}).get("detectors", []):
                    file_path = i.get("elements", [{}])[0].get(
                        "source_mapping", {}).get("filename_relative", "")
                    if any(x in file_path for x in exclude_paths):
                        continue

                    issues.append({
                        "tool": "Slither",
                        "severity": i.get("impact", "Unknown"),
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("check", "Unknown")
                    })
        except:
            pass
    return issues

# --- STEP 2: ADERYN ---


def step_aderyn(exclude_paths):
    print("🦜 Running Aderyn...")
    cmd = ["aderyn", ".", "-o", "report.json", "-x", ",".join(exclude_paths)]
    run_command(cmd, TIMEOUT_ADERYN)
    issues = []

    if os.path.exists("report.json"):
        try:
            with open("report.json", "r") as f:
                data = json.load(f)
            severity_map = {"critical_issues": "Critical",
                            "high_issues": "High", "medium_issues": "Medium"}
            for key, sev in severity_map.items():
                for i in data.get(key, {}).get("issues", []):
                    if not i.get("instances"):
                        continue
                    file_path = i["instances"][0].get("contract_path", "")
                    if any(x in file_path for x in exclude_paths):
                        continue

                    issues.append({
                        "tool": "Aderyn",
                        "severity": sev,
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("title", "Unknown")
                    })
            os.remove("report.json")
        except:
            pass
    return issues

# --- GENERATE REPORT ---


def generate_report(all_issues):
    if not all_issues:
        return "✅ No critical security issues found."

    # Filter for AI analysis (High/Critical only)
    high_crit = [i for i in all_issues if i['severity']
                 in ["High", "Critical"]]
    medium = [i for i in all_issues if i['severity'] == "Medium"]

    md = ["# 🛡️ ThirdGen Audit Report\n"]

    md.append(
        f"**Summary:** Found {len(high_crit)} High/Critical and {len(medium)} Medium issues.\n")

    # PROCESS HIGH/CRITICAL WITH AI
    if high_crit:
        md.append("## 🚨 High & Critical Findings")

        for idx, issue in enumerate(high_crit):
            issue_id = f"H-{str(idx+1).zfill(2)}"  # H-01, H-02

            # If we have an API Key, use AI to generate the full report
            if GEMINI_API_KEY:
                src = get_src(issue['file'])
                ai_report = analyze_issue(issue, src, issue_id)
                if ai_report:
                    # AI generated the full body
                    md.append(f"### {issue_id} [{issue['check']}]")
                    md.append(ai_report)
                    md.append("\n---\n")
                    continue

            # Fallback if no AI or AI failed
            md.append(f"### {issue_id} [{issue['check']}]")
            md.append(f"**Description:** {issue['description']}")
            md.append(f"**File:** `{issue['file']}`")
            md.append("\n---\n")

    # PROCESS MEDIUM (Standard List)
    if medium:
        md.append("## ⚠️ Medium Findings")
        for idx, issue in enumerate(medium):
            md.append(f"**M-{str(idx+1).zfill(2)} [{issue['check']}]**")
            md.append(f"File: `{issue['file']}`")
            md.append(f"Description: {issue['description']}\n")

    return "\n".join(md)

# --- MAIN ---


def main():
    print("🚀 STARTING AUDIT...")
    config = load_config()

    all_issues = []
    all_issues.extend(step_slither(config["exclude_paths"]))
    all_issues.extend(step_aderyn(config["exclude_paths"]))

    # Generate Report
    report = generate_report(all_issues)

    # Save & Post
    with open("report.md", "w") as f:
        f.write(report)
    print("✅ Audit Complete.")

    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    if token and repo and "pull" in os.getenv("GITHUB_REF", ""):
        try:
            pr_num = os.getenv("GITHUB_REF").split("/")[-2]
            # ✅ CORRECT CODE (Copy this exactly)
            url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
            headers = {"Authorization": f"token {token}",
                       "Accept": "application/vnd.github.v3+json"}

            # Update or Post
            existing = requests.get(url, headers=headers).json()
            if isinstance(existing, list):
                for c in existing:
                    if "ThirdGen Audit Report" in c.get("body", ""):
                        requests.patch(
                            f"{url}/{c['id']}", json={"body": report}, headers=headers)
                        return
            requests.post(url, json={"body": report}, headers=headers)
        except Exception as e:
            print(f"⚠️ Github Comment Error: {e}")


if __name__ == "__main__":
    main()
