import subprocess
import json
import os
import requests
import sys
import glob

# --- CONFIGURATION & CONSTANTS ---
TIMEOUT_SLITHER = 300
TIMEOUT_MYTHRIL = 600  # 10 mins max per file for deep scan
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
                # Merge user config with defaults
                if "exclude_paths" in user_conf:
                    config["exclude_paths"] = user_conf["exclude_paths"]
                if "solc_version" in user_conf:
                    config["solc_version"] = user_conf["solc_version"]
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
        print(f"⏰ Command timed out: {' '.join(command)}")
        return None
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

# --- HELPER: GET SOURCE CODE ---


def get_src(file_path):
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return f.read()
    except:
        pass
    return ""

# --- FEATURE: SMART ANALYSIS (Exploit + Fix) ---


def analyze_issue(issue, source_code):
    print(f"🧠 Analyzing: {issue['description'][:50]}...")

    prompt = f"""
    You are a Black Hat Hacker turned Security Auditor.
    
    VULNERABILITY: {issue['description']}
    FILE: {issue['file']}
    CODE:
    {source_code}
    
    OUTPUT FORMAT (Markdown):
    **Exploit Scenario:**
    (Explain simply how a hacker would exploit this in 2 sentences)
    
    **Fixed Code:**
    ```solidity
    (The corrected code only)
    ```
    """

    analysis = query_gemini(prompt)
    if analysis:
        return analysis.replace("```markdown", "").strip()
    return None

# --- STEP 1: SLITHER (STATIC ANALYSIS) ---


def step_slither(exclude_paths):
    print("🔍 Running Slither...")
    cmd = ["slither", ".", "--json", "-"]
    stdout = run_command(cmd, TIMEOUT_SLITHER)

    issues = []

    if stdout:
        try:
            start = stdout.find('{')
            end = stdout.rfind('}') + 1
            if start != -1 and end != -1:
                data = json.loads(stdout[start:end])
                detectors = data.get("results", {}).get("detectors", [])

                for i in detectors:
                    # FILTER: Check if file is in excluded paths
                    file_path = i.get("elements", [{}])[0].get(
                        "source_mapping", {}).get("filename_relative", "")

                    if any(ignored in file_path for ignored in exclude_paths):
                        continue

                    minified = {
                        "tool": "Slither",
                        "severity": i.get("impact", "Unknown"),
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("check", "Unknown")
                    }

                    # AI Enrichment
                    if GEMINI_API_KEY and minified['severity'] in ["High", "Critical"]:
                        src = get_src(file_path)
                        if src:
                            minified['analysis'] = analyze_issue(minified, src)

                    issues.append(minified)

        except Exception as e:
            print(f"⚠️ Error parsing Slither: {e}")

    return issues

# --- STEP 2: ADERYN (RUST ANALYSIS) ---


def step_aderyn(exclude_paths):
    print("🦜 Running Aderyn...")

    # Aderyn has a native flag '-x' for excludes (comma separated)
    # We join our list "lib/, test/" -> "lib/,test/"
    exclude_string = ",".join(exclude_paths)

    cmd = ["aderyn", ".", "-o", "report.json", "-x", exclude_string]
    run_command(cmd, TIMEOUT_ADERYN)

    issues = []
    if os.path.exists("report.json"):
        try:
            with open("report.json", "r") as f:
                data = json.load(f)

            # Aderyn JSON structure: "high_issues": { "issues": [...] }
            severity_map = {
                "critical_issues": "Critical",
                "high_issues": "High",
                "medium_issues": "Medium"
            }

            for key, severity_label in severity_map.items():
                group = data.get(key, {}).get("issues", [])
                for i in group:
                    # Aderyn typically handles exclusion internally with -x,
                    # but we double check the file path just in case
                    instances = i.get("instances", [])
                    if not instances:
                        continue

                    file_path = instances[0].get("contract_path", "")

                    # Double-check exclusion (redundancy is safety)
                    if any(ignored in file_path for ignored in exclude_paths):
                        continue

                    issues.append({
                        "tool": "Aderyn",
                        "severity": severity_label,
                        "file": file_path,
                        "description": i.get("description", ""),
                        "check": i.get("title", "Unknown")
                    })

            # Cleanup
            os.remove("report.json")

        except Exception as e:
            print(f"⚠️ Error parsing Aderyn: {e}")

    return issues

# --- STEP 3: MYTHRIL (SYMBOLIC EXECUTION) ---


def step_mythril(exclude_paths):
    print("🪄 Running Mythril (Deep Scan)...")
    issues = []

    # 1. FIND FILES: Mythril is slow, so we only run it on valid source files
    # We walk the directory and manually filter files
    targets = []
    for root, dirs, files in os.walk("."):
        # Remove excluded dirs from traversal
        dirs[:] = [d for d in dirs if not any(
            x in os.path.join(root, d) for x in exclude_paths)]

        for file in files:
            if file.endswith(".sol"):
                full_path = os.path.join(root, file)
                # Extra check: ensure path string doesn't contain excluded keywords
                if not any(ignored in full_path for ignored in exclude_paths):
                    targets.append(full_path)

    if not targets:
        print("ℹ️ No target files found for Mythril.")
        return []

    print(f"ℹ️ Mythril targeting {len(targets)} files: {targets}")

    # 2. RUN SCAN PER FILE
    for target in targets:
        print(f"   - Scanning {target}...")
        cmd = ["myth", "analyze", target,
               "--execution-timeout", "120", "-o", "json"]
        stdout = run_command(cmd, TIMEOUT_MYTHRIL)

        if stdout:
            try:
                # Mythril output can be messy (logs + JSON). Find the JSON object.
                start = stdout.find('{')
                end = stdout.rfind('}') + 1
                if start != -1:
                    data = json.loads(stdout[start:end])
                    for bug in data.get("issues", []):
                        issues.append({
                            "tool": "Mythril",
                            "severity": bug.get("severity", "Medium"),
                            "file": target,
                            "description": bug.get("description", ""),
                            "check": bug.get("swc-id", "Unknown")
                        })
            except Exception:
                pass  # Fail silently on parse error

    return issues

# --- GENERATE REPORT ---


def generate_report(all_issues):
    if not all_issues:
        return "✅ No critical security issues found in source files."

    md = ["# 🛡️ ThirdGen Security Report\n"]

    # Sort by severity
    critical = [i for i in all_issues if i['severity'] in ["Critical", "High"]]
    medium = [i for i in all_issues if i['severity'] == "Medium"]

    md.append(
        f"**Scan Summary:** Found {len(critical)} Critical/High and {len(medium)} Medium issues.\n")

    # Helper to render list
    def render_list(issue_list):
        for i in issue_list:
            icon = "🔴" if i['severity'] in ["High", "Critical"] else "⚠️"
            md.append(
                f"### {icon} [{i['tool']}] {i['severity']}: {i['check']}")
            md.append(f"**File:** `{i['file']}`")
            md.append(f"**Description:** {i['description']}\n")

            if i.get('analysis'):
                md.append(f"{i['analysis']}\n")

            md.append("---\n")

    if critical:
        md.append("## 🚨 Critical & High Findings")
        render_list(critical)

    if medium:
        md.append("## ⚠️ Medium Findings")
        render_list(medium)

    return "\n".join(md)

# --- MAIN ---


def main():
    print("🚀 STARTING THIRDGEN SCAN...")

    # 1. Load Config (excludes)
    config = load_config()
    exclude_paths = config["exclude_paths"]
    print(f"🚫 Ignoring paths: {exclude_paths}")

    all_issues = []

    # 2. Run Tools
    all_issues.extend(step_slither(exclude_paths))
    all_issues.extend(step_aderyn(exclude_paths))

    # Only run Mythril if we have time/resources (optional toggle could go here)
    all_issues.extend(step_mythril(exclude_paths))

    # 3. Generate & Save
    report = generate_report(all_issues)
    with open("report.md", "w") as f:
        f.write(report)
    print("✅ Report Generated!")

    # 4. Post to GitHub (if PR)
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    if token and repo and "pull" in os.getenv("GITHUB_REF", ""):
        pr_num = os.getenv("GITHUB_REF").split("/")[-2]
        url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
        # Check for existing comment to update
        try:
            old_comments = requests.get(
                url, headers={"Authorization": f"token {token}"}).json()
            for c in old_comments:
                if "ThirdGen Security Report" in c.get("body", ""):
                    patch_url = f"[https://api.github.com/repos/](https://api.github.com/repos/){repo}/issues/comments/{c['id']}"
                    requests.patch(patch_url, json={"body": report}, headers={
                                   "Authorization": f"token {token}"})
                    print("✅ Comment Updated.")
                    return
        except:
            pass

        # Post new
        requests.post(url, json={"body": report}, headers={
                      "Authorization": f"token {token}"})
        print("✅ Comment Posted.")


if __name__ == "__main__":
    main()
