import subprocess
import json
import os
import urllib.request
import urllib.error

# --- CONFIGURATION ---
TIMEOUT_SLITHER = 300
TIMEOUT_ADERYN = 300
CONFIG_FILE = "thirdgen.config.json"
HIDDEN_SIGNATURE = ""  # Helps us find our own comment

# --- HELPER: RUN COMMAND ---


def run_command(command, timeout=300, env=None):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, env=env)
        return result.stdout
    except:
        return None

# --- HELPER: MINIFY ---


def minify_issue(tool, raw_issue):
    try:
        if tool == "slither":
            loc = raw_issue.get("elements", [{}])[0].get("source_mapping", {})
            return {
                "tool": "slither",
                "severity": raw_issue.get("impact", "Unknown"),
                "file": loc.get("filename_relative", "Unknown"),
                "description": raw_issue.get("description", "").strip()
            }
        elif tool == "mythril":
            return {
                "tool": "mythril",
                "severity": raw_issue.get("severity", "High"),
                "file": raw_issue.get("filename", "Unknown"),
                "description": raw_issue.get("description", "").strip()
            }
        elif tool == "aderyn":
            instances = raw_issue.get("instances", [])
            file_path = instances[0].get(
                "path", "Unknown") if instances else "Unknown"
            return {
                "tool": "aderyn",
                "severity": raw_issue.get("severity", "Unknown"),
                "file": file_path,
                "description": raw_issue.get("description", "").strip()
            }
    except:
        return None
    return None

# --- HELPER: FILTER ---


def filter_issues(issues, config):
    excludes = {x.lower() for x in config.get("exclude_severities", [])}
    return [i for i in issues if i.get("severity", "Unknown").lower() not in excludes]

# --- GITHUB INTEGRATION (ZERO CONFIG) ---


def post_github_comment(report_body):
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")  # e.g. "owner/repo"
    ref = os.getenv("GITHUB_REF")         # e.g. "refs/pull/42/merge"

    if not token or not repo or not ref:
        print("⚠️ GITHUB_TOKEN not found. Skipping PR comment.")
        return

    # Extract PR Number from ref (refs/pull/123/merge -> 123)
    try:
        if "refs/pull/" in ref:
            pr_number = ref.split("/")[2]
        else:
            print("⚠️ Not a Pull Request. Skipping comment.")
            return
    except:
        return

    print(f"🤖 Posting to PR #{pr_number} on {repo}...")
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }

    # 1. Check for existing comment (Sticky logic)
    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    existing_comment_id = None

    try:
        req = urllib.request.Request(comments_url, headers=headers)
        with urllib.request.urlopen(req) as res:
            comments = json.loads(res.read())
            for c in comments:
                if HIDDEN_SIGNATURE in c.get("body", ""):
                    existing_comment_id = c["id"]
                    break
    except Exception as e:
        print(f"⚠️ Failed to fetch comments: {e}")

    # 2. Post or Update
    data = json.dumps({"body": report_body}).encode("utf-8")

    try:
        if existing_comment_id:
            # UPDATE existing
            url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_comment_id}"
            req = urllib.request.Request(
                url, data=data, headers=headers, method="PATCH")
            print("🔄 Updating existing comment...")
        else:
            # CREATE new
            req = urllib.request.Request(
                comments_url, data=data, headers=headers, method="POST")
            print("nw Creating new comment...")

        with urllib.request.urlopen(req) as res:
            print("✅ Comment posted successfully!")
    except Exception as e:
        print(f"❌ Failed to post comment: {e}")

# --- REPORT GENERATOR ---


def generate_report(issues):
    severity_map = {"High": "🔴", "Critical": "🔥",
                    "Medium": "🟠", "Low": "🟡", "Informational": "🔵"}

    # Add hidden signature so we can find this comment later
    md = [f"{HIDDEN_SIGNATURE}\n"]
    md.append("## 🛡️ Security Scan Report")
    md.append(f"**Found {len(issues)} issues**")
    md.append("")
    md.append("| Tool | Sev | File | Description |")
    md.append("|---|---|---|---|")

    if not issues:
        md.append("| ✅ | Safe | - | No vulnerabilities found! |")
    else:
        for i in issues:
            sev = i.get("severity", "Unknown").capitalize()
            icon = severity_map.get(sev, "⚪")
            # Safe description
            desc = i.get("description", "").replace(
                "\n", "<br>").replace("|", "\|")
            md.append(
                f"| {i['tool'].capitalize()} | {icon} {sev} | `{i['file']}` | {desc} |")

    md.append("\n_Scanned by ThirdGen Orchestrator_")
    return "\n".join(md)

# --- MAIN FLOW ---


def main():
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            config = json.load(f)

    # Setup
    ver = config.get("solc_version", "0.8.25")
    run_command(["solc-select", "install", ver])
    run_command(["solc-select", "use", ver])

    # Scan
    print("🚀 RUNNING SCANS...")
    all_issues = []

    # Slither
    stdout = run_command(["slither", ".", "--json", "-"], TIMEOUT_SLITHER)
    if stdout:
        try:
            data = json.loads(stdout[stdout.find('{'):stdout.rfind('}')+1])
            all_issues.extend([minify_issue("slither", i)
                              for i in data.get("results", {}).get("detectors", [])])
        except:
            pass

    # Aderyn
    run_command(["aderyn", ".", "-o", "aderyn_report.json"], TIMEOUT_ADERYN)
    if os.path.exists("aderyn_report.json"):
        try:
            with open("aderyn_report.json") as f:
                data = json.load(f)
            for sev in ["critical", "high", "medium", "low"]:
                for i in data.get(f"{sev}_issues", {}).get("issues", []):
                    i["severity"] = sev
                    all_issues.extend([minify_issue("aderyn", i)])
        except:
            pass

    # Mythril
    myth_targets = config.get("mythril", {}).get("targets", [])
    for t in myth_targets:
        cmd = ["myth", "analyze", t, "-o", "json", "--solv",
               ver, "--strategy", "bfs", "--max-depth", "20"]
        stdout = run_command(cmd, timeout=None)
        if stdout:
            try:
                data = json.loads(stdout[stdout.find('{'):stdout.rfind('}')+1])
                for i in data.get('issues', []):
                    i['filename'] = t
                    all_issues.extend([minify_issue("mythril", i)])
            except:
                pass

    # Filter & Cleanup
    all_issues = [x for x in all_issues if x is not None]
    final_issues = filter_issues(all_issues, config)

    # Generate & Post
    report_body = generate_report(final_issues)

    # Save local copy just in case
    with open("pr_report.md", "w") as f:
        f.write(report_body)

    # TRIGGER THE BOT
    post_github_comment(report_body)


if __name__ == "__main__":
    main()
