"""
Checkmarx Security Report — Email Draft Generator
===================================================
Drop this script + your Checkmarx XML + (optional) a .png image into one folder.
Run:  python generate_email_draft.py
Open the generated HTML in your browser, click Copy Email Body, paste into Outlook.
"""

import xml.etree.ElementTree as ET
import os, glob, sys, base64
from datetime import date, datetime, timedelta
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
BASE_URL     = "https://blackduck.phibred.com:444/srm/projects"
SEV_ORDER    = ["critical", "high", "medium", "low", "info"]
SECTION_MAP  = {
    "component analysis": "SCA",
    "static analysis":    "SAST",
    "iac analysis":       "IaC",
}
# Status: if gap between creation-time and first-seen > 15 days → Active, else New
STATUS_THRESHOLD_DAYS = 15
# Remediation SLA from first-seen
REM_SLA = {"critical": None, "high": 45, "medium": 90, "low": 180, "info": None}
TBL_HEADER = "#BDD7EE"
# ─────────────────────────────────────────────────────────────────────────────


def find_xml():
    d = os.path.dirname(os.path.abspath(__file__))
    files = glob.glob(os.path.join(d, "*.xml"))
    if not files:
        print("ERROR: No .xml file in script folder."); sys.exit(1)
    files.sort(key=os.path.getmtime, reverse=True)
    print(f"Found XML : {os.path.basename(files[0])}")
    return files[0]


def find_png():
    """Return base64 data-URI if a .png exists in same folder, else None."""
    d = os.path.dirname(os.path.abspath(__file__))
    files = glob.glob(os.path.join(d, "*.png"))
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    print(f"Found image: {os.path.basename(files[0])}")
    with open(files[0], "rb") as f:
        data = base64.b64encode(f.read()).decode()
    return f"data:image/png;base64,{data}"


def parse_date(s):
    if not s:
        return None
    s = s.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        return datetime.fromisoformat(s).date()
    except Exception:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def compute_status(creation_time_str, first_seen_str):
    ct = parse_date(creation_time_str)
    fs = parse_date(first_seen_str)
    if ct is None or fs is None:
        return "New"
    diff = abs((ct - fs).days)
    return "Active" if diff > STATUS_THRESHOLD_DAYS else "New"


def compute_rem_date(first_seen_str, severity):
    fs = parse_date(first_seen_str)
    sev = severity.lower()
    if sev == "critical":
        return "N/A"
    if sev == "info":
        return "When possible"
    days = REM_SLA.get(sev)
    if days is None or fs is None:
        return "N/A"
    return (fs + timedelta(days=days)).strftime("%d-%b-%Y")


def is_overdue(first_seen_str, severity):
    """True if remediation date is in the past (Active overdue finding)."""
    fs = parse_date(first_seen_str)
    sev = severity.lower()
    days = REM_SLA.get(sev)
    if fs is None or days is None:
        return False
    rem = fs + timedelta(days=days)
    return rem < date.today()


def clean_code(code):
    """Replace underscores with spaces in vulnerability name code."""
    return code.replace("_", " ") if code else ""


def parse_report(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    raw_date = root.attrib.get("date", "")
    try:
        scan_dt   = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        scan_date = scan_dt.strftime("%d-%b-%Y")
    except Exception:
        scan_date = raw_date[:10] if raw_date else "N/A"

    proj      = root.find("project")
    app_name  = proj.attrib.get("name", "N/A") if proj is not None else "N/A"
    proj_id   = proj.attrib.get("id", "") if proj is not None else ""
    portal    = f"{BASE_URL}/{proj_id}" if proj_id else BASE_URL

    author_raw = root.attrib.get("author", "")
    if author_raw:
        local = author_raw.split("@")[0]
        author_name = local.replace(".", " ").replace("_", " ").title()
    else:
        author_name = ""

    # Groups: key=(section, vuln_name_code, vuln_category, severity)
    # We group SAST/IaC by tool code; SCA by ComponentIdentifier
    groups = defaultdict(lambda: {
        "instances": 0, "status": "New",
        "rem_date": "", "overdue": False,
        "component": "", "first_seen": ""
    })

    for finding in root.iter("finding"):
        det = finding.attrib.get("detection-method", "").lower()
        sec = SECTION_MAP.get(det)
        if sec is None:
            continue

        severity     = finding.attrib.get("severity", "low").lower()
        creation_t   = finding.attrib.get("creation-time", "")
        first_seen   = finding.attrib.get("first-seen", "")
        status       = compute_status(creation_t, first_seen)
        rem_date     = compute_rem_date(first_seen, severity)
        overdue_flag = is_overdue(first_seen, severity) and status == "Active"

        rule_el  = finding.find("rule")
        vuln_cat = rule_el.attrib.get("name", "Unknown") if rule_el is not None else "Unknown"
        vuln_cat = clean_code(vuln_cat)   # remove underscores in category too

        results = finding.findall(".//result")
        inst_count = len(results)

        if sec == "SCA":
            # SCA: Vulnerability Name = ComponentIdentifier from first result
            first_result = results[0] if results else None
            av = first_result.find(".//Additional-value[@key='ComponentIdentifier']") if first_result is not None else None
            vuln_name = av.text.strip() if av is not None and av.text else vuln_cat

            gkey = (sec, vuln_name, vuln_cat, severity)
            groups[gkey]["instances"] += inst_count
            groups[gkey]["status"]     = status
            groups[gkey]["rem_date"]   = rem_date
            groups[gkey]["overdue"]    = overdue_flag
            groups[gkey]["first_seen"] = first_seen
        else:
            # SAST / IaC: Vulnerability Name = tool code, group per result
            for result in results:
                tool_el  = result.find("tool")
                code_raw = tool_el.attrib.get("code", "") if tool_el is not None else ""
                vuln_name = clean_code(code_raw) if code_raw else vuln_cat

                gkey = (sec, vuln_name, vuln_cat, severity)
                groups[gkey]["instances"] += 1
                groups[gkey]["status"]     = status
                groups[gkey]["rem_date"]   = rem_date
                groups[gkey]["overdue"]    = overdue_flag
                groups[gkey]["first_seen"] = first_seen

    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    sections = {"SAST": [], "SCA": [], "IaC": []}

    for (sec, vuln_name, vuln_cat, severity), data in groups.items():
        sections[sec].append({
            "vuln_cat":  vuln_cat,
            "vuln_name": vuln_name,
            "severity":  severity,
            "status":    data["status"],
            "instances": data["instances"],
            "rem_date":  data["rem_date"],
            "overdue":   data["overdue"],
        })

    for sec in sections:
        sections[sec].sort(key=lambda x: sev_rank.get(x["severity"].lower(), 99))

    return app_name, scan_date, proj_id, portal, author_name, sections


# ── Summary counts ────────────────────────────────────────────────────────────
def summary_counts(findings):
    c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f["severity"].lower()
        if sev in c:
            c[sev] += 1
    return c


# ── HTML: summary count table ─────────────────────────────────────────────────
def build_summary_table(counts):
    def cell(sev):
        v = counts[sev]
        return (f'<td style="padding:5px 18px;border:1px solid #bbb;'
                f'text-align:center;font-weight:bold;">{v}</td>')
    return (
        '<table style="border-collapse:collapse;font-size:11px;margin:4px 0 8px;">'
        f'<thead><tr style="background:{TBL_HEADER};">'
        '<th style="padding:5px 18px;border:1px solid #bbb;">Critical</th>'
        '<th style="padding:5px 18px;border:1px solid #bbb;">High</th>'
        '<th style="padding:5px 18px;border:1px solid #bbb;">Medium</th>'
        '<th style="padding:5px 18px;border:1px solid #bbb;">Low</th>'
        '</tr></thead><tbody><tr>'
        + cell("critical") + cell("high") + cell("medium") + cell("low")
        + '</tr></tbody></table><br>'
    )


# ── HTML: detail findings table ───────────────────────────────────────────────
def build_detail_table(findings):
    if not findings:
        return ""
    rows = ""
    for i, f in enumerate(findings, 1):
        rem_style = 'color:#CC0000;font-weight:bold;' if f["overdue"] else ''
        rows += (
            f'<tr>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{i}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;">{f["vuln_cat"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;">{f["vuln_name"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{f["severity"].title()}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{f["status"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;{rem_style}">{f["rem_date"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;font-weight:bold;">{f["instances"]}</td>'
            f'</tr>'
        )
    return (
        '<p style="margin:10px 0 4px;font-size:11px;text-decoration:underline;">Vulnerabilities Requiring Attention:</p>'
        '<table style="border-collapse:collapse;width:100%;font-size:11px;">'
        f'<thead><tr style="background:{TBL_HEADER};">'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">S.No.</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;">Vulnerability Category</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;">Vulnerability Name</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Severity</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Status</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Remediation Due Date</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Instance Count</th>'
        '</tr></thead>'
        f'<tbody>{rows}</tbody></table><br>'
    )


def build_section(label, findings):
    counts  = summary_counts(findings)
    s_tbl   = build_summary_table(counts)
    d_tbl   = build_detail_table(findings)
    return (
        f'<p style="margin:16px 0 4px;font-size:11px;font-weight:bold;">{label} Summary:</p>'
        f'<p style="margin:2px 0 4px;font-size:11px;text-decoration:underline;">Active Vulnerabilities Count:</p>'
        f'{s_tbl}{d_tbl}'
    )


# ── Full HTML ─────────────────────────────────────────────────────────────────
def generate_html(app_name, scan_date, portal, author_name, sections, img_src):
    today      = date.today().strftime("%d-%b-%Y")
    sast_block = build_section("SAST", sections["SAST"])
    sca_block  = build_section("SCA",  sections["SCA"])
    iac_block  = build_section("IaC",  sections["IaC"])

    # Image block
    if img_src:
        img_block = f'<img src="{img_src}" style="max-width:480px;width:100%;height:auto;display:block;margin:8px 0;">'
    else:
        img_block = '<p style="color:#CC0000;font-size:11px;">&lt;insert-photo-here-small-size-as-per-ratio&gt;</p>'

    author_line = author_name if author_name else "&lt;insert name here&gt;"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Email Draft – {app_name}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:Calibri,'Segoe UI',sans-serif;font-size:11px;color:#222;
        background:#eef2f7;padding:20px;}}
  .page{{max-width:920px;margin:0 auto;}}
  .toolbar{{background:#1a3a5c;color:#fff;padding:12px 18px;border-radius:8px 8px 0 0;
            display:flex;align-items:center;justify-content:space-between;}}
  .t-title{{font-size:13px;font-weight:bold;}}
  .t-meta{{font-size:10px;color:#a8c4e0;margin-top:3px;}}
  .copy-btn{{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4);
             color:#fff;padding:6px 14px;border-radius:4px;cursor:pointer;
             font-size:11px;font-family:inherit;transition:background .2s;}}
  .copy-btn:hover{{background:rgba(255,255,255,.28);}}
  .copy-btn.ok{{background:#2e7d32;border-color:#2e7d32;}}
  .card{{background:#fff;border:1px solid #d0d7de;border-top:none;
         border-radius:0 0 8px 8px;padding:28px 32px 32px;line-height:1.8;}}
  .foot{{margin-top:14px;font-size:10px;color:#999;border-top:1px solid #eee;padding-top:8px;}}
  mark{{background:#FFFF00;}}
</style>
</head>
<body>
<div class="page">
  <div class="toolbar">
    <div>
      <div class="t-title">📧 Email Draft — Security Report: {app_name}</div>
      <div class="t-meta">Generated: {today}</div>
    </div>
    <button class="copy-btn" id="cb" onclick="copyEmail()">📋 Copy Email Body</button>
  </div>

  <div class="card">
    <div id="emailBody">

      <p>Hello Team,</p><br>

      <p>The security assessment of the application <strong>{app_name}</strong> has been completed.
      You can view the detailed vulnerabilities here:&nbsp;
      <a href="{portal}" style="color:#CC0000;font-weight:bold;">{portal}</a></p><br>

      <p><strong>Assessment Summary</strong></p>
      <p>Note, this is a list of all vulnerabilities and findings noted as part of the SAST, SCA, IaC and Container security assessment.</p><br>

      <p><strong>Scan Date:</strong> {scan_date}</p>
      <p><strong>Report Shared Date:</strong> {today}</p><br>

      {sast_block}

      {sca_block}

      <p style="font-size:11px;">In addition, please note:</p>
      <ul style="font-size:11px;margin:4px 0 4px 20px;line-height:1.8;">
        <li>16 vulnerability have been analysed and reported as Informational findings.</li>
        <li>163 packages have been identified with legal risks.</li>
        <li>249 packages are identified as outdated.</li>
      </ul>
      <p style="font-size:11px;">More details are available in the Checkmarx dashboards.</p><br>

      {iac_block}

      <p><strong>Action Required</strong></p>
      <p><strong>Kindly share your remediation plan for the reported vulnerabilities. Please refer to the Corteva remediation policy timelines as mentioned below:</strong></p><br>

      {img_block}
      <br>

      <p><strong>Please let us know if you have any queries or need assistance from our side regarding the remediation or reported vulnerabilities.</strong></p><br>

      <p><strong>Additional Note:</strong></p>
      <ul style="font-size:11px;margin:4px 0 4px 20px;line-height:1.8;">
        <li>Kindly refer Appsec-Wiki for our processes and guideline documents on how to get access to the tools and navigate through them (e.g. for blackduck access you can refer MyAccessRequest_Blackduck.pdf document)</li>
        <li>It is recommended to take the action as stated in Blackduck_UserGuide.pdf available in the wiki link once you receive this report. In case of any query or requirement or update, you may reach out at dl-appSec.</li>
        <li><mark>Changes to production environment should only be made after proper testing is completed in non-prod ensuring compatibility within our environment.</mark></li>
      </ul><br>

      <p>Regards,<br>{author_line}</p>

    </div>
    <div class="foot">
      Auto-generated by generate_email_draft.py on {today}.
      Open in browser → Copy Email Body → Paste into Outlook.
    </div>
  </div>
</div>
<script>
function copyEmail(){{
  var el=document.getElementById('emailBody'),s=window.getSelection(),r=document.createRange();
  r.selectNodeContents(el);s.removeAllRanges();s.addRange(r);
  document.execCommand('copy');s.removeAllRanges();
  var b=document.getElementById('cb');
  b.textContent='✅ Copied!';b.classList.add('ok');
  setTimeout(function(){{b.textContent='📋 Copy Email Body';b.classList.remove('ok');}},2500);
}}
</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    xml_path     = find_xml()
    img_src      = find_png()
    app_name, scan_date, proj_id, portal, author_name, sections = parse_report(xml_path)

    print(f"\n  Application : {app_name}  (Project ID: {proj_id})")
    print(f"  Portal Link : {portal}")
    print(f"  Scan Date   : {scan_date}")
    print(f"  Author      : {author_name}")
    for sec in ["SAST", "SCA", "IaC"]:
        c = summary_counts(sections[sec])
        print(f"\n  {sec}  Critical:{c['critical']}  High:{c['high']}  Medium:{c['medium']}  Low:{c['low']}")
        for r in sections[sec]:
            flag = " ⚠️ OVERDUE" if r["overdue"] else ""
            print(f"      [{r['severity'].upper():8s}] {r['vuln_name']}  — {r['instances']} instance(s)  [{r['status']}]{flag}")

    html      = generate_html(app_name, scan_date, portal, author_name, sections, img_src)
    d         = os.path.dirname(os.path.abspath(__file__))
    safe      = app_name.replace(" ", "_").replace("/", "-")
    out_path  = os.path.join(d, f"email_draft_{safe}.html")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  ✅ Email draft : email_draft_{safe}.html")
    print(f"  📂 Saved at    : {out_path}\n")


if __name__ == "__main__":
    main()
        
