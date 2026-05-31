"""
Checkmarx Security Report — Email Draft Generator
===================================================
Parses real Checkmarx XML export.
Groups findings by (vulnerability name + severity) and sums instances.

Usage:
  python generate_email_draft.py
  python generate_email_draft.py "https://your-portal-link"
"""

import xml.etree.ElementTree as ET
import os, glob, sys
from datetime import date, datetime, timedelta
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────
PORTAL_LINK = "https://checkmarx.company.com/results"   # <-- change me

REMEDIATION_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 120}

SECTION_MAP = {
    "component analysis": "SCA",
    "static analysis":    "SAST",
    "iac analysis":       "IaC",
}

SEV_ORDER  = ["critical", "high", "medium", "low"]
SEV_COLORS = {
    "critical": "#CC0000",
    "high":     "#E65C00",
    "medium":   "#D4820A",
    "low":      "#8B7500",
}


# ── 1. Find XML ───────────────────────────────────────────────────────────────
def find_xml_report():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    files = glob.glob(os.path.join(script_dir, "*.xml"))
    if not files:
        print("ERROR: No .xml file found in the script folder.")
        sys.exit(1)
    files.sort(key=os.path.getmtime, reverse=True)
    print(f"Found report: {os.path.basename(files[0])}")
    return files[0]


# ── 2. Parse + GROUP by (vuln_name, component, severity) ─────────────────────
def parse_report(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    raw_date = root.attrib.get("date", "")
    try:
        scan_dt   = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        scan_date = scan_dt.strftime("%d-%b-%Y")
    except Exception:
        scan_dt   = datetime.now()
        scan_date = raw_date[:10] if raw_date else "N/A"

    project  = root.find("project")
    app_name = project.attrib.get("name", "N/A") if project is not None else "N/A"

    # key → (section, vuln_name, component, severity, status)
    # value → {"instances": int, "rem_date": str}
    # Group key: (section, vuln_name, component, severity)
    groups = defaultdict(lambda: {"instances": 0, "status": "New", "rem_date": ""})

    for finding in root.iter("finding"):
        det = finding.attrib.get("detection-method", "").lower()
        sec = SECTION_MAP.get(det)
        if sec is None:
            continue

        severity     = finding.attrib.get("severity", "low").lower()
        triage       = finding.attrib.get("triage-status", "to-be-fixed")
        status_label = "New" if triage == "to-be-fixed" else triage.replace("-", " ").title()

        rule_el   = finding.find("rule")
        vuln_name = rule_el.attrib.get("name", "Unknown") if rule_el is not None else "Unknown"

        results    = finding.findall(".//result")
        inst_count = len(results)

        # Component: from first result
        comp_id = ""
        if results:
            av = results[0].find(".//Additional-value[@key='ComponentIdentifier']")
            if av is not None and av.text:
                comp_id = av.text

        # Remediation due date
        try:
            rem_str = (scan_dt.date() + timedelta(days=REMEDIATION_DAYS.get(severity, 90))).strftime("%d-%b-%Y")
        except Exception:
            rem_str = "N/A"

        # Group key — same vuln name + severity in same section gets merged
        gkey = (sec, vuln_name, severity)
        groups[gkey]["instances"] += inst_count
        groups[gkey]["status"]     = status_label
        groups[gkey]["rem_date"]   = rem_str
        # For component: keep first seen (or accumulate as comma list if different)
        if "component" not in groups[gkey]:
            groups[gkey]["component"] = comp_id
        elif comp_id and comp_id not in groups[gkey]["component"]:
            # Append different components (e.g. SAST file paths differ — just keep first)
            pass  # keep first component identifier

    # Build section lists sorted by severity order
    sections = {"SAST": [], "SCA": [], "IaC": []}
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}

    for (sec, vuln_name, severity), data in groups.items():
        sections[sec].append({
            "vuln_name": vuln_name,
            "component": data.get("component", ""),
            "severity":  severity,
            "status":    data["status"],
            "instances": data["instances"],
            "rem_date":  data["rem_date"],
        })

    for sec in sections:
        sections[sec].sort(key=lambda x: sev_rank.get(x["severity"].lower(), 99))

    return app_name, scan_date, sections


# ── 3. Summary counts (unique grouped rows per severity) ──────────────────────
def summary_counts(findings):
    c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f["severity"].lower()
        if sev in c:
            c[sev] += 1
    return c


# ── 4. HTML helpers ───────────────────────────────────────────────────────────
def build_summary_table(counts):
    def cell(sev):
        v     = counts[sev]
        color = SEV_COLORS[sev] if v > 0 else "#999"
        return (f'<td style="padding:6px 22px;border:1px solid #ccc;'
                f'text-align:center;font-weight:bold;color:{color};">{v}</td>')
    return (
        '<table style="border-collapse:collapse;font-size:13px;margin:6px 0 12px;">'
        '<thead><tr style="background:#dce8f5;">'
        '<th style="padding:6px 22px;border:1px solid #bbb;color:#CC0000;">Critical</th>'
        '<th style="padding:6px 22px;border:1px solid #bbb;color:#E65C00;">High</th>'
        '<th style="padding:6px 22px;border:1px solid #bbb;color:#D4820A;">Medium</th>'
        '<th style="padding:6px 22px;border:1px solid #bbb;color:#8B7500;">Low</th>'
        '</tr></thead><tbody><tr>'
        + cell("critical") + cell("high") + cell("medium") + cell("low")
        + '</tr></tbody></table>'
    )


def build_detail_table(findings):
    if not findings:
        return ""
    rows = ""
    for i, f in enumerate(findings, 1):
        bg    = "#f9f9f9" if i % 2 == 0 else "#ffffff"
        color = SEV_COLORS.get(f["severity"].lower(), "#444")
        rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{i}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;">{f["vuln_name"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;">{f["component"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;'
            f'color:{color};font-weight:bold;">{f["severity"].title()}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{f["status"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;">{f["rem_date"]}</td>'
            f'<td style="padding:5px 8px;border:1px solid #ddd;text-align:center;font-weight:bold;">{f["instances"]}</td>'
            f'</tr>'
        )
    return (
        '<p style="margin:10px 0 4px;font-weight:bold;font-size:13px;">Vulnerabilities Requiring Attention:</p>'
        '<table style="border-collapse:collapse;width:100%;font-size:12px;">'
        '<thead><tr style="background:#dce8f5;">'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">S.No.</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;">Vulnerability Name</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;">Component / Identifier</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Severity</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Status</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Remediation Due Date</th>'
        '<th style="padding:5px 8px;border:1px solid #bbb;text-align:center;">Instance Count</th>'
        '</tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )


def build_section(label, findings):
    counts    = summary_counts(findings)
    sum_tbl   = build_summary_table(counts)
    detail    = build_detail_table(findings)
    return (
        f'<p style="margin:20px 0 4px;font-size:15px;font-weight:bold;'
        f'text-decoration:underline;color:#1a3a5c;">{label} Summary:</p>'
        f'<p style="margin:2px 0 4px;font-weight:bold;font-size:13px;">Active Vulnerabilities Count:</p>'
        f'{sum_tbl}{detail}'
        f'<hr style="border:none;border-top:1px solid #e0e0e0;margin:18px 0;">'
    )


# ── 5. Full HTML ──────────────────────────────────────────────────────────────
def generate_html(app_name, scan_date, sections, portal_link, xml_filename):
    today = date.today().strftime("%d-%b-%Y")
    body  = (build_section("SAST", sections["SAST"]) +
             build_section("SCA",  sections["SCA"])  +
             build_section("IaC",  sections["IaC"]))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Email Draft – {app_name}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:Calibri,'Segoe UI',sans-serif;font-size:14px;color:#222;
        background:#eef2f7;min-height:100vh;padding:24px;}}
  .page{{max-width:900px;margin:0 auto;}}
  .toolbar{{background:#1a3a5c;color:#fff;padding:13px 20px;border-radius:8px 8px 0 0;
            display:flex;align-items:center;justify-content:space-between;}}
  .t-title{{font-size:15px;font-weight:bold;}}
  .t-meta{{font-size:11px;color:#a8c4e0;margin-top:3px;}}
  .copy-btn{{background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4);
             color:#fff;padding:7px 16px;border-radius:5px;cursor:pointer;
             font-size:13px;font-family:inherit;transition:background .2s;}}
  .copy-btn:hover{{background:rgba(255,255,255,.25);}}
  .copy-btn.ok{{background:#2e7d32;border-color:#2e7d32;}}
  .card{{background:#fff;border:1px solid #d0d7de;border-top:none;
         border-radius:0 0 8px 8px;padding:32px 36px 36px;line-height:1.7;}}
  .foot{{margin-top:18px;font-size:11px;color:#999;border-top:1px solid #eee;padding-top:10px;}}
</style>
</head>
<body>
<div class="page">
  <div class="toolbar">
    <div>
      <div class="t-title">📧 Email Draft — Security Report: {app_name}</div>
      <div class="t-meta">Source: {xml_filename} &nbsp;|&nbsp; Generated: {today}</div>
    </div>
    <button class="copy-btn" id="cb" onclick="copyEmail()">📋 Copy Email Body</button>
  </div>
  <div class="card">
    <div id="emailBody">
      <p>Hello Team,</p><br>
      <p>The security assessment of application <strong>{app_name}</strong> has been completed.
      You can view the detailed report here:&nbsp;
      <a href="{portal_link}" style="color:#CC0000;font-weight:bold;">{portal_link}</a></p><br>
      <p><strong>Scan Date:</strong> {scan_date}</p>
      <p><strong>Report Shared Date:</strong> {today}</p>
      <hr style="border:none;border-top:1px solid #ddd;margin:18px 0;">
      {body}
      <p>In addition, please note any open items from the previous cycle that remain unresolved.<br>
      Kindly ensure remediation is completed before the due dates mentioned above.</p><br>
      <p>Regards,<br><strong>Security Team</strong></p>
    </div>
    <div class="foot">
      Auto-generated from <code>{xml_filename}</code> on {today}.
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


# ── 6. Main ───────────────────────────────────────────────────────────────────
def main():
    portal_link  = sys.argv[1] if len(sys.argv) > 1 else PORTAL_LINK
    xml_path     = find_xml_report()
    xml_filename = os.path.basename(xml_path)

    app_name, scan_date, sections = parse_report(xml_path)

    print(f"\n  Application : {app_name}")
    print(f"  Scan Date   : {scan_date}")
    for sec in ["SAST", "SCA", "IaC"]:
        c = summary_counts(sections[sec])
        rows = sections[sec]
        print(f"  {sec:4s}  {len(rows)} grouped row(s)  "
              f"Critical:{c['critical']}  High:{c['high']}  Medium:{c['medium']}  Low:{c['low']}")
        for r in rows:
            print(f"         → {r['vuln_name']} [{r['severity']}] — {r['instances']} instance(s)")

    html       = generate_html(app_name, scan_date, sections, portal_link, xml_filename)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    safe_name  = app_name.replace(" ", "_").replace("/", "-")
    out_path   = os.path.join(script_dir, f"email_draft_{safe_name}.html")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  Email draft saved: email_draft_{safe_name}.html")
    print(f"  Open in browser → Copy Email Body → Paste into Outlook.\n")


if __name__ == "__main__":
    main()
