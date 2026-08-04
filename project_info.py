"""
Project Info page.

Generates a simple HTML page describing this project (matching the format
from the internship's project brief) and opens it in the default browser -
same pattern as the reference walkthrough (a temp .html file + webbrowser).

>>> EDIT THE CONSTANTS BELOW with your own details before submitting <<<
"""

import os
import tempfile
import webbrowser

PROJECT_START_DATE = "01-DEC-2025"
PROJECT_END_DATE = "31-DEC-2025"
PROJECT_STATUS = "Completed"

COMPANY_NAME = "Supraja Technologies"
COMPANY_EMAIL = "contact@suprajatechnologies.com"

# (name, employee/intern ID, email) for every team member.
DEVELOPERS = [
    ("K. Dhamini", "ST#IS#9540", "dhamini467@gmail.com"),
    ("Ande Manjunath", "9533", "manjunath13556d@gmail.com"),
    ("Shaik Mohammad Sadiq", "9565", "Sadiqshaik0402@gmail.com"),
    ("Kadire Harsha Vardhan", "9566", "harshayadavkadire@gmail.com"),
]

_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Project Information</title>
<style>
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #ffffff;
    color: #111111;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 24px 60px;
  }}
  h1 {{ font-size: 32px; margin-bottom: 20px; }}
  h2 {{ font-size: 22px; margin-top: 40px; margin-bottom: 4px; }}
  p.intro {{ font-size: 16px; line-height: 1.6; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th, td {{ border: 1px solid #dddddd; padding: 10px 14px; text-align: left; font-size: 15px; vertical-align: top; }}
  th {{ background: #f5f5f5; width: 220px; }}
  .placeholder {{ color: #b45309; }}
</style>
</head>
<body>
  <h1>Project Information</h1>
  <p class="intro">
    This project was developed by the team of <strong>{dev_count}</strong> interns listed below
    as part of a <strong>Cyber Security Internship</strong> with <strong>{company_name}</strong>.
    This project is designed to <strong>secure webcam access on Windows devices and
    protect against unauthorized (spyware-style) camera activity</strong>.
  </p>

  <h2>Project Details</h2>
  <table>
    <tr><th>Project Name</th><td>Webcam Spyware Security</td></tr>
    <tr><th>Project Description</th><td>Implementing physical security policy on webcams
        in Windows devices to prevent spyware activity, with face-recognition-gated access
        control, activity logging, and scheduled camera restrictions.</td></tr>
    <tr><th>Project Start Date</th><td>{start_date}</td></tr>
    <tr><th>Project End Date</th><td>{end_date}</td></tr>
    <tr><th>Project Status</th><td><strong>{status}</strong></td></tr>
  </table>

  <h2>Developer Details</h2>
  <table>
    <tr><th>Name</th><th>Employee / Intern ID</th><th>Email</th></tr>
    {dev_rows}
  </table>

  <h2>Company Details</h2>
  <table>
    <tr><th>Company</th><td>{company_name}</td></tr>
    <tr><th>Email</th><td>{company_email}</td></tr>
  </table>
</body>
</html>
"""


def generate_project_info_html() -> str:
    """Builds the project info HTML and writes it to a temp file. Returns the file path."""
    dev_rows = "".join(
        f"<tr><td>{name}</td><td>{dev_id}</td><td>{email}</td></tr>"
        for name, dev_id, email in DEVELOPERS
    )
    html = _HTML_TEMPLATE.format(
        dev_count=len(DEVELOPERS),
        dev_rows=dev_rows,
        start_date=PROJECT_START_DATE,
        end_date=PROJECT_END_DATE,
        status=PROJECT_STATUS,
        company_name=COMPANY_NAME,
        company_email=COMPANY_EMAIL,
    )
    fd, path = tempfile.mkstemp(suffix=".html", prefix="project_info_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def open_project_info():
    """Generates the project info page and opens it in the system's default browser."""
    path = generate_project_info_html()
    webbrowser.open(f"file://{os.path.abspath(path)}")
    return path


if __name__ == "__main__":
    p = generate_project_info_html()
    print(f"Generated: {p}")
