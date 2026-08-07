"""
Project Info page.

Generates a simple HTML page describing this project (matching the format
from the internship's project brief) and opens it in the system's default
browser - same pattern as the original walkthrough (a temp .html file +
webbrowser).

>>> EDIT THE CONSTANTS BELOW with your own details before submitting <<<
"""

import os
import tempfile
import webbrowser

PROJECT_NAME = "Webcam Spyware Security"
PROJECT_DESCRIPTION = ("Implementing physical security policy on webcams in Windows devices to "
                       "prevent spyware activity, with face-recognition-gated access control, "
                       "activity logging, and scheduled camera restrictions.")
COMPANY_NAME = "Supraja Technologies"
COMPANY_EMAIL = "contact@suprajatechnologies.com"

# (name, employee/intern ID, email) for every team member.
DEVELOPERS = [
    ("K. Dhamini", "ST#IS#9540", "dhamini467@gmail.com"),
    ("Ande Manjunath", "ST#IS#9533", "manjunath13556d@gmail.com"),
    ("Shaik Mohammad Sadiq", "ST#IS#9565", "Sadiqshaik0402@gmail.com"),
    ("Kadire Harsha Vardhan", "ST#IS#9566", "harshayadavkadire@gmail.com"),
]


def get_project_info() -> dict:
    """Returns the project metadata as a dict (used for the browser HTML page)."""
    return {
        'project_name': PROJECT_NAME,
        'project_description': PROJECT_DESCRIPTION,
        'company_name': COMPANY_NAME,
        'developers': list(DEVELOPERS),
    }


def _escape_html(text: str) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{project_name} - Project Information</title>
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
</style>
</head>
<body>
  <h1>Project Information</h1>
  <p class="intro">
    This project was developed by <strong>{developers}</strong> as part of a
    <strong>Cyber Security Internship</strong> with <strong>{company_name}</strong>.
    This project is designed to <strong>secure webcam access on Windows devices and
    protect against unauthorized (spyware-style) camera activity</strong>.
  </p>

  <h2>Project Details</h2>
  <table>
    <tr><th>Project Name</th><td>{project_name}</td></tr>
    <tr><th>Project Description</th><td>{project_description}</td></tr>
  </table>

  <h2>Development Team</h2>
  <table>
    <tr><th>#</th><th>Name</th><th>Employee / Intern ID</th><th>Email</th></tr>
    {developer_rows}
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
    info = get_project_info()
    names = ", ".join(name for name, _, _ in info['developers'])
    rows = "\n".join(
        f"    <tr><td>{i}</td><td>{_escape_html(name)}</td>"
        f"<td>{_escape_html(dev_id)}</td><td>{_escape_html(email)}</td></tr>"
        for i, (name, dev_id, email) in enumerate(info['developers'], start=1)
    )
    html = _HTML_TEMPLATE.format(
        project_name=_escape_html(info['project_name']),
        project_description=_escape_html(info['project_description']),
        developers=_escape_html(names),
        developer_rows=rows,
        company_name=_escape_html(info['company_name']),
        company_email=_escape_html(COMPANY_EMAIL),
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
