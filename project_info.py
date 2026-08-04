"""
Project Info data.

Exposes the project's metadata (company, description, and the full team of
interns) so the GUI can render it inside the application window - no
browser, no HTML file.

>>> EDIT THE CONSTANTS BELOW with your own details before submitting <<<
"""

PROJECT_NAME = "Webcam Spyware Security"
PROJECT_DESCRIPTION = ("Implementing physical security policy on webcams in Windows devices to "
                       "prevent spyware activity, with face-recognition-gated access control, "
                       "activity logging, and scheduled camera restrictions.")

COMPANY_NAME = "Supraja Technologies"

# (name, employee/intern ID, email) for every team member.
DEVELOPERS = [
    ("K. Dhamini", "ST#IS#9540", "dhamini467@gmail.com"),
    ("Ande Manjunath", "ST#IS#9533", "manjunath13556d@gmail.com"),
    ("Shaik Mohammad Sadiq", "ST#IS#9565", "Sadiqshaik0402@gmail.com"),
    ("Kadire Harsha Vardhan", "ST#IS#9566", "harshayadavkadire@gmail.com"),
]


def get_project_info() -> dict:
    """Returns the project metadata as a dict for the GUI to display."""
    return {
        'project_name': PROJECT_NAME,
        'project_description': PROJECT_DESCRIPTION,
        'company_name': COMPANY_NAME,
        'developers': list(DEVELOPERS),
    }
