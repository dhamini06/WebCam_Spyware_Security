"""
Main Entry Point for Webcam Spyware Security Application
"""

import sys
import logging
import os
import ctypes
from pathlib import Path


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def request_admin():
    """Relaunch with admin privileges via UAC prompt"""
    script = os.path.abspath(__file__)
    python_exe = sys.executable
    params = f'"{script}"'
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, params, None, 1
        )
    except Exception:
        pass
    sys.exit(0)


# Auto-elevate to admin if not already running as admin
if not is_admin():
    request_admin()


# Setup logging
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Import GUI
try:
    from gui import main
    logger.info("Application starting...")
    
    if __name__ == "__main__":
        main()
except ImportError as e:
    logger.error(f"Failed to import GUI module: {e}")
    logger.error("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    logger.error(f"Application error: {e}", exc_info=True)
    sys.exit(1)
