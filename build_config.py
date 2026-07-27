"""
Build Configuration for Webcam Spyware Security
PyInstaller configuration for creating Windows executable (.exe)
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class BuildConfig:
    """Build configuration for PyInstaller"""
    
    # Project paths
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    MAIN_SCRIPT = os.path.join(PROJECT_ROOT, 'main.py')
    BUILD_DIR = os.path.join(PROJECT_ROOT, 'build')
    DIST_DIR = os.path.join(PROJECT_ROOT, 'dist')
    SPEC_FILE = os.path.join(PROJECT_ROOT, 'webcam_security.spec')
    
    # Output configuration
    OUTPUT_NAME = 'WebcamSecurity'
    OUTPUT_FILE = os.path.join(DIST_DIR, f'{OUTPUT_NAME}.exe')
    
    # Hidden imports (modules PyInstaller doesn't detect automatically)
    HIDDEN_IMPORTS = [
        'customtkinter',
        'PIL',
        'cv2',
        'face_recognition',
        'dlib',
        'numpy',
        'cryptography',
        'bcrypt',
    ]
    
    # Binaries (dependencies not in Python packages)
    BINARIES = []
    
    # Data files to include
    DATAS = [
        ('assets', 'assets'),
        ('database', 'database'),
        ('logs', 'logs'),
        ('reports', 'reports'),
        ('temp', 'temp'),
    ]
    
    # Excluded modules (to reduce exe size)
    EXCLUDES = [
        'pytest',
        'unittest',
        'matplotlib',
        'pandas',
        'scipy',
        'sklearn',
    ]
    
    # PyInstaller options
    PYINSTALLER_OPTIONS = {
        '--name': OUTPUT_NAME,
        '--windowed': True,  # No console window
        '--icon': None,  # Optional: add icon file
        '--onefile': False,  # Create folder instead of single exe
        '--add-data': DATAS,
        '--hidden-import': HIDDEN_IMPORTS,
        '--exclude-module': EXCLUDES,
        '--collect-all': ['customtkinter'],
    }


class BuildManager:
    """Manages the build process"""
    
    def __init__(self, config: BuildConfig = None):
        """Initialize build manager"""
        self.config = config or BuildConfig()
        logging.basicConfig(level=logging.INFO)
    
    def validate_environment(self) -> bool:
        """
        Validate build environment
        
        Returns:
            True if environment is valid
        """
        print("[1] Validating build environment...")
        
        # Check main script exists
        if not os.path.exists(self.config.MAIN_SCRIPT):
            logger.error(f"Main script not found: {self.config.MAIN_SCRIPT}")
            return False
        
        # Check PyInstaller is installed
        try:
            subprocess.run(['pyinstaller', '--version'], 
                         capture_output=True, check=True)
            print("  ✅ PyInstaller found")
        except:
            logger.error("PyInstaller not installed. Install with: pip install pyinstaller")
            return False
        
        # Check required modules
        required_modules = ['customtkinter', 'cv2', 'bcrypt', 'cryptography']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
                print(f"  ✅ {module} found")
            except ImportError:
                missing_modules.append(module)
                logger.error(f"Missing module: {module}")
        
        if missing_modules:
            logger.error(f"Missing modules: {', '.join(missing_modules)}")
            return False
        
        print("  ✅ All dependencies found\n")
        return True
    
    def clean_build_artifacts(self) -> bool:
        """
        Clean previous build artifacts
        
        Returns:
            True if successful
        """
        print("[2] Cleaning previous builds...")
        
        try:
            import shutil
            
            # Remove build directory
            if os.path.exists(self.config.BUILD_DIR):
                shutil.rmtree(self.config.BUILD_DIR)
                print(f"  ✅ Removed build directory")
            
            # Remove spec file
            if os.path.exists(self.config.SPEC_FILE):
                os.remove(self.config.SPEC_FILE)
                print(f"  ✅ Removed spec file")
            
            print()
            return True
        
        except Exception as e:
            logger.error(f"Error cleaning build: {e}")
            return False
    
    def build_executable(self) -> bool:
        """
        Build the executable using PyInstaller
        
        Returns:
            True if successful
        """
        print("[3] Building executable...")
        
        try:
            # Build PyInstaller command
            cmd = [
                'pyinstaller',
                '--name', self.config.OUTPUT_NAME,
                '--windowed',
                '--onedir',
                '--noconfirm',
            ]
            
            # Add hidden imports
            for module in self.config.HIDDEN_IMPORTS:
                cmd.extend(['--hidden-import', module])
            
            # Add data files
            for src, dest in self.config.DATAS:
                src_path = os.path.join(self.config.PROJECT_ROOT, src)
                if os.path.exists(src_path):
                    cmd.extend(['--add-data', f'{src_path}{os.pathsep}{dest}'])
            
            # Add excludes
            for module in self.config.EXCLUDES:
                cmd.extend(['--exclude-module', module])
            
            # Add main script
            cmd.append(self.config.MAIN_SCRIPT)
            
            print(f"  Building: {' '.join(cmd[:5])}...\n")
            
            # Run PyInstaller
            result = subprocess.run(cmd, cwd=self.config.PROJECT_ROOT)
            
            if result.returncode == 0:
                print("\n  ✅ Build successful\n")
                return True
            else:
                logger.error(f"Build failed with code {result.returncode}")
                return False
        
        except Exception as e:
            logger.error(f"Error building executable: {e}")
            return False
    
    def verify_build(self) -> bool:
        """
        Verify the build output
        
        Returns:
            True if build verified
        """
        print("[4] Verifying build...")
        
        try:
            # Check dist directory exists
            if not os.path.exists(self.config.DIST_DIR):
                logger.error(f"Dist directory not found: {self.config.DIST_DIR}")
                return False
            
            print(f"  ✅ Dist directory: {self.config.DIST_DIR}")
            
            # List output files
            output_files = os.listdir(self.config.DIST_DIR)
            if output_files:
                print(f"  ✅ Generated {len(output_files)} items:")
                for item in output_files[:5]:
                    print(f"    - {item}")
                if len(output_files) > 5:
                    print(f"    ... and {len(output_files) - 5} more")
            else:
                logger.error("No output files generated")
                return False
            
            # Check for exe
            exe_path = os.path.join(self.config.DIST_DIR, 
                                   self.config.OUTPUT_NAME, 
                                   f'{self.config.OUTPUT_NAME}.exe')
            
            if os.path.exists(exe_path):
                exe_size = os.path.getsize(exe_path) / (1024 * 1024)
                print(f"  ✅ Executable: {exe_path}")
                print(f"  ✅ Size: {exe_size:.1f} MB\n")
                return True
            else:
                logger.error(f"Executable not found: {exe_path}")
                return False
        
        except Exception as e:
            logger.error(f"Error verifying build: {e}")
            return False
    
    def build(self) -> bool:
        """
        Run complete build process
        
        Returns:
            True if build successful
        """
        print("\n" + "=" * 60)
        print("Webcam Spyware Security - Build Process")
        print("=" * 60 + "\n")
        
        # Validate environment
        if not self.validate_environment():
            print("\n❌ Build failed: Environment validation failed\n")
            return False
        
        # Clean previous builds
        if not self.clean_build_artifacts():
            print("\n❌ Build failed: Cleanup failed\n")
            return False
        
        # Build executable
        if not self.build_executable():
            print("\n❌ Build failed: Executable generation failed\n")
            return False
        
        # Verify build
        if not self.verify_build():
            print("\n❌ Build failed: Verification failed\n")
            return False
        
        print("=" * 60)
        print("✅ Build completed successfully!")
        print("=" * 60)
        print(f"\nExecutable location:")
        print(f"  {self.config.DIST_DIR}\\{self.config.OUTPUT_NAME}\\{self.config.OUTPUT_NAME}.exe")
        print(f"\nTo run: Double-click the .exe file or run from command line")
        print(f"  {self.config.OUTPUT_NAME}.exe\n")
        
        return True


class DistributionManager:
    """Manages distribution package creation"""
    
    def __init__(self, build_config: BuildConfig = None):
        """Initialize distribution manager"""
        self.config = build_config or BuildConfig()
    
    def create_installer_batch(self) -> bool:
        """
        Create batch file for easy installation/launch
        
        Returns:
            True if successful
        """
        try:
            batch_content = f"""@echo off
REM Webcam Spyware Security Launcher
REM This batch file launches the application

cd /d "%~dp0"
echo Launching Webcam Spyware Security...
"{self.config.OUTPUT_NAME}\\{self.config.OUTPUT_NAME}.exe"
pause
"""
            
            batch_path = os.path.join(self.config.DIST_DIR, 'Launch.bat')
            
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            
            logger.info(f"Batch launcher created: {batch_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error creating batch launcher: {e}")
            return False
    
    def create_readme(self) -> bool:
        """
        Create README.txt for distribution
        
        Returns:
            True if successful
        """
        try:
            readme_content = """WEBCAM SPYWARE SECURITY
=======================

INSTALLATION:
1. Extract all files to a folder
2. Run Launch.bat or WebcamSecurity.exe

REQUIREMENTS:
- Windows 10 or later
- No additional installations required (all dependencies included)

FEATURES:
- Real-time webcam monitoring
- Face recognition for intruder detection
- Encrypted activity logs
- Role-based access control
- Automatic enable/disable scheduling
- Comprehensive security reports

FIRST RUN:
1. Create admin account
2. Set up webcam monitoring policies
3. Configure automatic schedules
4. Review activity logs

SUPPORT:
For issues or questions, check the logs folder for detailed error information.

SECURITY:
- All logs are encrypted with AES encryption
- Passwords are hashed with bcrypt (12-round)
- Session tokens expire after 24 hours
- Registry changes require admin privilege

VERSION: 1.0
LICENSE: Proprietary
"""
            
            readme_path = os.path.join(self.config.DIST_DIR, 'README.txt')
            
            with open(readme_path, 'w') as f:
                f.write(readme_content)
            
            logger.info(f"README created: {readme_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error creating README: {e}")
            return False


if __name__ == "__main__":
    import sys
    
    print("\n" + "=" * 60)
    print("Webcam Spyware Security - Build System")
    print("=" * 60 + "\n")
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
    else:
        command = "build"
    
    if command == "build":
        # Build executable
        manager = BuildManager()
        success = manager.build()
        
        if success:
            # Create distribution files
            dist_manager = DistributionManager()
            dist_manager.create_installer_batch()
            dist_manager.create_readme()
        
        sys.exit(0 if success else 1)
    
    elif command == "clean":
        # Clean build artifacts
        manager = BuildManager()
        manager.clean_build_artifacts()
        print("✅ Build artifacts cleaned\n")
    
    elif command == "check":
        # Check environment only
        manager = BuildManager()
        manager.validate_environment()
    
    else:
        print(f"Usage: python {os.path.basename(__file__)} [build|clean|check]")
        print("  build - Build executable (default)")
        print("  clean - Clean build artifacts")
        print("  check - Check build environment")
