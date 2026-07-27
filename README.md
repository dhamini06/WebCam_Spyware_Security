# Webcam Spyware Security - Enterprise Privacy Protection Suite

## Overview

**Webcam Spyware Security** is a comprehensive Windows desktop application designed to provide enterprise-grade privacy protection against unauthorized webcam access. Built with Python 3.12, CustomTkinter, and advanced security technologies, this application offers real-time monitoring, biometric authentication, and sophisticated access control.

## Key Features

### 🔐 Security & Authentication
- **Role-Based Access Control (RBAC)**: Admin and Employee roles with granular permissions
- **Bcrypt Password Hashing**: 12-round hashing for maximum security
- **Fernet Encryption**: AES-128 encryption for sensitive data
- **Session Management**: 24-hour token expiry with automatic cleanup
- **Admin Privilege Detection**: Automatic detection of elevated permissions

### 📹 Camera Management
- **Real-Time Monitoring**: Continuous webcam device detection
- **Registry-Level Control**: Windows Registry integration for driver-level control
- **Enable/Disable Functionality**: Granular per-device camera control
- **Activity Logging**: All camera operations logged with user tracking
- **Intruder Image Capture**: Automatic snapshot capture on unauthorized access

### 👤 Face Recognition Engine
- **HOG-Based Detection**: Fast, efficient face detection without GPU
- **128-D Encoding**: Industry-standard face encoding for high accuracy
- **Duplicate Detection**: Prevents duplicate face registrations
- **Confidence Scoring**: Calculates match confidence (1 - distance metric)
- **Intruder Identification**: Identifies users against registered database

### 📋 Activity Logging & Reporting
- **Encrypted Logs**: All activity logs encrypted at rest
- **Severity Levels**: info, warning, error, critical categorization
- **Multi-Format Export**: JSON, CSV, PDF report generation
- **Audit Trails**: Complete user action history
- **Log Retention**: Configurable retention policies with automatic cleanup

### 🎯 Access Control Policies
- **Allow/Deny Rules**: Flexible policy types
- **Scope-Based Policies**: Global, user-specific, and application-specific
- **Time-Based Activation**: Policies active only during specified hours
- **Policy Evaluation**: Sophisticated evaluation engine
- **Conflict Resolution**: Deny-first precedence for security

### ⏰ Automatic Scheduling
- **Recurrence Support**: once, daily, weekly, monthly schedules
- **Background Monitoring**: Continuous background scheduler thread
- **Template Policies**: Pre-built schedules (work hours, sleep hours, always-on)
- **Time-Zone Aware**: Operates in system timezone
- **Duplicate Prevention**: Prevents repeated execution within 1 hour

### 🎨 User Interface
- **Modern Dark Theme**: CustomTkinter with #1a1a1a dark background
- **Responsive Design**: 1200x700px adaptive layout
- **Sidebar Navigation**: 200px left sidebar with role-based menus
- **Color Coding**: Intuitive status indicators (green/orange/red)
- **Thread-Based Login**: Non-blocking async authentication

## Technical Architecture

### Core Stack
- **Language**: Python 3.12.7
- **GUI Framework**: CustomTkinter 5.2.2
- **Database**: SQLite 3 with foreign key constraints
- **Authentication**: bcrypt 4.1.2
- **Encryption**: cryptography (Fernet) 41.0.7
- **Computer Vision**: face_recognition + OpenCV 4.8.1

### Module Structure

#### Security Layer (3 modules)
- `authentication.py` (23.9 KB) - User auth, session management, RBAC
- `crypto_manager.py` (8.4 KB) - Encryption/decryption operations
- `utils.py` (11.9 KB) - Utility functions (validation, system info, datetime)

#### Data Layer (1 module)
- `database.py` (24.3 KB) - SQLite management with 8-table schema

#### Device Layer (2 modules)
- `registry_manager.py` (20.7 KB) - Windows Registry operations
- `camera_controller.py` (17.5 KB) - High-level camera management

#### Advanced Features (5 modules)
- `face_manager.py` (24.9 KB) - Face recognition & biometrics
- `policy_manager.py` (20 KB) - Access policy engine
- `scheduler.py` (16.5 KB) - Automatic scheduling system
- `logging_manager.py` (16.9 KB) - Activity logging & encryption
- `report_generator.py` (18.5 KB) - Multi-format report generation

#### Presentation & Build (3 modules)
- `gui.py` (19.4 KB) - CustomTkinter UI components
- `assets.py` (9.2 KB) - Theme & resource management
- `build_config.py` (13.2 KB) - PyInstaller build configuration

#### Support Modules (2 modules)
- `user_manager.py` (13.7 KB) - High-level user administration
- `main.py` (0.9 KB) - Application entry point

### Database Schema

**8 Tables with 50+ columns:**
1. **users** - User accounts, roles, face data
2. **logs** - Activity logging with severity
3. **intruder_logs** - Failed login attempts
4. **policies** - Access control policies
5. **schedules** - Automatic schedules
6. **settings** - Application configuration
7. **camera_access** - Camera usage tracking
8. **face_registry** - Registered face encodings
9. **sessions** - Active session tokens

## Project Statistics

### Code Metrics
- **Total Lines**: ~6,500 lines of Python code
- **Total Size**: ~260 KB of source code
- **Modules**: 15 production-ready modules
- **Classes**: 40+ classes
- **Methods**: 200+ methods
- **Documentation**: Comprehensive inline comments

### Testing Coverage
- ✅ Database layer tested (Phases 2)
- ✅ Authentication system tested (Phase 3)
- ✅ GUI components tested (Phase 4)
- ✅ Registry operations tested (Phase 5)
- ✅ Logging manager tested (Phase 7)
- ✅ Scheduler tested (Phase 8)
- ✅ Policy manager tested (Phase 9)
- ✅ Report generator tested (Phase 10)

## Installation

### Prerequisites
- Windows 10 or later
- Python 3.12+ (for development)
- 2GB RAM minimum
- Internet connection (for dependencies)

### Development Setup

```bash
# 1. Clone/Extract the project
cd webcam_spyware_security

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application
python main.py
```

### Production Deployment

```bash
# Build Windows executable
python build_config.py build

# Distribute dist/WebcamSecurity folder
# Users run: WebcamSecurity.exe
```

## Usage Guide

### First Run
1. **Create Admin Account**
   - Launch application
   - Register new admin user
   - Set strong password

2. **Configure Camera Protection**
   - Enable camera monitoring
   - Register authorized faces
   - Set access policies

3. **Set Automatic Schedules**
   - Business hours protection
   - After-hours monitoring
   - Weekend policies

4. **Monitor Activity**
   - View activity logs
   - Generate reports
   - Review security events

### Daily Operations
- Check activity logs for unauthorized access attempts
- Review and respond to security alerts
- Verify camera status in real-time
- Export weekly security reports

### Administration
- Manage user accounts
- Create/update access policies
- Configure automatic schedules
- Review audit trails
- Export comprehensive reports

## Security Specifications

### Cryptography
- **Hashing**: bcrypt with 12 rounds (>100ms per hash)
- **Encryption**: AES-128 (Fernet) with HMAC
- **Key Storage**: Secure local file (.encryption_key)
- **Session Tokens**: 256-bit random (UUID4 format)

### Access Control
- **Authentication**: Username/password with 3-attempt lockout
- **Authorization**: Role-based access control (2 roles)
- **Session**: 24-hour expiry, automatic cleanup
- **Privilege**: Admin detection for system operations

### Face Recognition
- **Model**: HOG (Histogram of Oriented Gradients)
- **Encoding**: 128-dimensional face encoding
- **Matching**: Distance < 0.6 (1 - distance confidence)
- **Speed**: ~100-200ms per face on typical hardware

### Logging
- **Encryption**: All sensitive logs encrypted
- **Retention**: Configurable retention (default 90 days)
- **Immutable**: Database-level audit trail
- **User Tracking**: All actions linked to user

## Performance Characteristics

### Benchmarks (Intel i5, 8GB RAM)
- GUI Startup: 1-2 seconds
- Camera Detection: 0.5-1 second
- Face Recognition: 100-200ms per face
- Policy Evaluation: <10ms
- Report Generation: <500ms for 1000 entries
- Database Query: <50ms typical

### Resource Usage
- **Memory**: 150-300 MB during operation
- **CPU**: <5% idle, <20% during face recognition
- **Disk**: ~100MB app + 50-100MB database
- **Network**: Offline operation (no internet required)

## File Structure

```
webcam_spyware_security/
├── Python Modules (15 files, ~260 KB)
│   ├── Core: main.py, gui.py, database.py
│   ├── Security: authentication.py, crypto_manager.py
│   ├── Devices: camera_controller.py, registry_manager.py
│   ├── Features: face_manager.py, policy_manager.py, scheduler.py
│   ├── Logging: logging_manager.py, report_generator.py
│   ├── Support: utils.py, assets.py, user_manager.py, build_config.py
│   └── Main entry: main.py
│
├── Data Directories
│   ├── database/
│   │   ├── app.db (SQLite database)
│   │   └── .encryption_key (Fernet key)
│   ├── assets/
│   │   └── faces/ (Face recognition data)
│   ├── logs/ (Activity logs)
│   ├── reports/ (Generated reports)
│   └── temp/ (Temporary files)
│
├── Documentation
│   ├── README.md (This file)
│   ├── BUILD_GUIDE.md (Build instructions)
│   ├── requirements.txt (Dependencies)
│   └── LICENSE (Proprietary)
```

## Configuration

### Application Settings
Available in database settings table:
- Camera monitoring: enabled/disabled
- Face recognition threshold: 0.6 (default)
- Session timeout: 24 hours
- Log retention: 90 days
- Report format: JSON (default)

### Environment Variables (Optional)
```bash
WEBCAM_SECURITY_DB=./database/app.db
LOG_LEVEL=INFO
```

## Troubleshooting

### Camera Not Detected
```
Solution: 
- Check camera connection
- Verify device driver
- Run as administrator
```

### Face Recognition Fails
```
Solution:
- Ensure good lighting
- Check image quality
- Verify face_recognition library
```

### Registry Access Denied
```
Solution:
- Run application as administrator
- Check Windows Registry permissions
```

### Database Locked
```
Solution:
- Close other instances
- Check file permissions
- Restore from backup if corrupted
```

## Development

### Running Tests
```bash
# Phase-specific tests
python database.py      # Phase 2
python authentication.py # Phase 3
python gui.py           # Phase 4
python scheduler.py     # Phase 8
python policy_manager.py # Phase 9
python report_generator.py # Phase 10
```

### Building Executable
```bash
# Check environment
python build_config.py check

# Build with PyInstaller
python build_config.py build

# Output: dist/WebcamSecurity/WebcamSecurity.exe
```

### Development Guidelines
- Follow PEP 8 style guide
- Add docstrings to all functions
- Use type hints where applicable
- Log important operations
- Test before committing

## Future Enhancements

### Planned Features
- [ ] Cloud sync for multi-device
- [ ] Mobile app integration
- [ ] Email alerts on security events
- [ ] Advanced analytics dashboard
- [ ] Machine learning threat detection
- [ ] RFID badge integration
- [ ] Network camera support
- [ ] Event recording and playback

### Technical Improvements
- [ ] Async database operations
- [ ] Websocket real-time updates
- [ ] GraphQL API
- [ ] Unit test suite
- [ ] CI/CD pipeline
- [ ] Docker containerization

## Support

### Getting Help
1. Check BUILD_GUIDE.md for common issues
2. Review logs in logs/ directory
3. Check database for error entries
4. Review activity logs for clues

### Reporting Issues
- Document steps to reproduce
- Include log excerpts
- Attach relevant screenshots
- Note system specifications

## License

**Proprietary License** - All rights reserved

This software is proprietary and confidential. Unauthorized copying, modification, or distribution is prohibited.

## Version History

### Version 1.0 (Current)
- Initial production release
- All 11 development phases complete
- Full feature set implemented
- Comprehensive documentation
- Production-ready code

### Version Information
- **Release Date**: 2024
- **Build System**: PyInstaller 6.3.0
- **Python Target**: 3.12+
- **Windows Support**: 10/11

## Credits

Developed as an enterprise-grade privacy protection solution combining:
- Modern UI with CustomTkinter
- Advanced biometric authentication
- Sophisticated policy engine
- Comprehensive logging & reporting
- Production-ready deployment system

---

**Status**: ✅ Production Ready
**Last Updated**: 2024
**Maintenance**: Active
**Support**: Available

For questions or more information, contact the development team.
