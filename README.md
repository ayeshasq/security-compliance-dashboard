
# 🔒 Security Compliance Dashboard

A comprehensive macOS security compliance scanner with real-time web dashboard visualization.

![Dashboard Preview](https://img.shields.io/badge/Status-Active-success)
![Platform](https://img.shields.io/badge/Platform-macOS-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 Features

- **17+ Security Checks** - Comprehensive CIS benchmark compliance scanning
- **Real-time Dashboard** - Beautiful web interface with charts and visualizations
- **Educational Insights** - Plain-English explanations for each security check
- **Priority Guidance** - Severity-based recommendations (Critical/High/Medium/Low)
- **Automated Remediation** - Step-by-step fix instructions
- **Full-Stack Application** - Python backend + Next.js frontend

## 🔍 Security Checks Performed

### Core System Security
- Firewall Status
- FileVault Disk Encryption
- Gatekeeper App Signing
- System Integrity Protection (SIP)
- Remote Login (SSH)

### User Account Security
- Admin Account Audit
- Password Policy Strength
- Guest Account Status
- Password Hints Configuration

### Application Security
- XProtect Malware Scanner
- Download Quarantine Protection
- Automatic Security Updates

### Network & Sharing
- Bluetooth Security
- AirDrop Settings
- File Sharing Status
- macOS Version Check

## 🛠️ Tech Stack

**Frontend:**
- Next.js 15
- React 19
- Tailwind CSS
- Recharts (data visualization)

**Backend:**
- Python 3.12
- Subprocess (system checks)
- JSON file storage

## 📦 Installation

### Prerequisites
- macOS 14.0 or later
- Python 3.12+
- Node.js 18+

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/security-compliance-dashboard.git
cd security-compliance-dashboard
```

2. **Install dependencies**
```bash
npm install --legacy-peer-deps
```

3. **Start the dashboard**
```bash
npm run dev
```

4. **Run a security scan** (in new terminal)
```bash
cd ../python-scanner
python3 -m venv venv
source venv/bin/activate
pip install colorama requests
python3 scanner.py
```

5. **View results**
Open http://localhost:3000 in your browser

## 🎯 Usage

1. Start the web dashboard: `npm run dev`
2. Run the scanner: `python3 scanner.py`
3. View results at http://localhost:3000
4. Review failed checks and follow remediation steps

## 📊 Sample Output
```
╔═══════════════════════════════════════════════╗
║   Security Compliance Checker v3.0            ║
║   Ultimate macOS Security Audit Tool          ║
║   17+ Comprehensive Security Checks           ║
╚═══════════════════════════════════════════════╝

[PASS] MACOS-FW-001: Firewall Status
[PASS] MACOS-FV-001: FileVault Disk Encryption
[FAIL] MACOS-SSH-001: Remote Login (SSH)

Compliance Score: 82.4%
```

## 🔐 Security Best Practices

This tool implements security checks based on:
- CIS (Center for Internet Security) Benchmarks
- Apple Security Guidelines
- Industry best practices

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

MIT License - feel free to use this project for learning and portfolio purposes.

## 👤 Author

** AYESHA SIDDIQUI **


⭐ Star this repo if you find it helpful!
