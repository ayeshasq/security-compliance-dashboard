#!/usr/bin/env python3
"""
Security Compliance Checker for macOS - Ultimate Edition
Comprehensive security audit tool with 18+ checks
"""

import os
import sys
import subprocess
import platform
import pwd
import time
from datetime import datetime, timedelta
from colorama import init, Fore, Style

# Try to import upload_scan
try:
    from upload_scan import upload_scan
    UPLOAD_AVAILABLE = True
except ImportError:
    UPLOAD_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║   Security Compliance Checker v3.0            ║
    ║   Ultimate macOS Security Audit Tool          ║
    ║   18+ Comprehensive Security Checks           ║
    ╚═══════════════════════════════════════════════╝
    """
    print(f"{Fore.CYAN}{banner}")

def run_command(command):
    """Helper to run shell commands safely"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), -1

def check_firewall():
    """Check if macOS firewall is enabled"""
    stdout, stderr, returncode = run_command(
        "defaults read /Library/Preferences/com.apple.alf globalstate"
    )
    
    if stdout in ['1', '2']:
        return {
            'check_id': 'MACOS-FW-001',
            'check_name': 'Firewall Status',
            'status': 'PASS',
            'severity': 'HIGH',
            'description': 'Firewall is enabled',
            'current_value': 'Enabled',
            'expected_value': 'Enabled'
        }
    else:
        return {
            'check_id': 'MACOS-FW-001',
            'check_name': 'Firewall Status',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': 'Firewall is not enabled - your Mac is exposed to network attacks',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: System Settings > Network > Firewall > Turn On'
        }

def check_filevault():
    """Check if FileVault disk encryption is enabled"""
    stdout, stderr, returncode = run_command("fdesetup status")
    
    if "FileVault is On" in stdout:
        return {
            'check_id': 'MACOS-FV-001',
            'check_name': 'FileVault Disk Encryption',
            'status': 'PASS',
            'severity': 'CRITICAL',
            'description': 'Full disk encryption is enabled',
            'current_value': 'Enabled',
            'expected_value': 'Enabled'
        }
    else:
        return {
            'check_id': 'MACOS-FV-001',
            'check_name': 'FileVault Disk Encryption',
            'status': 'FAIL',
            'severity': 'CRITICAL',
            'description': 'Disk encryption is disabled - data vulnerable if Mac is stolen',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: System Settings > Privacy & Security > FileVault > Turn On'
        }

def check_gatekeeper():
    """Check if Gatekeeper is enabled"""
    stdout, stderr, returncode = run_command("spctl --status")
    
    if "assessments enabled" in stdout:
        return {
            'check_id': 'MACOS-GK-001',
            'check_name': 'Gatekeeper (App Signing)',
            'status': 'PASS',
            'severity': 'HIGH',
            'description': 'Gatekeeper protects against unsigned/malicious apps',
            'current_value': 'Enabled',
            'expected_value': 'Enabled'
        }
    else:
        return {
            'check_id': 'MACOS-GK-001',
            'check_name': 'Gatekeeper (App Signing)',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': 'Gatekeeper disabled - can run untrusted apps',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: sudo spctl --master-enable'
        }

def check_sip():
    """Check System Integrity Protection status"""
    stdout, stderr, returncode = run_command("csrutil status")
    
    if "enabled" in stdout.lower():
        return {
            'check_id': 'MACOS-SIP-001',
            'check_name': 'System Integrity Protection (SIP)',
            'status': 'PASS',
            'severity': 'CRITICAL',
            'description': 'SIP prevents malware from modifying system files',
            'current_value': 'Enabled',
            'expected_value': 'Enabled'
        }
    else:
        return {
            'check_id': 'MACOS-SIP-001',
            'check_name': 'System Integrity Protection (SIP)',
            'status': 'FAIL',
            'severity': 'CRITICAL',
            'description': 'SIP disabled - system files vulnerable to tampering',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: Reboot to Recovery Mode, Terminal: csrutil enable'
        }

def check_remote_login():
    """Check if SSH/Remote Login is disabled"""
    stdout, stderr, returncode = run_command("sudo systemsetup -getremotelogin")
    
    if "Off" in stdout:
        return {
            'check_id': 'MACOS-SSH-001',
            'check_name': 'Remote Login (SSH)',
            'status': 'PASS',
            'severity': 'HIGH',
            'description': 'SSH remote login is disabled (recommended unless needed)',
            'current_value': 'Disabled',
            'expected_value': 'Disabled'
        }
    else:
        return {
            'check_id': 'MACOS-SSH-001',
            'check_name': 'Remote Login (SSH)',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': 'SSH is enabled - potential unauthorized remote access',
            'current_value': 'Enabled',
            'expected_value': 'Disabled (unless required)',
            'remediation': 'Disable: System Settings > General > Sharing > Remote Login > Off'
        }

def check_automatic_updates():
    """Check automatic security updates"""
    stdout, stderr, returncode = run_command(
        "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates"
    )
    
    if stdout == '1':
        return {
            'check_id': 'MACOS-AU-001',
            'check_name': 'Automatic Security Updates',
            'status': 'PASS',
            'severity': 'MEDIUM',
            'description': 'Automatic security updates are enabled',
            'current_value': 'Enabled',
            'expected_value': 'Enabled'
        }
    else:
        return {
            'check_id': 'MACOS-AU-001',
            'check_name': 'Automatic Security Updates',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'description': 'Automatic updates disabled - missing critical patches',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: System Settings > General > Software Update > Automatic Updates'
        }

def check_screensaver_password():
    """Check screensaver password requirement"""
    stdout, stderr, returncode = run_command(
        "defaults read com.apple.screensaver askForPassword"
    )
    
    if stdout == '1':
        return {
            'check_id': 'MACOS-SS-001',
            'check_name': 'Screensaver Password',
            'status': 'PASS',
            'severity': 'MEDIUM',
            'description': 'Password required after screensaver',
            'current_value': 'Required',
            'expected_value': 'Required'
        }
    else:
        return {
            'check_id': 'MACOS-SS-001',
            'check_name': 'Screensaver Password',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'description': 'No password required - anyone can access unlocked Mac',
            'current_value': 'Not Required',
            'expected_value': 'Required',
            'remediation': 'Enable: System Settings > Lock Screen > Require password immediately'
        }

def check_guest_account():
    """Check if guest account is disabled"""
    stdout, stderr, returncode = run_command(
        "sudo dscl . -read /Users/Guest"
    )
    
    if "does not exist" in stderr or returncode != 0:
        return {
            'check_id': 'MACOS-USR-001',
            'check_name': 'Guest Account Disabled',
            'status': 'PASS',
            'severity': 'MEDIUM',
            'description': 'Guest account is properly disabled',
            'current_value': 'Disabled',
            'expected_value': 'Disabled'
        }
    else:
        return {
            'check_id': 'MACOS-USR-001',
            'check_name': 'Guest Account Disabled',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'description': 'Guest account enabled - unauthorized access risk',
            'current_value': 'Enabled',
            'expected_value': 'Disabled',
            'remediation': 'Disable: System Settings > Users & Groups > Guest User > Off'
        }

def check_show_password_hints():
    """Check if password hints are disabled"""
    stdout, stderr, returncode = run_command(
        "defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint"
    )
    
    if stdout == '0' or returncode != 0:
        return {
            'check_id': 'MACOS-PWD-001',
            'check_name': 'Password Hints Disabled',
            'status': 'PASS',
            'severity': 'LOW',
            'description': 'Password hints are disabled',
            'current_value': 'Disabled',
            'expected_value': 'Disabled'
        }
    else:
        return {
            'check_id': 'MACOS-PWD-001',
            'check_name': 'Password Hints Disabled',
            'status': 'FAIL',
            'severity': 'LOW',
            'description': 'Password hints shown - information leakage',
            'current_value': f'Shown after {stdout} attempts',
            'expected_value': 'Never shown',
            'remediation': 'Disable: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0'
        }

def check_bluetooth():
    """Check Bluetooth status"""
    stdout, stderr, returncode = run_command(
        "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState"
    )
    
    if stdout == '0':
        return {
            'check_id': 'MACOS-BT-001',
            'check_name': 'Bluetooth Security',
            'status': 'PASS',
            'severity': 'LOW',
            'description': 'Bluetooth is disabled (recommended when not in use)',
            'current_value': 'Disabled',
            'expected_value': 'Disabled when not needed'
        }
    else:
        return {
            'check_id': 'MACOS-BT-001',
            'check_name': 'Bluetooth Security',
            'status': 'FAIL',
            'severity': 'LOW',
            'description': 'Bluetooth enabled - potential attack vector',
            'current_value': 'Enabled',
            'expected_value': 'Disabled when not in use',
            'remediation': 'Disable when not needed: System Settings > Bluetooth > Off'
        }

def check_macos_version():
    """Check macOS version is recent"""
    version = platform.mac_ver()[0]
    major_version = int(version.split('.')[0])
    
    # macOS 14 (Sonoma) or later is current
    if major_version >= 14:
        return {
            'check_id': 'MACOS-VER-001',
            'check_name': 'macOS Version Current',
            'status': 'PASS',
            'severity': 'HIGH',
            'description': f'Running modern macOS version {version}',
            'current_value': version,
            'expected_value': '14.0 or later'
        }
    else:
        return {
            'check_id': 'MACOS-VER-001',
            'check_name': 'macOS Version Current',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': f'Running outdated macOS {version} - missing security patches',
            'current_value': version,
            'expected_value': '14.0 or later',
            'remediation': 'Update: System Settings > General > Software Update'
        }

def check_admin_accounts():
    """Check number of admin accounts"""
    stdout, stderr, returncode = run_command(
        "dscl . -read /Groups/admin GroupMembership"
    )
    
    if stdout:
        admins = stdout.replace('GroupMembership:', '').strip().split()
        admin_count = len(admins)
        
        if admin_count <= 2:
            return {
                'check_id': 'MACOS-USR-002',
                'check_name': 'Admin Account Audit',
                'status': 'PASS',
                'severity': 'MEDIUM',
                'description': f'Appropriate number of admin accounts: {admin_count}',
                'current_value': f'{admin_count} admins: {", ".join(admins)}',
                'expected_value': '1-2 admin accounts'
            }
        else:
            return {
                'check_id': 'MACOS-USR-002',
                'check_name': 'Admin Account Audit',
                'status': 'FAIL',
                'severity': 'MEDIUM',
                'description': f'Too many admin accounts ({admin_count}) - increased risk',
                'current_value': f'{admin_count} admins: {", ".join(admins)}',
                'expected_value': '1-2 admin accounts',
                'remediation': 'Review and demote unnecessary admin accounts to Standard users'
            }
    
    return {
        'check_id': 'MACOS-USR-002',
        'check_name': 'Admin Account Audit',
        'status': 'ERROR',
        'severity': 'MEDIUM',
        'description': 'Could not check admin accounts'
    }

def check_password_policy():
    """Check password policy and requirements"""
    # Check minimum password length
    stdout, stderr, returncode = run_command(
        "pwpolicy -getaccountpolicies 2>/dev/null | grep -i 'policyAttributePassword matches'"
    )
    
    # Check if password policy is configured
    policy_stdout, _, _ = run_command(
        "pwpolicy -getaccountpolicies 2>&1"
    )
    
    has_policy = "policyContent" in policy_stdout or "policyCategoryPasswordContent" in policy_stdout
    
    if has_policy:
        # Try to determine minimum length
        min_length = "Unknown"
        if ".{" in policy_stdout:
            try:
                # Extract number from pattern like .{8,}
                import re
                match = re.search(r'\.{(\d+)', policy_stdout)
                if match:
                    min_length = match.group(1)
            except:
                pass
        
        # Check if strong requirements exist
        has_complexity = any(term in policy_stdout.lower() for term in ['uppercase', 'lowercase', 'digit', 'special'])
        
        if min_length != "Unknown" and int(min_length) >= 8 and has_complexity:
            return {
                'check_id': 'MACOS-PWD-002',
                'check_name': 'Password Policy Strength',
                'status': 'PASS',
                'severity': 'HIGH',
                'description': f'Strong password policy configured (min {min_length} chars with complexity)',
                'current_value': f'Min {min_length} characters, complexity required',
                'expected_value': 'Min 8+ characters with complexity'
            }
        elif min_length != "Unknown" and int(min_length) >= 8:
            return {
                'check_id': 'MACOS-PWD-002',
                'check_name': 'Password Policy Strength',
                'status': 'FAIL',
                'severity': 'HIGH',
                'description': f'Password policy exists but lacks complexity requirements',
                'current_value': f'Min {min_length} characters, no complexity',
                'expected_value': 'Min 8+ characters with complexity (upper, lower, numbers)',
                'remediation': 'Configure: sudo pwpolicy -setglobalpolicy "minChars=8 requiresAlpha=1 requiresNumeric=1"'
            }
        else:
            return {
                'check_id': 'MACOS-PWD-002',
                'check_name': 'Password Policy Strength',
                'status': 'FAIL',
                'severity': 'HIGH',
                'description': 'Weak or no password policy configured',
                'current_value': 'Minimal or no requirements',
                'expected_value': 'Min 8+ characters with complexity',
                'remediation': 'Configure: sudo pwpolicy -setglobalpolicy "minChars=8 requiresAlpha=1 requiresNumeric=1"'
            }
    else:
        return {
            'check_id': 'MACOS-PWD-002',
            'check_name': 'Password Policy Strength',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': 'No password policy configured - weak passwords allowed',
            'current_value': 'No policy',
            'expected_value': 'Strong password requirements',
            'remediation': 'Configure: sudo pwpolicy -setglobalpolicy "minChars=8 requiresAlpha=1 requiresNumeric=1"'
        }

def check_xprotect():
    """Check XProtect (Apple's malware scanner) status"""
    # Check if XProtect is present and updated
    xprotect_path = "/System/Library/CoreServices/XProtect.bundle"
    
    if os.path.exists(xprotect_path):
        # Check last update time
        plist_path = f"{xprotect_path}/Contents/Resources/XProtect.meta.plist"
        
        if os.path.exists(plist_path):
            # Get file modification time
            mod_time = os.path.getmtime(plist_path)
            last_update = datetime.fromtimestamp(mod_time)
            days_old = (datetime.now() - last_update).days
            
            if days_old <= 30:
                return {
                    'check_id': 'MACOS-APP-001',
                    'check_name': 'XProtect Malware Scanner',
                    'status': 'PASS',
                    'severity': 'HIGH',
                    'description': f'XProtect is active and updated ({days_old} days old)',
                    'current_value': f'Active, updated {days_old} days ago',
                    'expected_value': 'Active and updated within 30 days'
                }
            else:
                return {
                    'check_id': 'MACOS-APP-001',
                    'check_name': 'XProtect Malware Scanner',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'description': f'XProtect definitions outdated ({days_old} days old)',
                    'current_value': f'Last updated {days_old} days ago',
                    'expected_value': 'Updated within 30 days',
                    'remediation': 'Update: System Settings > General > Software Update'
                }
        else:
            return {
                'check_id': 'MACOS-APP-001',
                'check_name': 'XProtect Malware Scanner',
                'status': 'FAIL',
                'severity': 'HIGH',
                'description': 'XProtect installed but cannot verify update status',
                'current_value': 'Status unknown',
                'expected_value': 'Active and updated'
            }
    else:
        return {
            'check_id': 'MACOS-APP-001',
            'check_name': 'XProtect Malware Scanner',
            'status': 'FAIL',
            'severity': 'CRITICAL',
            'description': 'XProtect not found - no malware protection',
            'current_value': 'Not installed',
            'expected_value': 'Installed and active',
            'remediation': 'Reinstall macOS or run System Update'
        }

def check_quarantine():
    """Check if quarantine attribute is enforced on downloads"""
    # Check if quarantine is enabled globally
    stdout, stderr, returncode = run_command(
        "defaults read com.apple.LaunchServices LSQuarantine"
    )
    
    # If the key doesn't exist or is enabled, that's good
    if returncode != 0 or stdout == '' or stdout == '1':
        # Check if quarantine events are being logged
        quarantine_db = os.path.expanduser("~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        
        if os.path.exists(quarantine_db):
            return {
                'check_id': 'MACOS-APP-002',
                'check_name': 'Download Quarantine Protection',
                'status': 'PASS',
                'severity': 'HIGH',
                'description': 'Quarantine attribute enabled - downloads are scanned',
                'current_value': 'Enabled and active',
                'expected_value': 'Enabled'
            }
        else:
            return {
                'check_id': 'MACOS-APP-002',
                'check_name': 'Download Quarantine Protection',
                'status': 'FAIL',
                'severity': 'HIGH',
                'description': 'Quarantine database missing - downloads may not be scanned',
                'current_value': 'Potentially disabled',
                'expected_value': 'Enabled',
                'remediation': 'System should recreate automatically. If issues persist, check System Settings > Privacy & Security'
            }
    else:
        return {
            'check_id': 'MACOS-APP-002',
            'check_name': 'Download Quarantine Protection',
            'status': 'FAIL',
            'severity': 'HIGH',
            'description': 'Quarantine disabled - downloads not scanned for malware',
            'current_value': 'Disabled',
            'expected_value': 'Enabled',
            'remediation': 'Enable: defaults delete com.apple.LaunchServices LSQuarantine (requires restart)'
        }

def check_airdrop():
    """Check AirDrop discoverability"""
    stdout, stderr, returncode = run_command(
        "defaults read com.apple.sharingd DiscoverableMode"
    )
    
    if "Off" in stdout or returncode != 0:
        return {
            'check_id': 'MACOS-NET-001',
            'check_name': 'AirDrop Discoverability',
            'status': 'PASS',
            'severity': 'LOW',
            'description': 'AirDrop not set to Everyone (good privacy)',
            'current_value': 'Limited/Off',
            'expected_value': 'Contacts Only or Off'
        }
    else:
        return {
            'check_id': 'MACOS-NET-001',
            'check_name': 'AirDrop Discoverability',
            'status': 'FAIL',
            'severity': 'LOW',
            'description': 'AirDrop may be visible to everyone',
            'current_value': 'Potentially Everyone',
            'expected_value': 'Contacts Only',
            'remediation': 'Change: Control Center > AirDrop > Contacts Only'
        }

def check_file_sharing():
    """Check if file sharing services are disabled"""
    stdout, stderr, returncode = run_command(
        "sudo launchctl list | grep com.apple.smbd"
    )
    
    if not stdout or returncode != 0:
        return {
            'check_id': 'MACOS-SHR-001',
            'check_name': 'File Sharing Disabled',
            'status': 'PASS',
            'severity': 'MEDIUM',
            'description': 'File sharing is disabled (recommended unless needed)',
            'current_value': 'Disabled',
            'expected_value': 'Disabled'
        }
    else:
        return {
            'check_id': 'MACOS-SHR-001',
            'check_name': 'File Sharing Disabled',
            'status': 'FAIL',
            'severity': 'MEDIUM',
            'description': 'File sharing is enabled - potential data exposure',
            'current_value': 'Enabled',
            'expected_value': 'Disabled unless required',
            'remediation': 'Disable: System Settings > General > Sharing > File Sharing > Off'
        }

def run_all_checks():
    """Run all security checks"""
    checks = [
        check_firewall,
        check_filevault,
        check_gatekeeper,
        check_sip,
        check_remote_login,
        check_automatic_updates,
        check_screensaver_password,
        check_guest_account,
        check_show_password_hints,
        check_bluetooth,
        check_macos_version,
        check_admin_accounts,
        check_password_policy,      # NEW
        check_xprotect,              # NEW
        check_quarantine,            # NEW
        check_airdrop,
        check_file_sharing
    ]
    
    results = []
    for check_func in checks:
        try:
            result = check_func()
            results.append(result)
            
            # Print result
            status_color = {
                'PASS': Fore.GREEN,
                'FAIL': Fore.RED,
                'ERROR': Fore.YELLOW
            }
            color = status_color.get(result['status'], Fore.WHITE)
            print(f"{color}[{result['status']}] {result['check_id']}: {result['check_name']}")
        except Exception as e:
            print(f"{Fore.YELLOW}[ERROR] Error running {check_func.__name__}: {str(e)}")
    
    return results

def print_summary(results):
    """Print summary of compliance check results"""
    total = len(results)
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    errors = len([r for r in results if r['status'] == 'ERROR'])
    
    compliance_score = (passed / total * 100) if total > 0 else 0
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}COMPLIANCE SUMMARY")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.GREEN}Passed:  {passed}/{total}")
    print(f"{Fore.RED}Failed:  {failed}/{total}")
    print(f"{Fore.YELLOW}Errors:  {errors}/{total}")
    print(f"{Fore.CYAN}Compliance Score: {compliance_score:.1f}%")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    # Group by severity
    critical = [r for r in results if r.get('severity') == 'CRITICAL' and r['status'] == 'FAIL']
    high = [r for r in results if r.get('severity') == 'HIGH' and r['status'] == 'FAIL']
    medium = [r for r in results if r.get('severity') == 'MEDIUM' and r['status'] == 'FAIL']
    
    if critical:
        print(f"{Fore.RED}🚨 CRITICAL Issues ({len(critical)}):")
        for result in critical:
            print(f"  • {result['check_name']}: {result['description']}")
    
    if high:
        print(f"\n{Fore.YELLOW}⚠️  HIGH Priority Issues ({len(high)}):")
        for result in high:
            print(f"  • {result['check_name']}: {result['description']}")
    
    if medium:
        print(f"\n{Fore.CYAN}ℹ️  MEDIUM Priority Issues ({len(medium)}):")
        for result in medium:
            print(f"  • {result['check_name']}")
    
    # Print remediation steps for critical and high
    critical_high = critical + high
    if critical_high:
        print(f"\n{Fore.CYAN}📋 PRIORITY REMEDIATION STEPS:")
        print(f"{Fore.CYAN}{'-'*60}")
        for result in critical_high:
            if result.get('remediation'):
                print(f"\n{Fore.YELLOW}[{result['severity']}] {result['check_name']}")
                print(f"{Fore.GREEN}Fix: {result['remediation']}")

def main():
    """Main execution function"""
    print_banner()
    
    print(f"{Fore.CYAN}[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.CYAN}[*] System: macOS {platform.mac_ver()[0]}")
    print(f"{Fore.CYAN}[*] Hostname: {platform.node()}")
    
    # Run all checks
    print(f"\n{Fore.YELLOW}[*] Running 17 comprehensive security checks...\n")
    results = run_all_checks()
    
    # Print summary
    print_summary(results)
    
    # Upload to dashboard if available
    if UPLOAD_AVAILABLE:
        print(f"\n{Fore.YELLOW}[*] Uploading results to dashboard...")
        if upload_scan(results):
            print(f"{Fore.GREEN}[✓] Results uploaded successfully!")
            print(f"{Fore.CYAN}[*] View dashboard at: http://localhost:3000")
        else:
            print(f"{Fore.YELLOW}[!] Upload failed. Check if dashboard is running.")
    else:
        print(f"\n{Fore.YELLOW}[!] Dashboard upload module not available")
    
    print(f"\n{Fore.GREEN}[✓] Security audit completed!")
    print(f"{Fore.CYAN}[*] Total checks performed: {len(results)}")

if __name__ == "__main__":
    main()
