import requests
import json

def upload_scan(results, system_name="macOS System", framework="CIS macOS"):
    """Upload scan results to the dashboard API"""
    
    total = len(results)
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    errors = len([r for r in results if r['status'] == 'ERROR'])
    compliance_score = round((passed / total * 100), 1) if total > 0 else 0
    
    scan_data = {
        'systemName': system_name,
        'framework': framework,
        'complianceScore': compliance_score,
        'totalChecks': total,
        'passedChecks': passed,
        'failedChecks': failed,
        'errorChecks': errors,
        'results': results
    }
    
    # UPDATE THIS URL WITH YOUR ACTUAL VERCEL URL
    urls = [
        'https://security-compliance-dashboard.vercel.app/api/scans',  # <-- CHANGE THIS
        'http://localhost:3000/api/scans'
    ]
    
    for url in urls:
        try:
            response = requests.post(
                url,
                json=scan_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"✓ Scan uploaded successfully!")
                print(f"  View at: {url.replace('/api/scans', '')}")
                return True
        except Exception as e:
            continue
    
    print("✗ Could not upload to dashboard")
    return False
