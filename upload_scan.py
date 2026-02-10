#!/usr/bin/env python3
"""
Upload scan results to JSON-based web dashboard
"""

import requests
import json

def upload_scan(results, system_name="macOS System", framework="CIS macOS"):
    """Upload scan results to the dashboard API"""
    
    # Calculate statistics
    total = len(results)
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    errors = len([r for r in results if r['status'] == 'ERROR'])
    compliance_score = round((passed / total * 100), 1) if total > 0 else 0
    
    # Prepare data for API
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
    
    try:
        # Send to API
        response = requests.post(
            'http://localhost:3000/api/scans',
            json=scan_data,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        
        if response.status_code == 200:
            print("✓ Scan uploaded successfully!")
            print("  View at: http://localhost:3000")
            return True
        else:
            print(f"✗ Upload failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("✗ Could not connect to dashboard.")
        print("  Make sure the dashboard is running: cd ~/Desktop/compliance-dashboard-simple && npm run dev")
        return False
    except Exception as e:
        print(f"✗ Upload error: {str(e)}")
        return False
