#!/usr/bin/env python3
"""
Python ZAP wrapper for Templar Hospitaller.
This provides a zap-cli compatible interface using the Python ZAP API.
"""

import json
import sys
import time
from zapv2 import ZAPv2

def quick_scan(targets, timeout=300):
    """Perform a quick scan using ZAP API"""
    zap = ZAPv2(apikey='', proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    
    # Start the scan
    scan_id = zap.ascan.scan(targets[0] if isinstance(targets, list) else targets)
    
    # Wait for completion
    start_time = time.time()
    while int(zap.ascan.status(scan_id)) < 100:
        if time.time() - start_time > timeout:
            break
        time.sleep(5)
    
    # Get alerts
    alerts = zap.core.alerts()
    
    # Format output similar to zap-cli --json
    output = []
    for alert in alerts:
        output.append({
            'alert': alert.get('alert', 'Unknown'),
            'description': alert.get('description', ''),
            'risk': alert.get('risk', 'Medium'),
            'url': alert.get('url', '')
        })
    
    return json.dumps(output, indent=2)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'quick-scan' and '--json' in sys.argv:
        # Extract target from arguments
        target_idx = sys.argv.index('--self-contained') + 1 if '--self-contained' in sys.argv else -1
        if target_idx < len(sys.argv):
            target = sys.argv[target_idx]
            result = quick_scan([target])
            print(result)
        else:
            print('[]')
    else:
        print('[]')
