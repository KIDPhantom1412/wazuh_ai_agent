"""
Debug script for rule_verification_node issues.
This script helps identify why logtest verification fails even when rules work in dashboard.
"""

import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def analyze_logtest_response(response: dict, expected_rule_ids: set[int]):
    """Analyze a logtest response and check for common issues."""
    
    print("\n" + "="*80)
    print("LOGTEST RESPONSE ANALYSIS")
    print("="*80)
    
    print(f"\nExpected Rule IDs: {sorted(expected_rule_ids)}")
    print(f"\nFull Response:\n{json.dumps(response, indent=2, ensure_ascii=False)}")
    
    # Try different parsing strategies
    strategies = []
    
    # Strategy 1: data.output.rule.id
    data = response.get("data", {})
    if "output" in data:
        output = data.get("output", {})
        strategies.append(("data.output", output))
    
    # Strategy 2: data.rule.id (direct)
    if "rule" in data:
        strategies.append(("data (direct)", data))
    
    # Strategy 3: root level
    if "rule" in response:
        strategies.append(("root level", response))
    
    print(f"\n\nTrying {len(strategies)} parsing strategies:")
    
    for strategy_name, output in strategies:
        print(f"\n--- Strategy: {strategy_name} ---")
        
        if not isinstance(output, dict):
            print(f"  ❌ Output is not a dict: {type(output)}")
            continue
        
        matched_rule = output.get("rule", {})
        print(f"  Matched rule object: {matched_rule}")
        
        if not isinstance(matched_rule, dict):
            print(f"  ❌ Rule is not a dict: {type(matched_rule)}")
            continue
        
        matched_id = matched_rule.get("id")
        print(f"  Matched ID (raw): {matched_id} (type: {type(matched_id)})")
        
        if matched_id is None:
            print(f"  ❌ No ID found in rule")
            continue
        
        # Try to convert to int
        try:
            matched_id_int = int(matched_id)
            print(f"  Matched ID (int): {matched_id_int}")
            
            if matched_id_int in expected_rule_ids:
                print(f"  ✅ SUCCESS! Matched ID {matched_id_int} is in expected IDs")
                return True
            else:
                print(f"  ❌ Matched ID {matched_id_int} NOT in expected IDs {sorted(expected_rule_ids)}")
        except (ValueError, TypeError) as e:
            print(f"  ❌ Failed to convert ID to int: {e}")
    
    print("\n" + "="*80)
    return False


def test_log_field_extraction(sample_logs: list):
    """Test different strategies for extracting log content."""
    
    print("\n" + "="*80)
    print("LOG FIELD EXTRACTION TEST")
    print("="*80)
    
    for idx, sample_log in enumerate(sample_logs):
        print(f"\n--- Log #{idx + 1} ---")
        print(f"Type: {type(sample_log)}")
        
        if isinstance(sample_log, dict):
            print(f"Keys: {list(sample_log.keys())}")
            
            # Try different field names
            fields_to_try = ["full_log", "message", "log", "data.log"]
            
            for field in fields_to_try:
                if "." in field:
                    parts = field.split(".")
                    value = sample_log
                    for part in parts:
                        if isinstance(value, dict):
                            value = value.get(part)
                        else:
                            value = None
                            break
                else:
                    value = sample_log.get(field)
                
                if value:
                    print(f"  ✅ Found '{field}': {value[:100]}..." if len(str(value)) > 100 else f"  ✅ Found '{field}': {value}")
                else:
                    print(f"  ❌ '{field}' not found or empty")
            
            # Show full_log if exists
            if "full_log" in sample_log:
                print(f"\nfull_log content:\n{sample_log['full_log']}")
        else:
            print(f"Log content: {sample_log}")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    # Example 1: Test logtest response parsing
    print("\n\nEXAMPLE 1: Testing logtest response parsing")
    
    # Simulate a successful logtest response
    test_response_1 = {
        "data": {
            "output": {
                "rule": {
                    "id": "110001",
                    "level": 5,
                    "description": "Test rule"
                }
            }
        }
    }
    
    expected_ids = {110001, 110002}
    analyze_logtest_response(test_response_1, expected_ids)
    
    # Example 2: Test with different response structure
    print("\n\nEXAMPLE 2: Testing alternative response structure")
    
    test_response_2 = {
        "data": {
            "rule": {
                "id": 110001,  # Note: int instead of string
                "level": 5
            }
        }
    }
    
    analyze_logtest_response(test_response_2, expected_ids)
    
    # Example 3: Test log field extraction
    print("\n\nEXAMPLE 3: Testing log field extraction")
    
    sample_logs = [
        {
            "full_log": "Jan 01 12:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
            "location": "/var/log/auth.log",
            "timestamp": "2026-01-01T12:00:00Z"
        },
        {
            "message": "Authentication failure",
            "data": {
                "log": "Failed login attempt"
            }
        },
        {
            "log": "Direct log field"
        }
    ]
    
    test_log_field_extraction(sample_logs)
    
    print("\n\n" + "="*80)
    print("DEBUG SCRIPT COMPLETED")
    print("="*80)
    print("\nTo use this script with your actual data:")
    print("1. Capture the actual logtest response from your Wazuh API")
    print("2. Capture the actual log samples from your indexer")
    print("3. Replace the test data above with your real data")
    print("4. Run: python debug_verification.py")
