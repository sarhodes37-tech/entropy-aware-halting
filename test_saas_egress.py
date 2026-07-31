import json
from epistemicos.cpr import PermissionScope

def test_saas_egress_governor():
    print("Testing SaaS Egress Governor (Row Count Limits)...\n")

    # We set a high byte limit to specifically isolate and test the row-counting logic
    scope = PermissionScope(
        max_row_count=50,
        max_payload_bytes=10000000
    )

    # Simulate a safe, isolated API query (e.g., retrieving 5 specific client files)
    safe_salesforce_payload = {
        "query": "SELECT Id, Name FROM Policy__c WHERE Region = 'VA'",
        "records": [{"id": f"POL-{i}", "name": f"Regional Freight {i}"} for i in range(5)],
        "totalSize": 5
    }

    # Simulate a Shinyhunters-style mass exfiltration (e.g., SELECT * FROM Accounts)
    malicious_list_payload = {
        "query": "SELECT * FROM Account",
        "records": [{"id": f"ACT-{i}", "name": "Bulk Dump"} for i in range(15000)],
        "totalSize": 15000
    }

    # Simulate an evasion attempt using dictionary key inflation instead of an array
    malicious_dict_evasion_payload = {
        f"ACT-{i}": {"name": "Bulk Dump", "status": "Active"} for i in range(60)
    }

    print("--- EVALUATING SAFE PAYLOAD ---")
    if scope.validate_egress(safe_salesforce_payload):
        print("  SUCCESS: Safe payload (5 records) passed egress governor.")
    else:
        print("  FAIL: Safe payload was erroneously blocked.")

    print("\n--- EVALUATING MASS EXFILTRATION PAYLOAD (LIST ARRAY) ---")
    if scope.validate_egress(malicious_list_payload):
        print("  FAIL: Mass exfiltration bypassed the governor!")
    else:
        print("  DEFENSE SUCCESSFUL: Payload blocked. Row count exceeded maximum limit (50).")

    print("\n--- EVALUATING DICTIONARY EVASION PAYLOAD ---")
    if scope.validate_egress(malicious_dict_evasion_payload):
        print("  FAIL: Dictionary evasion bypassed the governor!")
    else:
        print("  DEFENSE SUCCESSFUL: Dictionary key inflation blocked. Count exceeded maximum limit (50).")

if __name__ == "__main__":
    test_saas_egress_governor()
