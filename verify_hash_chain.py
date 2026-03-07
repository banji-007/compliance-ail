import sys
import os
import hashlib
import json

# Add ledger path
sys.path.append(os.path.join(os.path.dirname(__file__), 'ledger'))
from sqlite_ledger import get_ledger

def verify_manual_hash_chain():
    """Manually verify the hash chaining logic"""
    ledger = get_ledger()
    records = ledger.get_all_records()
    
    print("MANUAL HASH CHAIN VERIFICATION")
    print("=" * 50)
    
    previous_hash = "0" * 64  # Genesis hash
    
    for i, record in enumerate(records):
        # Recalculate expected hash
        hash_data = f"{record['timestamp']}{record['agent_id']}{record['tool_name']}{record['payload']}{record['decision']}"
        expected_hash = hashlib.sha256(f"{hash_data}{previous_hash}".encode()).hexdigest()
        
        print(f"\nRecord {record['id']}:")
        print(f"  Previous hash: {previous_hash[:16]}...")
        print(f"  Data: {hash_data[:50]}...")
        print(f"  Expected hash: {expected_hash[:16]}...")
        print(f"  Actual hash:   {record['record_hash'][:16]}...")
        print(f"  Match: {'YES' if expected_hash == record['record_hash'] else 'NO'}")
        
        if expected_hash != record['record_hash']:
            print(f"  ERROR: Hash mismatch!")
            return False
        
        previous_hash = record['record_hash']
    
    print(f"\nAll {len(records)} records have valid hash chains!")
    return True

if __name__ == "__main__":
    verify_manual_hash_chain()
