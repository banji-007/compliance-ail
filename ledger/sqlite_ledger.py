import sqlite3
import json
import hashlib
import datetime
from typing import Dict, Any, Optional, List

class SQLiteLedger:
    def __init__(self, db_path: str = "compliance_ledger.db"):
        """Initialize the SQLite ledger database"""
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        self._create_table()
    
    def _create_table(self):
        """Create the audit_logs table if it doesn't exist"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                payload TEXT NOT NULL,
                decision TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE
            )
        ''')
        self.conn.commit()
    
    def _calculate_hash(self, data: str, previous_hash: str = "0" * 64) -> str:
        """Calculate SHA-256 hash of data concatenated with previous hash"""
        combined_data = f"{data}{previous_hash}"
        return hashlib.sha256(combined_data.encode()).hexdigest()
    
    def get_previous_hash(self) -> str:
        """Get the hash of the most recent record"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        return result["record_hash"] if result else "0" * 64  # Genesis hash
    
    def log_tool_call(self, agent_id: str, tool_name: str, payload: Dict[str, Any], 
                     decision: str) -> int:
        """
        Log a tool call to the immutable ledger
        
        Args:
            agent_id: Identifier for the agent
            tool_name: Name of the tool being called
            payload: Dictionary of tool arguments
            decision: "Approved" or "Denied"
            
        Returns:
            int: ID of the inserted record
        """
        # Get previous hash for immutability
        previous_hash = self.get_previous_hash()
        
        # Prepare data for hashing
        timestamp = datetime.datetime.utcnow().isoformat()
        payload_json = json.dumps(payload, sort_keys=True)
        
        # Calculate record hash
        hash_data = f"{timestamp}{agent_id}{tool_name}{payload_json}{decision}"
        record_hash = self._calculate_hash(hash_data, previous_hash)
        
        # Insert record
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs 
            (timestamp, agent_id, tool_name, payload, decision, record_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, agent_id, tool_name, payload_json, decision, record_hash))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def verify_chain_integrity(self) -> bool:
        """
        Verify the integrity of the hash chain
        
        Returns:
            bool: True if chain is intact, False if tampered
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        records = cursor.fetchall()
        
        previous_hash = "0" * 64  # Genesis hash
        
        for record in records:
            # Recalculate expected hash
            hash_data = f"{record['timestamp']}{record['agent_id']}{record['tool_name']}{record['payload']}{record['decision']}"
            expected_hash = self._calculate_hash(hash_data, previous_hash)
            
            if record['record_hash'] != expected_hash:
                print(f"Chain integrity broken at record {record['id']}")
                return False
            
            previous_hash = record['record_hash']
        
        return True
    
    def get_all_records(self) -> List[sqlite3.Row]:
        """Get all records from the ledger"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
        return cursor.fetchall()
    
    def print_ledger(self, limit: Optional[int] = None):
        """Print the ledger in a clean, readable format"""
        records = self.get_all_records()
        
        if limit:
            records = records[-limit:]  # Show last N records
        
        print("\n" + "=" * 100)
        print("COMPLIANCE LEDGER")
        print("=" * 100)
        
        if not records:
            print("No records found in ledger.")
            return
        
        for record in records:
            print(f"\nRecord ID: {record['id']}")
            print(f"Timestamp: {record['timestamp']}")
            print(f"Agent ID: {record['agent_id']}")
            print(f"Tool Name: {record['tool_name']}")
            print(f"Decision: {record['decision']}")
            
            # Pretty print payload
            try:
                payload = json.loads(record['payload'])
                print("Payload:")
                for key, value in payload.items():
                    print(f"  {key}: {value}")
            except json.JSONDecodeError:
                print(f"Payload: {record['payload']}")
            
            print(f"Record Hash: {record['record_hash']}")
            print("-" * 50)
        
        print(f"\nTotal Records: {len(records)}")
        
        # Verify chain integrity
        if self.verify_chain_integrity():
            print("Chain Integrity: VERIFIED")
        else:
            print("Chain Integrity: COMPROMISED")
        
        print("=" * 100)
    
    def search_records(self, agent_id: Optional[str] = None, 
                      tool_name: Optional[str] = None,
                      decision: Optional[str] = None) -> List[sqlite3.Row]:
        """Search records by various criteria"""
        cursor = self.conn.cursor()
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        
        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        
        if decision:
            query += " AND decision = ?"
            params.append(decision)
        
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        return cursor.fetchall()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get ledger statistics"""
        cursor = self.conn.cursor()
        
        # Total records
        cursor.execute("SELECT COUNT(*) as total FROM audit_logs")
        total = cursor.fetchone()["total"]
        
        # By decision
        cursor.execute("SELECT decision, COUNT(*) as count FROM audit_logs GROUP BY decision")
        by_decision = {row["decision"]: row["count"] for row in cursor.fetchall()}
        
        # By tool
        cursor.execute("SELECT tool_name, COUNT(*) as count FROM audit_logs GROUP BY tool_name")
        by_tool = {row["tool_name"]: row["count"] for row in cursor.fetchall()}
        
        return {
            "total_records": total,
            "by_decision": by_decision,
            "by_tool": by_tool,
            "chain_integrity": self.verify_chain_integrity()
        }
    
    def close(self):
        """Close the database connection"""
        self.conn.close()

# Global ledger instance
_ledger_instance = None

def get_ledger() -> SQLiteLedger:
    """Get the global ledger instance"""
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = SQLiteLedger()
    return _ledger_instance
