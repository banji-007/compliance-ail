import json
import hashlib
import time
import logging
import os
from datetime import datetime
from immudb import ImmudbClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ImmuDBLedger:
    """
    Enterprise-grade cryptographic ledger using ImmuDB for true Merkle-tree immutability.
    """
    
    def __init__(self, host=None, port=None, user=None, password=None, database='defaultdb'):
        """
        Initialize ImmuDB connection.
        
        Args:
            host (str): ImmuDB server host
            port (int): ImmuDB server port
            user (str): ImmuDB username
            password (str): ImmuDB password
            database (str): Database name
        """
        self.host = host or os.getenv('IMMUDB_HOST', 'localhost')
        self.port = int(port or os.getenv('IMMUDB_PORT', 3322))
        self.user = user
        self.password = password
        self.database = database
        self.client = None
        
        # Strict credential validation - no fallbacks for production
        if self.user is None or self.password is None:
            raise ValueError('Critical: ImmuDB credentials missing from environment.')
        
        self._connect()
    
    def _connect(self):
        """Establish connection to ImmuDB server."""
        try:
            self.client = ImmudbClient(f"{self.host}:{self.port}")
            self.client.login(self.user, self.password, self.database)
            logging.info(f"Connected to ImmuDB at {self.host}:{self.port}")
        except Exception as e:
            logging.error(f"ImmuDB connection failed: {e}")
            raise
    
    def log_tool_call(self, agent_id, tool_name, payload, decision):
        """
        Log intercepted tool call to ImmuDB using verifiedSet for cryptographic immutability.
        
        Args:
            agent_id (str): ID of the agent making the tool call
            tool_name (str): Name of the tool being called
            payload (dict): Tool arguments/payload
            decision (str): OPA policy decision (APPROVED/DENIED with reason)
        
        Returns:
            str: Transaction hash for verification
        """
        timestamp = datetime.utcnow().isoformat()
        
        # Create the log entry
        log_entry = {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "tool_name": tool_name,
            "payload": payload,
            "decision": decision
        }
        
        # Serialize to JSON string
        serialized_entry = json.dumps(log_entry, separators=(',', ':'))
        
        # Create unique key using timestamp and tool name
        key = f"tool_call:{agent_id}:{int(time.time())}:{tool_name}"
        
        try:
            # Use verifiedSet for cryptographic anchoring to Merkle tree
            result = self.client.verifiedSet(key.encode(), serialized_entry.encode())
            
            transaction_hash = hashlib.sha256(f"{key}:{serialized_entry}:{result.id}".encode()).hexdigest()
            logging.info(f"Logged tool call with verifiedSet - TX: {result.id} Hash: {transaction_hash}")
            
            return transaction_hash
            
        except Exception as e:
            logging.error(f"Failed to log tool call: {e}")
            raise
    
    def get_previous_hash(self):
        """
        Get a reference to the latest transaction for hash chaining.
        
        Returns:
            str: Reference hash of the latest transaction
        """
        try:
            # Get the current database state
            state = self.client.currentState()
            # Use the database state hash as our reference
            return f"db:{state.db}:{state.txId}"
        except Exception as e:
            logging.error(f"Failed to get current ImmuDB state: {e}")
            return "unknown"

# Strict enforcement: System fails closed if credentials are missing.

# Global ledger instance
_ledger_instance = None

def get_ledger():
    """
    Get singleton instance of the ImmuDB ledger.
    
    Returns:
        ImmuDBLedger: The ledger instance
    """
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = ImmuDBLedger()
    return _ledger_instance
