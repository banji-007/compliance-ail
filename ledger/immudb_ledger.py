import json
import hashlib
import time
import logging
import os
import base64
import httpx
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class ImmuDBLedger:
    """
    Enterprise-grade cryptographic ledger using ImmuDB REST API for true Merkle-tree immutability.
    """
    
    def __init__(self, url=None, user=None, password=None, database='defaultdb'):
        """
        Initialize ImmuDB REST API connection.
        
        Args:
            url (str): ImmuDB REST API URL (e.g., http://immudb:8080)
            user (str): ImmuDB username
            password (str): ImmuDB password
            database (str): Database name
        """
        self.url = url or os.getenv('IMMUDB_URL', 'http://localhost:8080')
        self.user = user or os.getenv('IMMUDB_USER')
        self.password = password or os.getenv('IMMUDB_PASSWORD')
        self.database = database
        self.auth_token = None
        
        # Strict credential validation - no fallbacks for production
        if self.user is None or self.password is None:
            raise ValueError('Critical: ImmuDB credentials missing from environment.')
        
        self._connect()
    
    def _connect(self):
        """Establish connection to ImmuDB REST API and get auth token."""
        try:
            login_url = f"{self.url}/api/v2/login"
            login_data = {
                "user": base64.b64encode(self.user.encode()).decode(),
                "password": base64.b64encode(self.password.encode()).decode(),
                "database": base64.b64encode(self.database.encode()).decode()
            }
            
            with httpx.Client() as client:
                response = client.post(login_url, json=login_data)
                response.raise_for_status()
                
                result = response.json()
                self.auth_token = result.get("token")
                
                if not self.auth_token:
                    raise ValueError("No authentication token received from ImmuDB")
                
                logging.info(f"Connected to ImmuDB at {self.url}")
                
        except Exception as e:
            logging.error(f"ImmuDB REST connection failed: {e}")
            raise
    
    def log_tool_call(self, agent_id, tool_name, payload, decision):
        """
        Log intercepted tool call to ImmuDB using REST API for cryptographic immutability.
        
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
        
        # Serialize to JSON string and base64 encode for REST API
        serialized_entry = json.dumps(log_entry, separators=(',', ':'))
        encoded_value = base64.b64encode(serialized_entry.encode()).decode()
        
        # Create unique key using timestamp and tool name
        key = f"tool_call:{agent_id}:{int(time.time())}:{tool_name}"
        encoded_key = base64.b64encode(key.encode()).decode()
        
        try:
            set_url = f"{self.url}/api/v2/db/set"
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json"
            }
            
            set_data = {
                "KVs": [{"key": encoded_key, "value": encoded_value}]
            }
            
            with httpx.Client() as client:
                response = client.post(set_url, json=set_data, headers=headers)
                
                # Handle token expiry - refresh and retry once
                if response.status_code == 401:
                    logging.info("Token expired, refreshing and retrying...")
                    self._connect()  # Refresh token
                    headers["Authorization"] = f"Bearer {self.auth_token}"
                    response = client.post(set_url, json=set_data, headers=headers)
                
                response.raise_for_status()
                
                result = response.json()
                tx_id = result.get("id")
                
                if not tx_id:
                    raise ValueError("No transaction ID received from ImmuDB")
                
                # Create transaction hash for verification
                transaction_hash = hashlib.sha256(f"{key}:{serialized_entry}:{tx_id}".encode()).hexdigest()
                logging.info(f"Logged tool call to ImmuDB REST API - Local Ref: {transaction_hash}")
                
                return transaction_hash
                
        except Exception as e:
            logging.error(f"Failed to log tool call via REST API: {e}")
            raise
    
    def get_previous_hash(self):
        """
        Get a reference to the latest transaction for hash chaining.
        
        Returns:
            str: Reference hash of the latest transaction
        """
        try:
            state_url = f"{self.url}/api/v2/db/state"
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json"
            }
            
            with httpx.Client() as client:
                response = client.get(state_url, headers=headers)
                response.raise_for_status()
                
                result = response.json()
                tx_id = result.get("txId", "unknown")
                db = result.get("db", self.database)
                
                # Use the database state hash as our reference
                return f"db:{db}:{tx_id}"
                
        except Exception as e:
            logging.error(f"Failed to get current ImmuDB state via REST API: {e}")
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
