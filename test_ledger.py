import os
import json
import sys
from openai import OpenAI
from dotenv import load_dotenv

# Add paths for interceptor and ledger
sys.path.append(os.path.join(os.path.dirname(__file__), 'interceptor'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'ledger'))

from middleware import intercept_tool_call
from sqlite_ledger import get_ledger

# Load environment variables
load_dotenv()

class TestLedgerIntegration:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "provision_cloud_server",
                    "description": "Provision a cloud server with specified configuration",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "instance_type": {
                                "type": "string",
                                "description": "The type of cloud instance to provision (e.g., 't3.micro', 't3.small', 'm5.large')"
                            },
                            "region": {
                                "type": "string",
                                "description": "The cloud region where the server should be provisioned (e.g., 'us-east-1', 'us-west-2')"
                            },
                            "cost_per_hour": {
                                "type": "number",
                                "description": "The cost per hour for the instance in USD"
                            }
                        },
                        "required": ["instance_type", "region", "cost_per_hour"]
                    }
                }
            }
        ]
    
    def test_interceptor_logging(self):
        """Test that interceptor logs to ledger correctly"""
        print("\n" + "="*80)
        print("TESTING LEDGER INTEGRATION")
        print("="*80)
        
        # Test 1: Approved request
        print("\n1. Testing approved request ($5/hr)")
        approved_args = {
            "instance_type": "t3.micro",
            "region": "us-east-1", 
            "cost_per_hour": 5
        }
        
        response = intercept_tool_call("provision_cloud_server", approved_args, "test_agent")
        print(f"Response: {response}")
        
        # Test 2: Denied request
        print("\n2. Testing denied request ($50/hr)")
        denied_args = {
            "instance_type": "p4d.24xlarge",
            "region": "us-east-1",
            "cost_per_hour": 50
        }
        
        response = intercept_tool_call("provision_cloud_server", denied_args, "test_agent")
        print(f"Response: {response}")
        
        # Test 3: Another approved request
        print("\n3. Testing another approved request ($8/hr)")
        another_approved = {
            "instance_type": "t3.small",
            "region": "us-west-2",
            "cost_per_hour": 8
        }
        
        response = intercept_tool_call("provision_cloud_server", another_approved, "test_agent")
        print(f"Response: {response}")
    
    def test_ledger_functions(self):
        """Test ledger functions"""
        print("\n" + "="*80)
        print("TESTING LEDGER FUNCTIONS")
        print("="*80)
        
        ledger = get_ledger()
        
        # Print full ledger
        print("\n--- FULL LEDGER ---")
        ledger.print_ledger()
        
        # Test statistics
        print("\n--- LEDGER STATISTICS ---")
        stats = ledger.get_statistics()
        print(json.dumps(stats, indent=2))
        
        # Test search
        print("\n--- SEARCH RESULTS ---")
        denied_records = ledger.search_records(decision="DENIED")
        print(f"Found {len(denied_records)} denied records")
        
        approved_records = ledger.search_records(decision="APPROVED")
        print(f"Found {len(approved_records)} approved records")
        
        # Test chain integrity
        print("\n--- CHAIN INTEGRITY ---")
        is_valid = ledger.verify_chain_integrity()
        print(f"Chain integrity: {'VALID' if is_valid else 'INVALID'}")
    
    def test_full_agent_flow(self):
        """Test the full agent flow with ledger integration"""
        print("\n" + "="*80)
        print("TESTING FULL AGENT FLOW")
        print("="*80)
        
        # Import the updated BaseAgent
        sys.path.append(os.path.join(os.path.dirname(__file__), 'agent'))
        from base_agent import BaseAgent
        
        agent = BaseAgent("test_ledger_agent")
        
        # Test prompt that should be approved
        print("\n--- Testing approved request ---")
        messages = [{"role": "user", "content": "Spin up an AWS t3.micro in us-east-1 for $5/hour."}]
        
        response = agent.client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            tools=agent.tools,
            tool_choice="auto"
        )
        
        if response.choices[0].message.tool_calls:
            agent.handle_tool_calls(response.choices[0].message.tool_calls)
        
        # Test prompt that should be denied
        print("\n--- Testing denied request ---")
        messages = [{"role": "user", "content": "Spin up an AWS p4d.24xlarge in us-east-1 for $50/hour."}]
        
        response = agent.client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            tools=agent.tools,
            tool_choice="auto"
        )
        
        if response.choices[0].message.tool_calls:
            agent.handle_tool_calls(response.choices[0].message.tool_calls)

if __name__ == "__main__":
    tester = TestLedgerIntegration()
    
    # Run tests
    tester.test_interceptor_logging()
    tester.test_ledger_functions()
    tester.test_full_agent_flow()
    
    # Show final ledger state
    print("\n" + "="*80)
    print("FINAL LEDGER STATE")
    print("="*80)
    ledger = get_ledger()
    ledger.print_ledger()
