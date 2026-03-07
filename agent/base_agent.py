import os
import json
import sys
from openai import OpenAI
from dotenv import load_dotenv

# Add the interceptor directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'interceptor'))
from middleware import intercept_tool_call

# Load environment variables
load_dotenv()

class BaseAgent:
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
        self.messages = []
    
    def provision_cloud_server(self, instance_type, region, cost_per_hour):
        """Tool function for provisioning cloud servers"""
        tool_call = {
            "tool_name": "provision_cloud_server",
            "parameters": {
                "instance_type": instance_type,
                "region": region,
                "cost_per_hour": cost_per_hour
            }
        }
        print("\n=== TOOL CALL ===")
        print(json.dumps(tool_call, indent=2))
        print("==================\n")
        return f"Cloud server provisioning initiated for {instance_type} in {region} at ${cost_per_hour}/hour"
    
    def handle_tool_calls(self, tool_calls):
        """Handle tool calls from the assistant with interceptor middleware"""
        tool_results = []
        for tool_call in tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)
            
            # Pass tool call through interceptor
            interceptor_response = intercept_tool_call(function_name, function_args)
            
            if function_name == "provision_cloud_server":
                if interceptor_response["status"] == "APPROVED":
                    result = self.provision_cloud_server(
                        instance_type=function_args["instance_type"],
                        region=function_args["region"],
                        cost_per_hour=function_args["cost_per_hour"]
                    )
                    # Add interceptor approval info
                    result += f"\n[Interceptor: {interceptor_response['message']}]"
                else:
                    # Tool call was denied
                    result = f"Action blocked by interceptor: {interceptor_response['message']}"
                    
                tool_results.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": result
                })
            else:
                result = f"Unknown tool: {function_name}"
                tool_results.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": function_name,
                    "content": result
                })
        
        return tool_results
    
    def chat_loop(self):
        """Main chat loop"""
        print("Base Agent Chat Interface")
        print("Type 'quit' or 'exit' to end the conversation")
        print("=" * 50)
        
        while True:
            try:
                # Get user input
                user_input = input("\nYou: ").strip()
                
                if user_input.lower() in ['quit', 'exit']:
                    print("Goodbye!")
                    break
                
                if not user_input:
                    continue
                
                # Add user message to conversation
                self.messages.append({"role": "user", "content": user_input})
                
                # Make API call
                response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=self.messages,
                    tools=self.tools,
                    tool_choice="auto"
                )
                
                assistant_message = response.choices[0].message
                self.messages.append(assistant_message)
                
                # Check if assistant wants to use tools
                if assistant_message.tool_calls:
                    # Handle tool calls with interceptor
                    tool_results = self.handle_tool_calls(assistant_message.tool_calls)
                    
                    # Send tool results back to assistant
                    self.messages.extend(tool_results)
                    
                    # Get final response
                    final_response = self.client.chat.completions.create(
                        model="gpt-4",
                        messages=self.messages
                    )
                    
                    final_message = final_response.choices[0].message
                    self.messages.append(final_message)
                    print(f"\nAssistant: {final_message.content}")
                else:
                    # Regular response without tools
                    print(f"\nAssistant: {assistant_message.content}")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")

if __name__ == "__main__":
    agent = BaseAgent()
    agent.chat_loop()
