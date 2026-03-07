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
    def __init__(self, agent_id="base_agent"):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.agent_id = agent_id
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
        return f"Cloud server provisioning initiated for {instance_type} in {region} at ${cost_per_hour}/hour"

    def handle_tool_calls(self, tool_calls):
        """Handle tool calls from the assistant with interceptor middleware"""
        tool_results = []
        for tool_call in tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)

            print(f"[Agent Request] {function_name} | agent={self.agent_id} | args={json.dumps(function_args)}")

            interceptor_response = intercept_tool_call(function_name, function_args, self.agent_id)
            record_hash = interceptor_response.get("record_hash", "")[:16]
            pipeline_prefix = f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] -> [Ledger Hash] {record_hash}..."

            if function_name == "provision_cloud_server":
                if interceptor_response["status"] == "APPROVED":
                    result = self.provision_cloud_server(
                        instance_type=function_args["instance_type"],
                        region=function_args["region"],
                        cost_per_hour=function_args["cost_per_hour"]
                    )
                    print(f"{pipeline_prefix} -> [Execution] {result}")
                    result += f"\n[Interceptor: {interceptor_response['message']}]"
                else:
                    result = f"Action blocked by interceptor: {interceptor_response['message']}"
                    print(f"{pipeline_prefix} -> [Block] {interceptor_response['message']}")
            else:
                result = f"Unknown tool: {function_name}"
                print(f"{pipeline_prefix} -> [Block] Unknown tool: {function_name}")

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
                user_input = input("\nYou: ").strip()

                if user_input.lower() in ['quit', 'exit']:
                    print("Goodbye!")
                    break

                if not user_input:
                    continue

                self.messages.append({"role": "user", "content": user_input})

                response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=self.messages,
                    tools=self.tools,
                    tool_choice="auto"
                )

                assistant_message = response.choices[0].message
                self.messages.append(assistant_message)

                if assistant_message.tool_calls:
                    tool_results = self.handle_tool_calls(assistant_message.tool_calls)
                    self.messages.extend(tool_results)

                    final_response = self.client.chat.completions.create(
                        model="gpt-4",
                        messages=self.messages
                    )

                    final_message = final_response.choices[0].message
                    self.messages.append(final_message)
                    print(f"\nAssistant: {final_message.content}")
                else:
                    print(f"\nAssistant: {assistant_message.content}")

            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")

if __name__ == "__main__":
    agent = BaseAgent()
    agent.chat_loop()
