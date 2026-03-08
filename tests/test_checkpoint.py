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

class TestCheckpointAgent:
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
                            },
                            "tags": {
                                "type": "object",
                                "description": "A dictionary of metadata tags for policy evaluation. Include keys like 'environment', 'project', 'data_classification', and 'cost_center' if mentioned.",
                                "additionalProperties": {
                                    "type": "string"
                                }
                            }
                        },
                        "required": ["instance_type", "region", "cost_per_hour"]
                    }
                }
            }
        ]

    def provision_cloud_server(self, instance_type, region, cost_per_hour, tags=None):
        """Tool function for provisioning cloud servers"""
        if tags is None:
            tags = {}
        tool_call = {
            "tool_name": "provision_cloud_server",
            "parameters": {
                "instance_type": instance_type,
                "region": region,
                "cost_per_hour": cost_per_hour,
                "tags": tags
            }
        }
        print("\n=== TOOL CALL ===")
        print(json.dumps(tool_call, indent=2))
        print("==================\n")
        return f"Cloud server provisioning initiated for {instance_type} in {region} at ${cost_per_hour}/hour with tags: {tags}"

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
                        cost_per_hour=function_args["cost_per_hour"],
                        tags=function_args.get("tags", {})
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

        return tool_results

    def test_prompt(self, prompt):
        """Test a single prompt"""
        print(f"\nTesting prompt: '{prompt}'")
        print("=" * 60)

        messages = [{"role": "user", "content": prompt}]

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=messages,
                tools=self.tools,
                tool_choice="auto"
            )

            assistant_message = response.choices[0].message
            print(f"Assistant: {assistant_message.content}")

            if assistant_message.tool_calls:
                print("\nTool calls detected:")
                tool_results = self.handle_tool_calls(assistant_message.tool_calls)

                # Send tool results back to get final response
                messages.append(assistant_message)
                messages.extend(tool_results)

                final_response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=messages
                )

                final_message = final_response.choices[0].message
                print(f"Final response: {final_message.content}")
            else:
                print("No tool calls made.")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    agent = TestCheckpointAgent()

    # Test 1: Small instance (likely approved based on tags/environment)
    print("\n" + "="*80)
    print("CHECKPOINT TEST 1: Small instance (t3.micro)")
    print("="*80)
    agent.test_prompt("Spin up an AWS t3.micro in us-east-1 for $5/hour.")

    # Test 2: Large instance (may be denied based on instance type restrictions)
    print("\n" + "="*80)
    print("CHECKPOINT TEST 2: Large instance (p4d.24xlarge)")
    print("="*80)
    agent.test_prompt("Spin up an AWS p4d.24xlarge in us-east-1 for $50/hour.")
