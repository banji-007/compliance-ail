import os
import json
import sys
import pytest
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

pytestmark = pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; live LLM tests skipped",
)


class TestAgent:
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

    def test_prompt(self, prompt):
        """Test a single prompt"""
        print(f"Testing prompt: '{prompt}'")
        print("=" * 50)

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
                for tool_call in assistant_message.tool_calls:
                    function_name = tool_call.function.name
                    function_args = json.loads(tool_call.function.arguments)

                    if function_name == "provision_cloud_server":
                        result = self.provision_cloud_server(
                            instance_type=function_args["instance_type"],
                            region=function_args["region"],
                            cost_per_hour=function_args["cost_per_hour"]
                        )
                        print(f"Tool result: {result}")

                        # Send tool result back to get final response
                        messages.append(assistant_message)
                        messages.append({
                            "tool_call_id": tool_call.id,
                            "role": "tool",
                            "name": function_name,
                            "content": result
                        })

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
    agent = TestAgent()
    test_prompt = "Spin up an AWS p4d.24xlarge in us-east-1 for $32/hour."
    agent.test_prompt(test_prompt)
