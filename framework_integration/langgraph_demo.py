"""
LangGraph + AIL Integration Demo
---------------------------------
Demonstrates that the AIL interceptor is framework-agnostic: the same
middleware that guards the raw OpenAI SDK agent also guards a LangGraph
ReAct agent, with no changes to the policy or ledger layers.

Graph topology:
  user_input -> agent_node -> tool_node -> agent_node (loop)
                                  ^
                                  |
                          AIL interceptor (OPA + ledger)

Run:
    python framework_integration/langgraph_demo.py
"""

import os
import sys
import json
from typing import Annotated
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Add AIL layers to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'interceptor'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ledger'))

from middleware import intercept_tool_call
from sqlite_ledger import get_ledger

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

load_dotenv()

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]

# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

class ServerProvisionInput(BaseModel):
    """Input schema for cloud server provisioning."""
    instance_type: str = Field(..., description="The cloud instance type (e.g., 't3.micro', 'p4d.24xlarge')")
    region: str = Field(..., description="The cloud region where the server should be provisioned (e.g., 'us-east-1', 'eu-central-1')")
    cost_per_hour: float = Field(..., description="The hourly cost in USD for the instance")
    tags: dict = Field(default_factory=dict, description="A dictionary of metadata tags for policy evaluation. You MUST extract the keys 'environment', 'project', and 'data_classification' from the user prompt and populate them inside this dictionary. Do not leave the tags dictionary empty if the user mentions any of these values. Also include 'cost_center' if mentioned.")

def execute_provision_cloud_server(instance_type: str, region: str, cost_per_hour: float, tags: dict = None) -> str:
    """Dummy function that simulates cloud server provisioning."""
    if tags is None:
        tags = {}
    
    env = tags.get('environment', 'unknown')
    center = tags.get('cost_center', 'unknown')
    project = tags.get('project', 'unknown')
    
    return f"Cloud server provisioned: {instance_type} in {region} at ${cost_per_hour}/hour [env: {env}, center: {center}, project: {project}]"

@tool(args_schema=ServerProvisionInput)
def provision_cloud_server(instance_type: str, region: str, cost_per_hour: float, tags: dict = None) -> str:
    """Use this tool immediately to provision a server. You MUST extract the keys 'environment', 'project', and 'data_classification' from the user prompt and populate them inside the tags dictionary. Do not leave the tags dictionary empty if the user mentions them. Do not ask for missing information before calling this tool."""
    print('\n>>> [DEBUG] TOOL INVOKED BY LLM <<<')
    
    args = {
        "instance_type": instance_type,
        "region": region,
        "cost_per_hour": cost_per_hour,
        "tags": tags,
    }

    decision = intercept_tool_call("provision_cloud_server", args, agent_id="langgraph_agent")

    record_hash = decision.get("record_hash", "")[:16]
    pipeline_prefix = (
        f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] "
        f"-> [Ledger Hash] {record_hash}..."
    )

    if decision["status"] == "APPROVED":
        result = execute_provision_cloud_server(instance_type, region, cost_per_hour, tags)
        print(f"{pipeline_prefix} -> [Execution] {result}")
    else:
        result = f"BLOCKED by AIL: {decision['message']}"
        print(f"{pipeline_prefix} -> [Block] {decision['message']}")

    return result

# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

# Initialize LLM with strict execution system message
system_message = """You are an execution agent. You must execute the provision_cloud_server tool immediately. You must carefully extract any tags the user mentions (like environment, project, or data_classification) and put them into the tags dictionary. Do not ask for missing info, just execute with what you have."""

llm = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools([provision_cloud_server])

def agent_node(state: AgentState) -> AgentState:
    # Add system message if not present
    messages = state["messages"]
    if not any(msg.content == system_message for msg in messages if hasattr(msg, 'content')):
        from langchain_core.messages import SystemMessage
        messages = [SystemMessage(content=system_message)] + messages
    
    response = llm.invoke(messages)
    return {"messages": [response]}

def tool_node(state: AgentState) -> AgentState:
    last_message = state["messages"][-1]
    tool_results = []

    for tool_call in last_message.tool_calls:
        if tool_call["name"] == "provision_cloud_server":
            args = tool_call["args"]
            result = provision_cloud_server.invoke(args)
        else:
            result = f"Unknown tool: {tool_call['name']}"

        tool_results.append(
            ToolMessage(content=result, tool_call_id=tool_call["id"])
        )

    return {"messages": tool_results}

def should_continue(state: AgentState) -> str:
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        return "tools"
    return END

# ---------------------------------------------------------------------------
# Build graph
# ---------------------------------------------------------------------------

graph_builder = StateGraph(AgentState)
graph_builder.add_node("agent", agent_node)
graph_builder.add_node("tools", tool_node)

graph_builder.set_entry_point("agent")
graph_builder.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
graph_builder.add_edge("tools", "agent")

graph = graph_builder.compile()

# ---------------------------------------------------------------------------
# Run demo
# ---------------------------------------------------------------------------

def run(prompt: str):
    print("\n" + "=" * 70)
    print(f"USER: {prompt}")
    print("=" * 70)
    result = graph.invoke({"messages": [HumanMessage(content=prompt)]})
    final = result["messages"][-1].content
    print(f"\nAGENT: {final}")

if __name__ == "__main__":
    # Interactive chat loop
    print("LangGraph + AIL Integration Demo")
    print("Type 'quit' or 'exit' to end the conversation")
    print("Type 'demo' to run predefined test cases")
    print("=" * 70)
    
    while True:
        try:
            user_input = input("\nUSER: ").strip()
            
            if user_input.lower() in ['quit', 'exit']:
                print("Goodbye!")
                break
            
            if user_input.lower() == 'demo':
                # Run predefined test cases
                print("\n" + "=" * 70)
                print("DEMO: Running test cases")
                print("=" * 70)
                
                # Should be APPROVED (OPA would allow; OPA unavailable → fail-closed DENIED)
                run("Provision a t3.micro instance in us-east-1 for $5/hour with tags: environment='prod', cost_center='engineering', project='webapp'.")
                
                # Should be DENIED (cost exceeds policy threshold)
                run("Provision a p4d.24xlarge instance in us-east-1 for $50/hour with tags: environment='prod', cost_center='ml-research', project='model-training'.")
                
                # Test complex policy scenario with dev environment
                run("Provision a t3.small instance in us-west-2 for $8/hour with tags: environment='dev', cost_center='testing', project='cicd'.")
                
                # Show ledger tail
                print("\n" + "=" * 70)
                print("LEDGER (last 2 records)")
                print("=" * 70)
                get_ledger().print_ledger(limit=2)
                continue
            
            if not user_input:
                continue
            
            # Process user input through LangGraph
            print("\n" + "=" * 70)
            print(f"USER: {user_input}")
            print("=" * 70)
            result = graph.invoke({"messages": [HumanMessage(content=user_input)]})
            final = result["messages"][-1].content
            print(f"\nAGENT: {final}")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")
