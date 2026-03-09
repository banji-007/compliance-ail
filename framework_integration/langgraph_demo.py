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

from middleware import intercept_tool_call

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

class ComplianceAgent:
    def __init__(self, model="gpt-4", tools=None, system_prompt=None):
        """Initialize the compliance agent with system prompt and tools."""
        if system_prompt is None:
            # Default coaching prompt for policy compliance
            system_prompt = """You are a helpful cloud infrastructure assistant. 

If a tool returns a DENIED message with policy violations, you must read the violations, explain them to the user, and ask for missing information to try again. Common violations include:
- Missing cost_center tag for production environments
- Restricted instance types without proper project=ml-training tag  
- PCI-DSS data in wrong region (must be eu-central-1)

Always help users comply with policy rather than bypassing it."""
        
        self.client = ChatOpenAI(model=model, temperature=0).bind_tools(tools or [])
        self.graph = create_react_agent(self.client, system_prompt=system_prompt)

# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

class ServerProvisionInput(BaseModel):
    """Input schema for cloud server provisioning."""
    instance_type: str = Field(..., description="The cloud instance type (e.g., 't3.micro', 'p4d.24xlarge')")
    region: str = Field(..., description="The cloud region where the server should be provisioned (e.g., 'us-east-1', 'eu-central-1')")
    cost_per_hour: float = Field(..., description="The hourly cost in USD for the instance")
    environment: str = Field(..., description="Deployment environment extracted from user prompt (e.g., 'prod', 'dev', 'staging')")
    project: str = Field(default="unspecified", description="Project name extracted from user prompt (e.g., 'ml-training', 'webapp'). Use 'unspecified' if not mentioned.")
    data_classification: str = Field(default="unspecified", description="Data classification extracted from user prompt (e.g., 'pci-dss', 'internal', 'public'). Use 'unspecified' if not mentioned.")
    cost_center: str = Field(default="", description="Cost center extracted from user prompt. Leave empty string if not mentioned — the policy engine will enforce it.")
    encryption_at_rest: bool = Field(default=False, description="Whether encryption at rest is enabled. Required for SOC2 compliance in production environments. Set to True when the user mentions encryption, compliance, or SOC2.")

def execute_provision_cloud_server(instance_type: str, region: str, cost_per_hour: float, tags: dict) -> str:
    """Dummy function that simulates cloud server provisioning."""
    return (
        f"Cloud server provisioned: {instance_type} in {region} at ${cost_per_hour}/hour "
        f"[env: {tags.get('environment','unknown')}, cost_center: {tags.get('cost_center','unknown')}, "
        f"project: {tags.get('project','unknown')}]"
    )

# ---------------------------------------------------------------------------
# LangGraph Execution Block
# ---------------------------------------------------------------------------

@tool(args_schema=ServerProvisionInput)
def provision_cloud_server(
    instance_type: str,
    region: str,
    cost_per_hour: float,
    environment: str,
    project: str = "unspecified",
    data_classification: str = "unspecified",
    cost_center: str = "",
    encryption_at_rest: bool = False,
) -> str:
    """Provision a cloud server. Extract all tag values from the user prompt and pass them as explicit arguments.

    Tags guide policy enforcement:
    - environment: deployment tier ('prod', 'dev', 'staging')
    - project: project name ('ml-training', 'webapp', etc.)
    - data_classification: data sensitivity ('pci-dss', 'internal', 'public')
    - cost_center: required for production environments
    - encryption_at_rest: set True for SOC2-compliant prod deployments
    """
    print('\n>>> [DEBUG] TOOL INVOKED BY LLM <<<')

    tags = {
        "environment": environment,
        "project": project,
        "data_classification": data_classification,
        "cost_center": cost_center,
        "encryption_at_rest": str(encryption_at_rest).lower(),
    }

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
        result = (
            f"BLOCKED by AIL: {decision['message']}\n"
            f"Original parameters: instance_type={instance_type}, region={region}, "
            f"cost_per_hour={cost_per_hour}, environment={environment}, "
            f"project={project}, data_classification={data_classification}, "
            f"cost_center={cost_center!r}, encryption_at_rest={encryption_at_rest}. "
            f"Retry the tool with these exact parameters corrected as instructed."
        )
        print(f"{pipeline_prefix} -> [Block] {decision['message']}")

    return result

# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

# Initialize LLM with strict execution system message
system_message = """You are an execution agent. You must execute the provision_cloud_server tool immediately using the exact instance_type, region, and cost the user specified. Do not substitute a different instance type or region unless the user explicitly asks you to change them. When the user says to fix a denied request, apply only the corrections they state and keep all other parameters the same. Extract all tags the user mentions (environment, project, data_classification, cost_center, encryption_at_rest) and pass them as explicit arguments. For SOC2-compliant or production deployments, set encryption_at_rest=True unless the user explicitly says not to."""

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

    # Persistent conversation history across turns
    conversation_messages = []

    while True:
        try:
            user_input = input("\nUSER: ").strip()

            if user_input.lower() in ['quit', 'exit']:
                print("Goodbye!")
                break

            if user_input.lower() == 'demo':
                # Run predefined test cases (stateless, each is self-contained)
                print("\n" + "=" * 70)
                print("DEMO: Running test cases")
                print("=" * 70)

                # Should be APPROVED (OPA would allow; OPA unavailable → fail-closed DENIED)
                run("Provision a t3.micro instance in us-east-1 for $5/hour with tags: environment='prod', cost_center='engineering', project='webapp'.")

                # Should be DENIED (p4d.24xlarge requires project='ml-training' but has 'model-training')
                run("Provision a p4d.24xlarge instance in us-east-1 for $50/hour with tags: environment='prod', cost_center='ml-research', project='model-training'.")

                # Test complex policy scenario with dev environment
                run("Provision a t3.small instance in us-west-2 for $8/hour with tags: environment='dev', cost_center='testing', project='cicd'.")

                # Show ledger notice
                print("\n" + "=" * 70)
                print("LEDGER NOTICE")
                print("=" * 70)
                print("All intercepts are logged to ImmuDB cryptographic ledger.")
                print("ImmuDB is the source of truth for audit records.")
                print("Use ImmuDB client tools to query the audit trail.")
                continue

            if not user_input:
                continue

            # Process user input through LangGraph, carrying conversation history
            print("\n" + "=" * 70)
            print(f"USER: {user_input}")
            print("=" * 70)
            conversation_messages.append(HumanMessage(content=user_input))
            result = graph.invoke({"messages": conversation_messages})
            # Replace history with the full updated message list from the graph
            conversation_messages = result["messages"]
            final = conversation_messages[-1].content
            print(f"\nAGENT: {final}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")
