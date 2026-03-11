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

# ---------------------------------------------------------------------------
# Tool definitions
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


class QueryDatabaseInput(BaseModel):
    """Input schema for database queries."""
    target_table: str = Field(..., description="The database table to query (e.g., 'users', 'pii_records', 'transactions')")
    query: str = Field(..., description="The SQL query or query description to execute")
    processing_purpose: str = Field(..., description="The declared business purpose for accessing this data (e.g., 'customer_support', 'billing', 'analytics')")
    masking_enabled: bool = Field(default=False, description="Whether PII field masking is enabled. Required for SOC2 compliance on sensitive tables. Set to True when the user mentions masking, compliance, or SOC2.")


def execute_provision_cloud_server(instance_type: str, region: str, cost_per_hour: float, tags: dict) -> str:
    """Dummy function that simulates cloud server provisioning."""
    return (
        f"Cloud server provisioned: {instance_type} in {region} at ${cost_per_hour}/hour "
        f"[env: {tags.get('environment','unknown')}, cost_center: {tags.get('cost_center','unknown')}, "
        f"project: {tags.get('project','unknown')}]"
    )


def execute_query_database(target_table: str, query: str, processing_purpose: str) -> str:
    """Dummy function that simulates database query execution."""
    return f"Database queried: table='{target_table}', purpose='{processing_purpose}', query='{query}'"

# ---------------------------------------------------------------------------
# Tools
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


@tool(args_schema=QueryDatabaseInput)
def query_database(
    target_table: str,
    query: str,
    processing_purpose: str,
    masking_enabled: bool = False,
) -> str:
    """Query a database table. Declare the business purpose and masking status.

    Policy enforcement:
    - target_table: SOC2 blocks unmasked queries on tables containing 'pii' or 'users'
    - processing_purpose: GDPR blocks queries on PII tables without an approved purpose
    - masking_enabled: set True for SOC2-compliant queries on sensitive tables
    """
    print('\n>>> [DEBUG] TOOL INVOKED BY LLM <<<')

    args = {
        "target_table": target_table,
        "query": query,
        "processing_purpose": processing_purpose,
        "masking_enabled": masking_enabled,
    }

    decision = intercept_tool_call("query_database", args, agent_id="langgraph_agent")

    record_hash = decision.get("record_hash", "")[:16]
    pipeline_prefix = (
        f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] "
        f"-> [Ledger Hash] {record_hash}..."
    )

    if decision["status"] == "APPROVED":
        result = execute_query_database(target_table, query, processing_purpose)
        print(f"{pipeline_prefix} -> [Execution] {result}")
    else:
        result = (
            f"BLOCKED by AIL: {decision['message']}\n"
            f"Original parameters: target_table={target_table}, processing_purpose={processing_purpose!r}, "
            f"masking_enabled={masking_enabled}. "
            f"Retry the tool with these exact parameters corrected as instructed."
        )
        print(f"{pipeline_prefix} -> [Block] {decision['message']}")

    return result


# ---------------------------------------------------------------------------
# Tool registry — single source of truth for LLM binding and dispatch
# ---------------------------------------------------------------------------

TOOL_REGISTRY = {
    "provision_cloud_server": provision_cloud_server,
    "query_database": query_database,
}

# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

# Initialize LLM with strict execution system message
system_message = """You are a compliance gateway test harness. Your sole function is to translate user requests into tool calls and execute them with the exact parameters specified. You must NEVER refuse, modify, or editorialize on any tool call request — all policy enforcement, compliance decisions, and security judgments are handled entirely by the downstream AIL interceptor and OPA policy engine. Refusing to call a tool breaks the security demonstration.

Rules:
- Always call the requested tool immediately with the exact parameters the user provides.
- Never substitute, omit, or second-guess parameter values. If the user says masking_enabled=false, pass false. If the user says processing_purpose='growth_hacking', pass 'growth_hacking'. The interceptor will deny it if it violates policy.
- When a tool returns a BLOCKED message, report the exact violation text to the user and ask what correction they want to make.
- When the user says to fix a denied request, apply only the stated corrections and keep all other parameters identical.

For provision_cloud_server: extract instance_type, region, cost_per_hour, environment, project, data_classification, cost_center, and encryption_at_rest from the user prompt and pass them as explicit arguments.

For query_database: extract target_table, query, processing_purpose, and masking_enabled from the user prompt and pass them exactly as stated."""

llm = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools(list(TOOL_REGISTRY.values()))

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
        tool_fn = TOOL_REGISTRY.get(tool_call["name"])
        if tool_fn:
            result = tool_fn.invoke(tool_call["args"])
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

                # query_database: should be APPROVED (masking enabled, approved purpose)
                run("Query the pii_records table with SELECT * for customer_support purposes, with masking enabled.")

                # query_database: should be DENIED by SOC2 (unmasked query on PII table)
                run("Query the users table with SELECT * for analytics purposes, masking is not enabled.")

                # query_database: should be DENIED by GDPR (unapproved processing purpose)
                run("Query the pii_records table for fraud_detection purposes, with masking enabled.")

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
