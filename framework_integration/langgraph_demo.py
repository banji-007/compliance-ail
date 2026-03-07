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

@tool
def provision_cloud_server(instance_type: str, region: str, cost_per_hour: float) -> str:
    """Provision a cloud server with the given instance type, region, and hourly cost."""
    args = {
        "instance_type": instance_type,
        "region": region,
        "cost_per_hour": cost_per_hour,
    }

    decision = intercept_tool_call("provision_cloud_server", args, agent_id="langgraph_agent")

    record_hash = decision.get("record_hash", "")[:16]
    pipeline_prefix = (
        f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] "
        f"-> [Ledger Hash] {record_hash}..."
    )

    if decision["status"] == "APPROVED":
        result = (
            f"Cloud server provisioned: {instance_type} in {region} "
            f"at ${cost_per_hour}/hour"
        )
        print(f"{pipeline_prefix} -> [Execution] {result}")
    else:
        result = f"BLOCKED by AIL: {decision['message']}"
        print(f"{pipeline_prefix} -> [Block] {decision['message']}")

    return result

# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

llm = ChatOpenAI(model="gpt-4o", temperature=0).bind_tools([provision_cloud_server])

def agent_node(state: AgentState) -> AgentState:
    response = llm.invoke(state["messages"])
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
    # Should be APPROVED (OPA would allow; OPA unavailable → fail-closed DENIED)
    run("Provision a t3.micro instance in us-east-1 for $5/hour.")

    # Should be DENIED (cost exceeds policy threshold)
    run("Provision a p4d.24xlarge instance in us-east-1 for $50/hour.")

    # Show ledger tail
    print("\n" + "=" * 70)
    print("LEDGER (last 2 records)")
    print("=" * 70)
    get_ledger().print_ledger(limit=2)
