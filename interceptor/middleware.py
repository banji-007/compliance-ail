import json

def intercept_tool_call(tool_name, tool_args):
    """
    Intercept and validate tool calls before execution.
    
    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool
        
    Returns:
        dict: Response with 'status' and 'message' keys
    """
    print(f"\n=== INTERCEPTOR: Checking {tool_name} ===")
    print(f"Tool arguments: {json.dumps(tool_args, indent=2)}")
    
    if tool_name == "provision_cloud_server":
        # Check cost constraint
        cost_per_hour = tool_args.get("cost_per_hour", 0)
        
        if cost_per_hour > 10:
            response = {
                "status": "DENIED",
                "message": f"Budget exceeded: ${cost_per_hour}/hour is greater than $10/hour limit"
            }
        else:
            response = {
                "status": "APPROVED", 
                "message": f"Cost approved: ${cost_per_hour}/hour is within budget"
            }
    else:
        # Default approval for unknown tools
        response = {
            "status": "APPROVED",
            "message": f"Tool {tool_name} approved by default"
        }
    
    print(f"Interceptor decision: {response['status']} - {response['message']}")
    print("=" * 50)
    
    return response
