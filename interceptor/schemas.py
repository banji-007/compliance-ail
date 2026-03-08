"""
Pydantic schemas for pre-flight input validation in Epic 2.
"""

from typing import Dict, Optional
from pydantic import BaseModel, Field, ValidationError


class CloudServerProvisionSchema(BaseModel):
    """
    Strict schema for cloud server provisioning tool arguments.
    Catches LLM hallucinations before they reach OPA.
    """
    instance_type: str = Field(..., description="EC2 instance type (e.g., 'p4d.24xlarge')")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    cost_per_hour: float = Field(..., gt=0, description="Hourly cost in USD (must be positive)")
    tags: Dict[str, str] = Field(..., description="Dictionary of tags with string keys and values")
    
    class Config:
        # Extra fields forbidden to catch hallucinated parameters
        extra = "forbid"
        # Validate assignment to catch issues during instantiation
        validate_assignment = True
        # Use enum values for better error messages
        use_enum_values = True


def validate_cloud_server_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    """
    Validate tool arguments against CloudServerProvisionSchema.
    
    Args:
        tool_args: Dictionary of arguments to validate
        
    Returns:
        tuple[bool, Optional[str]]: (is_valid, error_message)
        If is_valid is True, error_message is None
        If is_valid is False, error_message contains the validation error
    """
    try:
        CloudServerProvisionSchema(**tool_args)
        return True, None
    except ValidationError as e:
        # Format the error for LLM consumption
        error_details = []
        for error in e.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            msg = error["msg"]
            error_details.append(f"{loc}: {msg}")
        
        formatted_error = "; ".join(error_details)
        return False, formatted_error
