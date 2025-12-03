
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to path
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.agent.chat_handler import ChatHandler, ToolCall
from src.agent.llm_client import LLMResponse, LLMMessage
from src.adapters.interface import AdapterResult, AdapterResultStatus

def test_chat_handler_logic():
    print("=== Testing ChatHandler Logic ===")
    
    # Mock dependencies
    mock_llm = MagicMock()
    mock_plugin_manager = MagicMock()
    mock_console = MagicMock()
    
    # Setup mock plugin manager
    mock_plugin_manager.discover_adapters.return_value = ["public_ip", "nmap"]
    mock_plugin_manager.get_adapter_info.side_effect = lambda name: {
        "description": f"Test description for {name}",
        "parameters": {},
        "safe_mode": True
    }
    
    # Initialize handler
    handler = ChatHandler(mock_llm, mock_plugin_manager, mock_console)
    print("✓ ChatHandler initialized")
    
    # Test 1: Tool Call Extraction
    print("\n--- Test 1: Tool Call Extraction ---")
    llm_response_text = """
    I will check your public IP address.
    ```json
    {
        "action": "execute_tool",
        "tool": "public_ip",
        "parameters": {},
        "rationale": "User requested IP check"
    }
    ```
    """
    tool_calls = handler.extract_tool_calls(llm_response_text)
    
    if len(tool_calls) == 1 and tool_calls[0].tool_name == "public_ip":
        print(f"✓ Tool call extracted successfully: {tool_calls[0]}")
    else:
        print(f"✗ Failed to extract tool call: {tool_calls}")
        return False

    # Test 2: Tool Execution
    print("\n--- Test 2: Tool Execution ---")
    mock_result = AdapterResult(
        status=AdapterResultStatus.SUCCESS,
        data={"ipv4": "1.2.3.4"},
        metadata={}
    )
    mock_plugin_manager.run_adapter.return_value = mock_result
    
    result = handler.execute_tool_call(tool_calls[0])
    
    if result.status == AdapterResultStatus.SUCCESS and result.data["ipv4"] == "1.2.3.4":
        print("✓ Tool executed successfully")
    else:
        print("✗ Tool execution failed")
        return False
        
    # Test 3: Result Formatting
    print("\n--- Test 3: Result Formatting ---")
    formatted = handler.format_tool_result("public_ip", result)
    print(f"Formatted result:\n{formatted}")
    if "1.2.3.4" in formatted:
        print("✓ Result formatted correctly")
    else:
        print("✗ Result formatting failed")
        return False

    # Test 4: Process Message Flow
    print("\n--- Test 4: Process Message Flow ---")
    mock_llm.generate.return_value = LLMResponse(
        content=llm_response_text,
        model="test-model",
        usage={}
    )
    
    response_text, calls = handler.process_message("What is my IP?")
    
    if "I will check your public IP" in response_text and len(calls) == 1:
        print("✓ Message processed correctly")
    else:
        print("✗ Message processing failed")
        return False
        
    print("\n=== All Tests Passed ===")
    return True

if __name__ == "__main__":
    try:
        success = test_chat_handler_logic()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
