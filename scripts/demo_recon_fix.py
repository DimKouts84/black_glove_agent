import sys
import os
import asyncio
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import agent.ui
import agent.cli

# Mock commands to demonstrate functionality
commands = [
    "recon passive --dry-run",
    "exit"
]

async def mock_get_input(*args, **kwargs):
    # Small delay to simulate typing
    await asyncio.sleep(1)
    if commands:
        cmd = commands.pop(0)
        print(f"\n[Mock User] > {cmd}")
        return cmd
    return "exit"

# Patch the async input function
agent.ui.get_user_input_async = mock_get_input

# Run the chat
if __name__ == "__main__":
    print("Starting Interactive Chat Demo for Recon Fix...")
    try:
        # Ensure we are in the right directory for config loading
        os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        agent.cli.chat()
    except SystemExit:
        pass
    except Exception as e:
        print(f"Error: {e}")
