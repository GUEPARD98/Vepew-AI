#!/usr/bin/env python3
"""
VPEW-AI Agent Runner
Alternative entry point to avoid RuntimeWarning
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the agent
from vpew_ai.sensor.agent import VPEWAgent

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_agent.py <config_path>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    
    try:
        agent = VPEWAgent(config_path)
        agent.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        agent.stop()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
