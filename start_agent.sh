#!/bin/bash
# Start LOOM weft-intel-bridge agent as MCP server
cd /mnt/workspace/projects/loom
source venv/bin/activate
echo "Starting LOOM weft-intel-bridge on port 8200..."
exec loom run agents/weft-intel-bridge.yaml --port 8200
