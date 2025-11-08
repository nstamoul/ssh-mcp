#!/bin/bash
# Start the MCP SSH HTTP server in silent mode (no debug output)

export DEBUG=false
node server-http.mjs
