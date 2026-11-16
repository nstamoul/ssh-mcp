#!/bin/sh
# SSH_ASKPASS helper: answers ssh's password prompt from the environment of
# this one ssh process. The MCP sets MCP_SSH_SECRET only for customer logins.
printf '%s\n' "$MCP_SSH_SECRET"
