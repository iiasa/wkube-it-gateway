#!/bin/bash

# Modify sshd_config (in container: /etc/ssh/sshd_config)
SSHD_CONFIG="/etc/ssh/sshd_config"

# Enable GatewayPorts
sed -i 's/^#GatewayPorts .*/GatewayPorts yes/' "$SSHD_CONFIG"
grep -q '^GatewayPorts' "$SSHD_CONFIG" || echo "GatewayPorts yes" >> "$SSHD_CONFIG"

# Start the original entrypoint script
exec /init