#!/bin/bash
set -e

SSHD_CONFIG="/etc/ssh/sshd_config"

# Enable GatewayPorts
sed -i 's/^#GatewayPorts .*/GatewayPorts yes/' "$SSHD_CONFIG"
grep -q '^GatewayPorts' "$SSHD_CONFIG" || echo "GatewayPorts yes" >> "$SSHD_CONFIG"

# Start your Go app in background
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Start sshd (via original init)
exec /init
