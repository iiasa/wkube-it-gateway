#!/bin/bash
set -e

SSHD_CONFIG="/etc/ssh/sshd_config"
sed -i 's/^#GatewayPorts .*/GatewayPorts yes/' "$SSHD_CONFIG"
grep -q '^GatewayPorts' "$SSHD_CONFIG" || echo "GatewayPorts yes" >> "$SSHD_CONFIG"

# Start Go app in background, redirect logs to stdout
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Start init system in foreground (sshd etc.)
exec /init