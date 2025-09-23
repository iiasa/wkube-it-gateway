#!/bin/bash
set -e

SSHD_CONFIG="/etc/ssh/sshd_config"
AUTHORIZED_KEYS_DIR="/config/ssh"
AUTHORIZED_KEYS_FILE="$AUTHORIZED_KEYS_DIR/authorized_keys"

# Ensure .ssh directory exists
mkdir -p "$AUTHORIZED_KEYS_DIR"
chmod 700 "$AUTHORIZED_KEYS_DIR"


if [ -f /ssh-secret/id_ed25519.pub ]; then
  cat /ssh-secret/id_ed25519.pub >> "$AUTHORIZED_KEYS_FILE"
  chmod 600 "$AUTHORIZED_KEYS_FILE"
fi

# Enforce key-only auth (disable password auth if env says so)
if [ "$PASSWORD_ACCESS" = "false" ]; then
  sed -i 's/^#PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
  sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
fi

# Enable GatewayPorts
sed -i 's/^#GatewayPorts .*/GatewayPorts yes/' "$SSHD_CONFIG"
grep -q '^GatewayPorts' "$SSHD_CONFIG" || echo "GatewayPorts yes" >> "$SSHD_CONFIG"

# Start your Go app in background
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Start sshd (via original init)
exec /init
