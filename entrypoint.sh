#!/bin/bash

# Start your Go app in background
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Patch sshd_config before s6/sshd starts
SSHD_CONFIG="/config/ssh/sshd_config"

# Ensure config dir exists (important on first run)
/bin/mkdir -p /config/ssh

if [ -f "$SSHD_CONFIG" ]; then
    sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' "$SSHD_CONFIG"
    sed -i 's/^#\?GatewayPorts.*/GatewayPorts yes/' "$SSHD_CONFIG"
    sed -i 's/^#\?PermitTunnel.*/PermitTunnel yes/' "$SSHD_CONFIG"

    # If any lines are missing, append them
    grep -q "^AllowTcpForwarding" "$SSHD_CONFIG" || echo "AllowTcpForwarding yes" >> "$SSHD_CONFIG"
    grep -q "^GatewayPorts" "$SSHD_CONFIG" || echo "GatewayPorts yes" >> "$SSHD_CONFIG"
    grep -q "^PermitTunnel" "$SSHD_CONFIG" || echo "PermitTunnel yes" >> "$SSHD_CONFIG"
else
    # Create a minimal config if it doesn't exist
    cat > "$SSHD_CONFIG" <<EOF
Port 2222
AllowTcpForwarding yes
GatewayPorts yes
PermitTunnel yes
EOF
fi

# Finally, hand over to s6-overlay (this will start sshd and others)
exec /init
