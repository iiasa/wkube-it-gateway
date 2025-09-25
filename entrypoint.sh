#!/bin/bash
set -e

# Start your Go app in background
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Inject/patch SSHD config before /init runs
SSHD_CONFIG="/config/sshd/sshd_config"

# Ensure directory exists
mkdir -p /config/sshd

# Append/override config parameters (idempotent)
add_config() {
  key="$1"
  value="$2"
  if grep -qE "^[# ]*${key}" "$SSHD_CONFIG" 2>/dev/null; then
    sed -i "s|^[# ]*${key}.*|${key} ${value}|" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

add_config "Port" "2222"
add_config "AllowTcpForwarding" "yes"
add_config "GatewayPorts" "yes"
add_config "PermitTunnel" "yes"
add_config "PasswordAuthentication" "no"
add_config "PermitRootLogin" "no"
add_config "Subsystem" "sftp /usr/lib/openssh/sftp-server"

# Hand off to container's init system (will start sshd)
/init
