#!/bin/sh
# /etc/cont-init.d/10-sshd-config

SSHD_CONFIG="/config/sshd/sshd_config"

# Ensure config file exists
mkdir -p /config/sshd
touch "$SSHD_CONFIG"

add_config() {
  key="$1"
  value="$2"
  if grep -qE "^[# ]*${key}" "$SSHD_CONFIG" 2>/dev/null; then
    sed -i "s|^[# ]*${key}.*|${key} ${value}|" "$SSHD_CONFIG"
  else
    echo "${key} ${value}" >> "$SSHD_CONFIG"
  fi
}

# Apply your customizations
add_config "Port" "2222"
add_config "AllowTcpForwarding" "yes"
add_config "GatewayPorts" "yes"
add_config "PermitTunnel" "yes"
add_config "PasswordAuthentication" "no"
add_config "PermitRootLogin" "no"
add_config "Subsystem" "sftp /usr/lib/openssh/sftp-server"
