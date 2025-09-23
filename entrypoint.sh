#!/bin/bash

# Start your Go app in background
/usr/local/bin/itgateway >> /proc/1/fd/1 2>&1 &

# Start sshd (via original init)
exec /init
