#!/bin/sh
# run in foreground so s6 can supervise it
exec /usr/local/bin/itgateway 2>&1
