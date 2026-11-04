#!/usr/bin/env bash
set -euo pipefail
systemctl is-active --quiet haproxy
/usr/sbin/haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
