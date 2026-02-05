#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Pegasus Heavy Industries LLC
#
# Uninstall script for nm-openvpn-sso NetworkManager plugin

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

PREFIX="${PREFIX:-/usr}"
LIBDIR="${LIBDIR:-$PREFIX/lib}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"

info "Stopping service..."
systemctl stop nm-openvpn-sso.service 2>/dev/null || true
systemctl disable nm-openvpn-sso.service 2>/dev/null || true

info "Removing files..."
rm -f "$LIBDIR/NetworkManager/nm-openvpn-sso-service"
rm -f "$SYSCONFDIR/NetworkManager/VPN/nm-openvpn-sso-service.name"
rm -f "$PREFIX/share/dbus-1/system-services/org.freedesktop.NetworkManager.openvpn-sso.service"
rm -f "$SYSCONFDIR/dbus-1/system.d/org.freedesktop.NetworkManager.openvpn-sso.conf"
rm -f "$LIBDIR/systemd/system/nm-openvpn-sso.service"

info "Reloading daemons..."
systemctl daemon-reload
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true

info "Restarting NetworkManager..."
systemctl restart NetworkManager

info "Uninstall complete!"
