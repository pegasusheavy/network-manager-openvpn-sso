#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Pegasus Heavy Industries LLC
#
# Install script for nm-openvpn-sso NetworkManager plugin

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Detect installation prefix
PREFIX="${PREFIX:-/usr}"
LIBDIR="${LIBDIR:-$PREFIX/lib}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"

# Paths
NM_VPN_DIR="$SYSCONFDIR/NetworkManager/VPN"
NM_LIB_DIR="$LIBDIR/NetworkManager"
DBUS_SYSTEM_SERVICES="$PREFIX/share/dbus-1/system-services"
DBUS_SYSTEM_CONF="$SYSCONFDIR/dbus-1/system.d"
SYSTEMD_SYSTEM_DIR="$LIBDIR/systemd/system"

# Build the project
info "Building nm-openvpn-sso..."
if command -v cargo &> /dev/null; then
    cargo build --release
else
    error "Cargo not found. Please install Rust: https://rustup.rs/"
fi

BINARY="target/release/nm-openvpn-sso-service"
if [[ ! -f "$BINARY" ]]; then
    error "Build failed - binary not found"
fi

# Create directories
info "Creating directories..."
mkdir -p "$NM_VPN_DIR"
mkdir -p "$NM_LIB_DIR"
mkdir -p "$DBUS_SYSTEM_SERVICES"
mkdir -p "$DBUS_SYSTEM_CONF"
mkdir -p "$SYSTEMD_SYSTEM_DIR"

# Install binary
info "Installing binary to $NM_LIB_DIR..."
install -m 755 "$BINARY" "$NM_LIB_DIR/nm-openvpn-sso-service"

# Install NetworkManager plugin file
info "Installing NetworkManager plugin configuration..."
install -m 644 data/nm-openvpn-sso-service.name "$NM_VPN_DIR/"

# Install D-Bus service file
info "Installing D-Bus service file..."
install -m 644 data/org.freedesktop.NetworkManager.openvpn-sso.service "$DBUS_SYSTEM_SERVICES/"

# Install D-Bus policy
info "Installing D-Bus policy..."
install -m 644 data/org.freedesktop.NetworkManager.openvpn-sso.conf "$DBUS_SYSTEM_CONF/"

# Install systemd service
info "Installing systemd service..."
install -m 644 data/nm-openvpn-sso.service "$SYSTEMD_SYSTEM_DIR/"

# Reload daemons
info "Reloading system daemons..."
systemctl daemon-reload
dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true

# Restart NetworkManager to pick up the new plugin
info "Restarting NetworkManager..."
systemctl restart NetworkManager

info "Installation complete!"
echo ""
echo "The OpenVPN SSO plugin is now available in NetworkManager."
echo "You can create a new VPN connection using:"
echo ""
echo "  nmcli connection add type vpn vpn-type openvpn-sso con-name \"My VPN\" \\"
echo "    vpn.data \"config=/path/to/your.ovpn\""
echo ""
echo "Or use the NetworkManager GUI and select 'OpenVPN SSO' as the VPN type."
