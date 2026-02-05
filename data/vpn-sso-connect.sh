#!/bin/bash
# VPN SSO Connection Helper
# This script helps connect to SSO-enabled VPN connections on KDE and other desktops

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get list of SSO VPN connections
get_sso_connections() {
    local connections=()
    # Get all VPN connections
    while IFS= read -r conn_name; do
        # Check if it's an openvpn-sso connection
        local service_type
        service_type=$(nmcli -t -f vpn.service-type connection show "$conn_name" 2>/dev/null | cut -d: -f2)
        if [[ "$service_type" == "org.freedesktop.NetworkManager.openvpn-sso" ]]; then
            echo "$conn_name"
        fi
    done < <(nmcli -t -f NAME,TYPE connection show | grep ":vpn$" | cut -d: -f1)
}

# Show connection status
show_status() {
    local conn="$1"
    local status=$(nmcli -t -f GENERAL.STATE connection show "$conn" 2>/dev/null | cut -d: -f2)
    if [[ "$status" == "activated" ]]; then
        echo -e "${GREEN}●${NC} $conn (connected)"
    else
        echo -e "${RED}○${NC} $conn (disconnected)"
    fi
}

# Connect to VPN
connect_vpn() {
    local conn="$1"
    echo -e "${YELLOW}Connecting to $conn...${NC}"
    echo "Your browser will open for SSO authentication."
    nmcli connection up "$conn"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Successfully connected to $conn${NC}"
        notify-send "VPN Connected" "Successfully connected to $conn" -i network-vpn 2>/dev/null || true
    else
        echo -e "${RED}Failed to connect to $conn${NC}"
        notify-send "VPN Connection Failed" "Failed to connect to $conn" -i network-error 2>/dev/null || true
    fi
}

# Disconnect from VPN
disconnect_vpn() {
    local conn="$1"
    echo -e "${YELLOW}Disconnecting from $conn...${NC}"
    nmcli connection down "$conn"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Disconnected from $conn${NC}"
        notify-send "VPN Disconnected" "Disconnected from $conn" -i network-offline 2>/dev/null || true
    fi
}

# Toggle connection
toggle_vpn() {
    local conn="$1"
    local status=$(nmcli -t -f GENERAL.STATE connection show "$conn" 2>/dev/null | cut -d: -f2)
    if [[ "$status" == "activated" ]]; then
        disconnect_vpn "$conn"
    else
        connect_vpn "$conn"
    fi
}

# Main menu using kdialog if available, otherwise CLI
main() {
    local connections=($(get_sso_connections))
    
    if [[ ${#connections[@]} -eq 0 ]]; then
        echo -e "${RED}No SSO VPN connections found.${NC}"
        echo "Import a connection with: nmcli connection import type openvpn file your-config.ovpn"
        echo "Then configure it: nmcli connection modify \"name\" vpn.service-type org.freedesktop.NetworkManager.openvpn-sso"
        exit 1
    fi
    
    # If only one connection, toggle it directly
    if [[ ${#connections[@]} -eq 1 ]]; then
        toggle_vpn "${connections[0]}"
        exit 0
    fi
    
    # Try kdialog for KDE, fall back to CLI
    if command -v kdialog &> /dev/null && [[ -n "$DISPLAY" || -n "$WAYLAND_DISPLAY" ]]; then
        # Build menu items
        local items=""
        for conn in "${connections[@]}"; do
            local status=$(nmcli -t -f GENERAL.STATE connection show "$conn" 2>/dev/null | cut -d: -f2)
            if [[ "$status" == "activated" ]]; then
                items="$items $conn \"● Connected - Click to disconnect\""
            else
                items="$items $conn \"○ Disconnected - Click to connect\""
            fi
        done
        
        local selected=$(eval kdialog --menu \"Select VPN Connection\" $items 2>/dev/null)
        if [[ -n "$selected" ]]; then
            toggle_vpn "$selected"
        fi
    else
        # CLI fallback
        echo "SSO VPN Connections:"
        echo "===================="
        local i=1
        for conn in "${connections[@]}"; do
            echo -n "  $i) "
            show_status "$conn"
            ((i++))
        done
        echo ""
        read -p "Enter number to toggle (or 'q' to quit): " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#connections[@]} ]]; then
            toggle_vpn "${connections[$((choice-1))]}"
        fi
    fi
}

# Handle command line arguments
case "${1:-}" in
    --list)
        get_sso_connections
        ;;
    --status)
        for conn in $(get_sso_connections); do
            show_status "$conn"
        done
        ;;
    --connect)
        if [[ -n "${2:-}" ]]; then
            connect_vpn "$2"
        else
            echo "Usage: $0 --connect <connection-name>"
            exit 1
        fi
        ;;
    --disconnect)
        if [[ -n "${2:-}" ]]; then
            disconnect_vpn "$2"
        else
            echo "Usage: $0 --disconnect <connection-name>"
            exit 1
        fi
        ;;
    --toggle)
        if [[ -n "${2:-}" ]]; then
            toggle_vpn "$2"
        else
            echo "Usage: $0 --toggle <connection-name>"
            exit 1
        fi
        ;;
    --help|-h)
        echo "VPN SSO Connection Helper"
        echo ""
        echo "Usage: $0 [OPTION] [CONNECTION]"
        echo ""
        echo "Options:"
        echo "  --list              List all SSO VPN connections"
        echo "  --status            Show status of all SSO VPN connections"
        echo "  --connect NAME      Connect to specified VPN"
        echo "  --disconnect NAME   Disconnect from specified VPN"
        echo "  --toggle NAME       Toggle connection state"
        echo "  --help              Show this help"
        echo ""
        echo "Without arguments, shows an interactive menu."
        ;;
    *)
        main
        ;;
esac
