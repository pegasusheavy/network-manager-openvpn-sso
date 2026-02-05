# NetworkManager OpenVPN SSO Plugin

A NetworkManager VPN plugin that adds OAuth 2.0 / OIDC Single Sign-On (SSO) support for OpenVPN connections.

[![CI](https://github.com/pegasusheavy/network-manager-openvpn-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/pegasusheavy/network-manager-openvpn-sso/actions/workflows/ci.yml)
[![Release](https://github.com/pegasusheavy/network-manager-openvpn-sso/actions/workflows/release.yml/badge.svg)](https://github.com/pegasusheavy/network-manager-openvpn-sso/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Browser-based SSO authentication** - Opens your default browser for OAuth/OIDC login
- **Automatic OAuth discovery** - Discovers authentication URLs from the OpenVPN server
- **Session token caching** - Caches session tokens for connection maintenance
- **Desktop notifications** - Shows connection status via system notifications
- **Full NetworkManager integration** - Works seamlessly with NetworkManager and network applets

## Installation

### Arch Linux

```bash
# From AUR or download from releases
sudo pacman -U networkmanager-openvpn-sso-*.pkg.tar.zst
```

### Debian / Ubuntu

```bash
sudo dpkg -i networkmanager-openvpn-sso_*_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

### Fedora / RHEL / CentOS

```bash
sudo dnf install networkmanager-openvpn-sso-*.x86_64.rpm
```

### Other Linux Distributions

```bash
# Download and extract the tarball
tar -xzf nm-openvpn-sso-service-linux-x86_64.tar.gz

# Run the install script
sudo ./install.sh
```

## Usage

### Importing an OpenVPN Configuration

1. Import your `.ovpn` file using NetworkManager:

```bash
nmcli connection import type openvpn file your-vpn-config.ovpn
```

2. Modify the connection to use the SSO plugin:

```bash
# Get the connection name
nmcli connection show | grep vpn

# Update to use SSO plugin
nmcli connection modify "your-vpn-name" vpn.service-type org.freedesktop.NetworkManager.openvpn-sso
```

3. Connect to the VPN:

```bash
nmcli connection up "your-vpn-name"
```

Your default browser will open for SSO authentication. After successful login, the VPN connection will be established automatically.

### Using with Network Manager GUI

The VPN connection will appear in your system's network settings and can be activated from there. When connecting, your browser will open for authentication.

## Requirements

- NetworkManager
- OpenVPN
- D-Bus
- A graphical session (for browser-based authentication)

## Building from Source

### Prerequisites

```bash
# Arch Linux
sudo pacman -S rust cargo dbus openssl pkgconf

# Debian/Ubuntu
sudo apt-get install rustc cargo libdbus-1-dev libssl-dev pkg-config

# Fedora
sudo dnf install rust cargo dbus-devel openssl-devel pkg-config
```

### Build

```bash
git clone https://github.com/pegasusheavy/network-manager-openvpn-sso.git
cd network-manager-openvpn-sso
cargo build --release
```

### Install

```bash
sudo ./install.sh
```

### Uninstall

```bash
sudo ./uninstall.sh
```

## Configuration

The plugin stores session tokens in `/var/lib/nm-openvpn-sso/` with restricted permissions. These tokens are used for session maintenance but do not persist across new connection attempts (SSO is required for each new connection).

## Troubleshooting

### Browser doesn't open

Ensure you have a default browser set and that `xdg-open` or your browser is accessible. The plugin will try multiple methods to open the browser:

1. `xdg-open` (skipped on KDE due to KIO limitations)
2. Direct browser launch (vivaldi, firefox, chromium, google-chrome)

### Connection times out

Check the NetworkManager logs for details:

```bash
journalctl -u NetworkManager -f
```

### VPN connects but no network access

Verify that the VPN routes are correctly applied:

```bash
ip route | grep tun
```

## How It Works

1. NetworkManager activates the VPN connection
2. The plugin starts OpenVPN with management interface enabled
3. OpenVPN connects to the server and receives an SSO authentication URL
4. The plugin opens your browser to the authentication URL
5. After successful authentication, the server provides credentials
6. The plugin completes the VPN connection and configures networking

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

- [GitHub Issues](https://github.com/pegasusheavy/network-manager-openvpn-sso/issues)
- [Patreon](https://www.patreon.com/c/PegasusHeavyIndustries)

---

Made with ❤️ by [Pegasus Heavy Industries LLC](https://github.com/pegasusheavy)
