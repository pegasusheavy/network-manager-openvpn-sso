# Maintainer: Pegasus Heavy Industries LLC <pegasusheavyindustries@gmail.com>
pkgname=networkmanager-openvpn-sso
pkgver=0.1.0
pkgrel=2
pkgdesc="NetworkManager VPN plugin for OpenVPN with SSO/OAuth authentication"
arch=('x86_64')
url="https://github.com/pegasusheavy/network-manager-openvpn-sso"
license=('MIT')
depends=('networkmanager' 'openvpn' 'libsecret' 'dbus')
makedepends=('cargo' 'rust')
provides=('networkmanager-openvpn-sso')
conflicts=('networkmanager-openvpn-sso-git')
source=()
sha256sums=()

build() {
    cd "$startdir"
    cargo build --release --locked
}

package() {
    cd "$startdir"
    
    # Install binary (same location pattern as nm-openvpn-service)
    install -Dm755 "target/release/nm-openvpn-sso-service" \
        "$pkgdir/usr/lib/nm-openvpn-sso-service"
    
    # Install NetworkManager VPN plugin name file
    install -Dm644 "data/nm-openvpn-sso-service.name" \
        "$pkgdir/usr/lib/NetworkManager/VPN/nm-openvpn-sso-service.name"
    
    # Install D-Bus policy (allows root to own the bus name)
    install -Dm644 "data/org.freedesktop.NetworkManager.openvpn-sso.conf" \
        "$pkgdir/usr/share/dbus-1/system.d/nm-openvpn-sso-service.conf"
    
    # Install helper script for KDE/CLI users
    install -Dm755 "data/vpn-sso-connect.sh" \
        "$pkgdir/usr/bin/vpn-sso-connect"
    
    # Install desktop entry
    install -Dm644 "data/vpn-sso-connect.desktop" \
        "$pkgdir/usr/share/applications/vpn-sso-connect.desktop"
    
    # Install license
    install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
