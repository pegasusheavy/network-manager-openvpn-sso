// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

#include "openvpnsso.h"
#include "openvpnssowidget.h"
#include "openvpnssoauth.h"

#include <KPluginFactory>
#include <KLocalizedString>
#include <NetworkManagerQt/ConnectionSettings>
#include <NetworkManagerQt/VpnSetting>

#include <QFile>
#include <QFileInfo>

extern "C" {
#include <NetworkManager.h>
}

K_PLUGIN_CLASS_WITH_JSON(OpenVpnSsoUiPlugin, "plasmanetworkmanagement_openvpnssoui.json")

OpenVpnSsoUiPlugin::OpenVpnSsoUiPlugin(QObject *parent, const QVariantList &)
    : VpnUiPlugin(parent)
{
}

OpenVpnSsoUiPlugin::~OpenVpnSsoUiPlugin() = default;

SettingWidget *OpenVpnSsoUiPlugin::widget(const NetworkManager::VpnSetting::Ptr &setting, QWidget *parent)
{
    return new OpenVpnSsoSettingWidget(setting, parent);
}

SettingWidget *OpenVpnSsoUiPlugin::askUser(const NetworkManager::VpnSetting::Ptr &setting, const QStringList &hints, QWidget *parent)
{
    return new OpenVpnSsoAuthWidget(setting, hints, parent);
}

QString OpenVpnSsoUiPlugin::suggestedFileName(const NetworkManager::ConnectionSettings::Ptr &connection) const
{
    return connection->id() + QStringLiteral(".ovpn");
}

QStringList OpenVpnSsoUiPlugin::supportedFileExtensions() const
{
    return {QStringLiteral("*.ovpn"), QStringLiteral("*.conf")};
}

VpnUiPlugin::ImportResult OpenVpnSsoUiPlugin::importConnectionSettings(const QString &fileName)
{
    if (!QFile::exists(fileName)) {
        return ImportResult::fail(i18n("File not found: %1", fileName));
    }

    const QFileInfo fileInfo(fileName);
    const QString connectionName = fileInfo.completeBaseName();
    const QString absolutePath = fileInfo.absoluteFilePath();

    // Create an NMConnection using libnm C API
    NMConnection *connection = nm_simple_connection_new();

    // Set connection settings
    NMSettingConnection *sConn = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(sConn));

    g_object_set(sConn,
                 NM_SETTING_CONNECTION_ID, connectionName.toUtf8().constData(),
                 NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
                 NM_SETTING_CONNECTION_AUTOCONNECT, FALSE,
                 nullptr);

    // Set VPN settings
    NMSettingVpn *sVpn = NM_SETTING_VPN(nm_setting_vpn_new());
    nm_connection_add_setting(connection, NM_SETTING(sVpn));

    g_object_set(sVpn,
                 NM_SETTING_VPN_SERVICE_TYPE, "org.freedesktop.NetworkManager.openvpn-sso",
                 nullptr);
    nm_setting_vpn_add_data_item(sVpn, "config", absolutePath.toUtf8().constData());

    return ImportResult::pass(connection);
}

VpnUiPlugin::ExportResult OpenVpnSsoUiPlugin::exportConnectionSettings(
    const NetworkManager::ConnectionSettings::Ptr &connection, const QString &fileName)
{
    auto vpnSetting = connection->setting(NetworkManager::Setting::Vpn).staticCast<NetworkManager::VpnSetting>();
    const NMStringMap data = vpnSetting->data();

    const QString configPath = data.value(QStringLiteral("config"));
    if (configPath.isEmpty()) {
        return ExportResult::fail(i18n("No configuration file path stored in this connection."));
    }

    if (!QFile::exists(configPath)) {
        return ExportResult::fail(i18n("Source configuration file not found: %1", configPath));
    }

    // Copy the original .ovpn file to the export location
    if (QFile::exists(fileName)) {
        QFile::remove(fileName);
    }
    if (!QFile::copy(configPath, fileName)) {
        return ExportResult::fail(i18n("Failed to copy configuration to: %1", fileName));
    }

    return ExportResult::pass();
}

#include "openvpnsso.moc"
