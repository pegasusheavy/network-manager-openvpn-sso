// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! Connection configuration parsing and management

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::OwnedValue;

/// VPN connection settings extracted from NetworkManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Unique connection identifier (used for keyring storage)
    pub uuid: String,
    /// Human-readable connection name
    pub id: String,
    /// Path to the .ovpn configuration file (None for NM-imported connections)
    pub config_path: Option<PathBuf>,
    /// Optional server override
    pub remote: Option<String>,
    /// Optional port override
    pub port: Option<u16>,
    /// Optional protocol override (udp/tcp)
    pub protocol: Option<String>,
    /// Username for initial auth (placeholder for SSO)
    pub username: Option<String>,
    /// Password for initial auth (placeholder for SSO)
    pub password: Option<String>,
    /// Additional OpenVPN arguments
    pub extra_args: Vec<String>,
    /// CA certificate path (from vpn.data "ca")
    pub ca: Option<String>,
    /// Client certificate path (from vpn.data "cert")
    pub cert: Option<String>,
    /// Client key path (from vpn.data "key")
    pub key: Option<String>,
    /// TLS auth key path (from vpn.data "ta")
    pub ta: Option<String>,
    /// TLS auth key direction (from vpn.data "ta-dir")
    pub ta_dir: Option<String>,
    /// Cipher algorithm (from vpn.data "cipher")
    pub cipher: Option<String>,
    /// Auth/digest algorithm (from vpn.data "auth")
    pub auth: Option<String>,
    /// Tunnel device type (from vpn.data "dev")
    pub dev: Option<String>,
    /// Remote cert TLS check (from vpn.data "remote-cert-tls")
    pub remote_cert_tls: Option<String>,
    /// Connection type: tls, password, etc. (from vpn.data "connection-type")
    pub connection_type: Option<String>,
}

impl ConnectionConfig {
    /// Parse connection settings from NetworkManager D-Bus format
    /// The format is a{sa{sv}} - dict of setting-name -> dict of key -> variant
    pub fn from_nm_settings(
        settings: &HashMap<String, HashMap<String, OwnedValue>>,
    ) -> Result<Self> {
        // Extract connection section
        let connection = settings
            .get("connection")
            .ok_or_else(|| anyhow!("Missing 'connection' settings section"))?;

        let uuid = get_string(connection, "uuid")?;
        let id = get_string(connection, "id").unwrap_or_else(|_| "OpenVPN SSO".to_string());

        // Extract VPN section
        let vpn = settings
            .get("vpn")
            .ok_or_else(|| anyhow!("Missing 'vpn' settings section"))?;

        // Get VPN data (nested dict)
        let vpn_data = get_string_dict(vpn, "data").unwrap_or_default();

        let config_path = vpn_data.get("config").map(PathBuf::from);

        // Parse individual NM settings (used when config_path is None)
        let ca = vpn_data.get("ca").cloned();
        let cert = vpn_data.get("cert").cloned();
        let key = vpn_data.get("key").cloned();
        let ta = vpn_data.get("ta").cloned();
        let ta_dir = vpn_data.get("ta-dir").cloned();
        let cipher = vpn_data.get("cipher").cloned();
        let auth = vpn_data.get("auth").cloned();
        let dev = vpn_data.get("dev").cloned();
        let remote_cert_tls = vpn_data.get("remote-cert-tls").cloned();
        let connection_type = vpn_data.get("connection-type").cloned();

        // Validate: need either a config file or at least a CA cert
        if config_path.is_none() && ca.is_none() {
            return Err(anyhow!(
                "Missing OpenVPN config: need either vpn.data.config path or vpn.data.ca certificate"
            ));
        }

        let remote = vpn_data.get("remote").cloned();
        let port = vpn_data.get("port").and_then(|p| p.parse().ok());
        let protocol = vpn_data.get("proto").cloned();
        let username = vpn_data.get("username").cloned();

        // Get secrets section for password
        let vpn_secrets = get_string_dict(vpn, "secrets").unwrap_or_default();
        let password = vpn_secrets.get("password").cloned();

        Ok(Self {
            uuid,
            id,
            config_path,
            remote,
            port,
            protocol,
            username,
            password,
            extra_args: Vec::new(),
            ca,
            cert,
            key,
            ta,
            ta_dir,
            cipher,
            auth,
            dev,
            remote_cert_tls,
            connection_type,
        })
    }

    /// Build OpenVPN command line arguments
    pub fn build_openvpn_args(&self, management_socket: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(ref config_path) = self.config_path {
            // .ovpn file mode: use --config
            args.extend([
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
            ]);
        } else {
            // NM-imported mode: build from individual settings
            args.extend([
                "--client".to_string(),
                "--nobind".to_string(),
                "--dev".to_string(),
                self.dev.clone().unwrap_or_else(|| "tun".to_string()),
                "--persist-key".to_string(),
                "--persist-tun".to_string(),
                "--resolv-retry".to_string(),
                "infinite".to_string(),
            ]);

            if let Some(ref ca) = self.ca {
                args.extend(["--ca".to_string(), ca.clone()]);
            }
            if let Some(ref cert) = self.cert {
                args.extend(["--cert".to_string(), cert.clone()]);
            }
            if let Some(ref key) = self.key {
                args.extend(["--key".to_string(), key.clone()]);
            }
            if let Some(ref ta) = self.ta {
                args.push("--tls-auth".to_string());
                args.push(ta.clone());
                if let Some(ref dir) = self.ta_dir {
                    args.push(dir.clone());
                }
            }
            if let Some(ref cipher) = self.cipher {
                args.extend(["--cipher".to_string(), cipher.clone()]);
            }
            if let Some(ref auth) = self.auth {
                args.extend(["--auth".to_string(), auth.clone()]);
            }
            if let Some(ref remote_cert_tls) = self.remote_cert_tls {
                args.extend(["--remote-cert-tls".to_string(), remote_cert_tls.clone()]);
            }
        }

        // Common: management interface
        args.extend([
            "--management".to_string(),
            management_socket.to_string(),
            "unix".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
            "--script-security".to_string(),
            "2".to_string(),
        ]);

        // Common: apply overrides
        if let Some(ref remote) = self.remote {
            // NM stores remote as "host:port" — split for OpenVPN's --remote host [port]
            if let Some((host, port)) = remote.rsplit_once(':') {
                args.extend(["--remote".to_string(), host.to_string(), port.to_string()]);
            } else {
                args.extend(["--remote".to_string(), remote.clone()]);
            }
        }

        if let Some(port) = self.port {
            args.extend(["--port".to_string(), port.to_string()]);
        }

        if let Some(ref proto) = self.protocol {
            args.extend(["--proto".to_string(), proto.clone()]);
        }

        args.extend(self.extra_args.clone());

        args
    }
}

fn get_string(dict: &HashMap<String, OwnedValue>, key: &str) -> Result<String> {
    dict.get(key)
        .ok_or_else(|| anyhow!("Missing key: {}", key))
        .and_then(|v| {
            // Try to extract string from the variant value
            // zvariant stores strings as Str or String types
            let s = v.to_string();
            // Remove quotes if present (zvariant's Display adds them)
            let trimmed = s.trim_matches('"');
            if !trimmed.is_empty() {
                Ok(trimmed.to_string())
            } else {
                Err(anyhow!("Key {} is not a string or is empty", key))
            }
        })
}

fn get_string_dict(
    dict: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<HashMap<String, String>> {
    use tracing::info;
    use zbus::zvariant::Value;

    dict.get(key).and_then(|v| {
        let mut result = HashMap::new();

        // Log the raw value for debugging
        info!(
            "Parsing vpn.data key '{}', raw value type: {:?}",
            key,
            v.value_signature()
        );

        // Try to access as Dict<String, String> using Value
        let value: Value = v.clone().into();
        info!("Converted to Value variant: {:?}", value);

        // Try as Dict
        if let Value::Dict(dict_val) = &value {
            for (k, v_inner) in dict_val.iter() {
                // k and v_inner are &Value
                if let (Value::Str(key_str), Value::Str(val_str)) = (k, v_inner) {
                    result.insert(key_str.to_string(), val_str.to_string());
                }
            }
        }

        // Fallback: try parsing from string representation
        if result.is_empty() {
            let s = v.to_string();
            info!("Trying string parse from: {}", s);

            // Format from NetworkManager is often "key = value, key2 = value2"
            // when converted to string
            for pair in s.split(", ") {
                if let Some((k, val)) = pair.split_once(" = ") {
                    let k = k.trim().trim_matches('"');
                    let val = val.trim().trim_matches('"');
                    if !k.is_empty() && !val.is_empty() {
                        result.insert(k.to_string(), val.to_string());
                    }
                }
            }
        }

        info!("Parsed vpn.data result: {:?}", result);

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    })
}
