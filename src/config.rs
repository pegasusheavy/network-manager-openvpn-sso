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
    /// Path to the .ovpn configuration file
    pub config_path: PathBuf,
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

        let config_path = vpn_data
            .get("config")
            .or_else(|| vpn_data.get("connection-type"))
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("Missing OpenVPN config path in vpn.data.config"))?;

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
        })
    }

    /// Build OpenVPN command line arguments
    pub fn build_openvpn_args(&self, management_socket: &str) -> Vec<String> {
        let mut args = vec![
            "--config".to_string(),
            self.config_path.to_string_lossy().to_string(),
            // Management interface for auth and status
            "--management".to_string(),
            management_socket.to_string(),
            "unix".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
            // Script security for auth
            "--script-security".to_string(),
            "2".to_string(),
        ];

        // Apply overrides
        if let Some(ref remote) = self.remote {
            args.extend(["--remote".to_string(), remote.clone()]);
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
