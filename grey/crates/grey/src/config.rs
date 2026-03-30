//! TOML configuration file support.
//!
//! Loads node configuration from a TOML file. CLI flags take precedence
//! over values in the config file.

use std::path::Path;

/// Top-level configuration file structure.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)] // Config file sections may define fields used in future PRs
pub struct ConfigFile {
    #[serde(default)]
    pub node: NodeConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Node configuration section.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
pub struct NodeConfig {
    pub validator_index: Option<u16>,
    pub listen_addr: Option<String>,
    pub port: Option<u16>,
    pub tiny: Option<bool>,
    pub chain: Option<String>,
    pub chain_spec: Option<String>,
    pub genesis_time: Option<u64>,
    pub db_path: Option<String>,
}

/// RPC configuration section.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
pub struct RpcConfig {
    pub port: Option<u16>,
    pub host: Option<String>,
    pub cors: Option<bool>,
}

/// Network configuration section.
#[derive(Debug, Default, serde::Deserialize)]
pub struct NetworkConfig {
    pub boot_peers: Option<Vec<String>>,
}

/// Logging configuration section.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
pub struct LoggingConfig {
    pub format: Option<String>,
    pub level: Option<String>,
}

impl ConfigFile {
    /// Load a configuration file from the given path.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse {}: {}", path.display(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[node]
validator_index = 3
listen_addr = "0.0.0.0"
port = 9001
tiny = false
db_path = "/var/lib/grey"

[rpc]
port = 9944
cors = true

[network]
boot_peers = ["/ip4/1.2.3.4/tcp/9000"]

[logging]
format = "json"
level = "debug"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.validator_index, Some(3));
        assert_eq!(config.node.listen_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(config.node.port, Some(9001));
        assert_eq!(config.node.tiny, Some(false));
        assert_eq!(config.rpc.port, Some(9944));
        assert_eq!(config.rpc.cors, Some(true));
        assert_eq!(config.network.boot_peers.as_ref().unwrap().len(), 1);
        assert_eq!(config.logging.format.as_deref(), Some("json"));
        assert_eq!(config.logging.level.as_deref(), Some("debug"));
    }

    #[test]
    fn test_parse_empty_config() {
        let config: ConfigFile = toml::from_str("").unwrap();
        assert!(config.node.validator_index.is_none());
        assert!(config.rpc.port.is_none());
    }

    #[test]
    fn test_parse_partial_config() {
        let toml_str = r#"
[node]
validator_index = 1

[logging]
level = "warn"
"#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.validator_index, Some(1));
        assert!(config.node.port.is_none());
        assert_eq!(config.logging.level.as_deref(), Some("warn"));
    }
}
