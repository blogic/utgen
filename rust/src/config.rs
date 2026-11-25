// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const CONFIG_ENV_VAR: &str = "TGEN_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/traffic-generator/config.json";

const LABEL_MAX: usize = 16;
const IFACE_MAX: usize = 15;
const MIN_TOKEN_LEN: usize = 16;
const TOKEN_PLACEHOLDER: &str = "REPLACE_ME";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: no configuration; refusing to guess a port pool")]
    Missing { path: PathBuf },
    #[error("{path}: invalid JSON: {source}")]
    Invalid {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path}: {message}")]
    Unreadable { path: PathBuf, message: String },
    #[error("{0}")]
    Rejected(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortConfig {
    pub label: String,
    pub iface: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub token: String,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

fn default_netns_prefix() -> String {
    "tgen-".into()
}
fn default_runs_dir() -> PathBuf {
    "/var/lib/traffic-generator/runs".into()
}
fn default_captures_dir() -> PathBuf {
    "/var/lib/traffic-generator/captures".into()
}
fn default_state_dir() -> PathBuf {
    "/run/traffic-generator".into()
}

/// The read-only status page. Absent means no web listener at all.
#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_netns_prefix")]
    pub netns_prefix: String,
    #[serde(default = "default_runs_dir")]
    pub runs_dir: PathBuf,
    #[serde(default = "default_captures_dir")]
    pub captures_dir: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    pub ports: Vec<PortConfig>,
    pub mcp: McpConfig,
    #[serde(default)]
    pub web: Option<WebConfig>,
    #[serde(skip)]
    pub path: PathBuf,
}

impl Config {
    /// Resolve a port by label or by kernel interface name.
    pub fn port_find(&self, reference: &str) -> Result<&PortConfig, ConfigError> {
        self.ports
            .iter()
            .find(|port| port.label == reference || port.iface == reference)
            .ok_or_else(|| {
                let known: Vec<String> = self
                    .ports
                    .iter()
                    .map(|p| format!("{}({})", p.label, p.iface))
                    .collect();
                ConfigError::Rejected(format!(
                    "unknown port {reference:?}; pool is: {}",
                    known.join(", ")
                ))
            })
    }

    pub fn netns_of(&self, port: &PortConfig) -> String {
        format!("{}{}", self.netns_prefix, port.label)
    }

    pub fn loopback_bind(&self) -> bool {
        matches!(self.mcp.host.as_str(), "127.0.0.1" | "::1" | "localhost")
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.ports.is_empty() {
            return Err(ConfigError::Rejected(
                "ports: pool is empty; nothing can be generated without ports".into(),
            ));
        }

        let mut labels = HashSet::new();
        let mut ifaces = HashSet::new();
        for (index, port) in self.ports.iter().enumerate() {
            let at = format!("ports[{index}]");
            if port.label.is_empty() || port.label.len() > LABEL_MAX {
                return Err(ConfigError::Rejected(format!(
                    "{at}: label {:?} must be 1..{LABEL_MAX} characters",
                    port.label
                )));
            }
            if !port
                .label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(ConfigError::Rejected(format!(
                    "{at}: label {:?} must be lowercase letters, digits or '-'",
                    port.label
                )));
            }
            if port.iface.is_empty() || port.iface.len() > IFACE_MAX {
                return Err(ConfigError::Rejected(format!(
                    "{at}: iface {:?} must be 1..{IFACE_MAX} characters",
                    port.iface
                )));
            }
            if !labels.insert(&port.label) {
                return Err(ConfigError::Rejected(format!(
                    "{at}: duplicate label {:?}",
                    port.label
                )));
            }
            if !ifaces.insert(&port.iface) {
                return Err(ConfigError::Rejected(format!(
                    "{at}: duplicate iface {:?}",
                    port.iface
                )));
            }
        }

        if !self.mcp.path.starts_with('/') {
            return Err(ConfigError::Rejected(format!(
                "mcp: path {:?} must start with '/'",
                self.mcp.path
            )));
        }
        // A reachable bind with no credential would let anyone on the lab network
        // reconfigure interfaces and push line-rate traffic.
        if !self.loopback_bind() && self.mcp.token.len() < MIN_TOKEN_LEN {
            return Err(ConfigError::Rejected(format!(
                "mcp: host {:?} is not loopback, so token must be at least {MIN_TOKEN_LEN} characters",
                self.mcp.host
            )));
        }
        if self.mcp.token.contains(TOKEN_PLACEHOLDER) {
            return Err(ConfigError::Rejected(format!(
                "mcp: token is still the shipped placeholder; generate one with \
                 `head -c 32 /dev/urandom | base64 | tr -d '=+/'`. A {TOKEN_PLACEHOLDER} \
                 token is long enough to pass every other check, which is how a \
                 shared example ends up guarding real hardware"
            )));
        }
        if let Some(web) = &self.web {
            if web.port == self.mcp.port {
                return Err(ConfigError::Rejected(format!(
                    "web.port {} collides with mcp.port; the status page is unauthenticated and \
                     must not share the listener that needs the token",
                    web.port
                )));
            }
        }
        if self.netns_prefix.is_empty() {
            return Err(ConfigError::Rejected(
                "netns_prefix must not be empty".into(),
            ));
        }
        Ok(())
    }
}

pub fn config_parse(text: &str, path: &Path) -> Result<Config, ConfigError> {
    let mut config: Config =
        serde_json::from_str(text).map_err(|source| ConfigError::Invalid {
            path: path.to_path_buf(),
            source,
        })?;
    config.path = path.to_path_buf();
    config.validate()?;
    Ok(config)
}

pub fn config_load(explicit: Option<PathBuf>) -> Result<Config, ConfigError> {
    let path = explicit.unwrap_or_else(|| {
        std::env::var(CONFIG_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH))
    });
    if !path.is_file() {
        return Err(ConfigError::Missing { path });
    }
    let text = std::fs::read_to_string(&path).map_err(|err| ConfigError::Unreadable {
        path: path.clone(),
        message: err.to_string(),
    })?;
    config_parse(&text, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "ports": [
            {"label": "p0", "iface": "eth0"},
            {"label": "p1", "iface": "eth1"}
        ],
        "mcp": {"host": "127.0.0.1", "port": 9140, "path": "/mcp", "token": "short"}
    }"#;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        config_parse(text, Path::new("/test/config.json"))
    }

    #[test]
    fn good_config_parses_with_defaults() {
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.netns_prefix, "tgen-");
        assert_eq!(cfg.ports.len(), 2);
        assert_eq!(cfg.netns_of(cfg.port_find("p0").unwrap()), "tgen-p0");
        assert_eq!(cfg.state_dir, PathBuf::from("/run/traffic-generator"));
    }

    #[test]
    fn port_find_accepts_label_or_iface() {
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.port_find("p1").unwrap().iface, "eth1");
        assert_eq!(cfg.port_find("eth1").unwrap().label, "p1");
    }

    #[test]
    fn unknown_port_lists_the_pool() {
        let cfg = parse(GOOD).unwrap();
        let message = cfg.port_find("nope").unwrap_err().to_string();
        assert!(message.contains("unknown port"), "{message}");
        assert!(message.contains("p0(eth0)"), "{message}");
    }

    #[test]
    fn duplicate_label_rejected() {
        let text = GOOD.replace(r#"{"label": "p1", "iface": "eth1"}"#, r#"{"label": "p0", "iface": "eth1"}"#);
        assert!(parse(&text).unwrap_err().to_string().contains("duplicate label"));
    }

    #[test]
    fn duplicate_iface_rejected() {
        let text = GOOD.replace(r#"{"label": "p1", "iface": "eth1"}"#, r#"{"label": "p1", "iface": "eth0"}"#);
        assert!(parse(&text).unwrap_err().to_string().contains("duplicate iface"));
    }

    #[test]
    fn empty_pool_rejected() {
        let text = r#"{"ports": [], "mcp": {"host":"127.0.0.1","port":9140,"path":"/mcp","token":"x"}}"#;
        assert!(parse(text).unwrap_err().to_string().contains("pool is empty"));
    }

    #[test]
    fn over_long_iface_rejected() {
        let text = GOOD.replace("eth1", "a-very-long-iface-name");
        assert!(parse(&text).unwrap_err().to_string().contains("1..15 characters"));
    }

    #[test]
    fn weak_token_rejected_on_non_loopback_bind() {
        let text = GOOD.replace("127.0.0.1", "0.0.0.0");
        let message = parse(&text).unwrap_err().to_string();
        assert!(message.contains("at least 16 characters"), "{message}");
    }

    #[test]
    fn weak_token_allowed_on_loopback() {
        assert_eq!(parse(GOOD).unwrap().mcp.token, "short");
    }

    #[test]
    fn the_shipped_placeholder_token_is_refused() {
        // It is long enough to satisfy every other check, so without this the
        // example config guards real hardware with a published credential.
        let text = GOOD.replace(r#""token": "short""#, r#""token": "REPLACE_ME: generate one""#);
        let message = parse(&text).unwrap_err().to_string();
        assert!(message.contains("still the shipped placeholder"), "{message}");
    }

    #[test]
    fn the_example_config_ships_a_placeholder_and_so_cannot_be_used_as_is() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../configs/example.json"),
        )
        .expect("configs/example.json");
        assert!(
            parse(&text).is_err(),
            "configs/example.json must not be usable without being edited"
        );
    }

    #[test]
    fn path_without_leading_slash_rejected() {
        let text = GOOD.replace(r#""path": "/mcp""#, r#""path": "mcp""#);
        assert!(parse(&text).unwrap_err().to_string().contains("must start with"));
    }

    #[test]
    fn missing_mcp_block_rejected() {
        let text = r#"{"ports": [{"label":"p0","iface":"eth0"}]}"#;
        assert!(matches!(parse(text), Err(ConfigError::Invalid { .. })));
    }

    #[test]
    fn missing_file_refuses_rather_than_guessing() {
        let err = config_load(Some(PathBuf::from("/nonexistent/tgen.json"))).unwrap_err();
        assert!(err.to_string().contains("refusing to guess"), "{err}");
    }

    #[test]
    fn invalid_json_names_the_path() {
        let err = parse("{not json").unwrap_err();
        assert!(err.to_string().contains("invalid JSON"), "{err}");
        assert!(err.to_string().contains("/test/config.json"), "{err}");
    }
}
