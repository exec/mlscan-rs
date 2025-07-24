use std::net::IpAddr;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scanner::PortStatus;
use crate::cli::ScanType;

pub mod builtin;
pub mod manager;

/// Trait for scanner plugins
#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// Plugin version
    fn version(&self) -> &str;
    
    /// Plugin description
    fn description(&self) -> &str;
    
    /// Supported scan types
    fn supported_scan_types(&self) -> Vec<ScanType>;
    
    /// Initialize the plugin with configuration
    async fn initialize(&mut self, config: PluginConfig) -> Result<()>;
    
    /// Perform a port scan
    async fn scan_port(&self, target: IpAddr, port: u16, timeout_ms: u64) -> Result<PortStatus>;
    
    /// Check if plugin supports a specific scan type
    fn supports_scan_type(&self, scan_type: ScanType) -> bool {
        self.supported_scan_types().contains(&scan_type)
    }
    
    /// Cleanup resources
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

/// Trait for output plugins
#[async_trait]
pub trait OutputPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// File extension for this output format
    fn file_extension(&self) -> &str;
    
    /// Content type/MIME type
    fn content_type(&self) -> &str;
    
    /// Initialize plugin
    async fn initialize(&mut self, config: PluginConfig) -> Result<()>;
    
    /// Format scan results
    async fn format_results(&self, results: &crate::scanner::MultiHostScanResult) -> Result<String>;
}

/// Trait for service detection plugins
#[async_trait]
pub trait ServiceDetectionPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;
    
    /// Supported ports for service detection
    fn supported_ports(&self) -> Vec<u16>;
    
    /// Initialize plugin
    async fn initialize(&mut self, config: PluginConfig) -> Result<()>;
    
    /// Detect service on an open port
    async fn detect_service(&self, target: IpAddr, port: u16, timeout_ms: u64) -> Result<Option<ServiceInfo>>;
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub settings: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub priority: u32,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            settings: HashMap::new(),
            enabled: true,
            priority: 100,
        }
    }
}

/// Service information detected by service detection plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub confidence: f32, // 0.0 to 1.0
    pub additional_info: HashMap<String, String>,
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub plugin_type: PluginType,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginType {
    Scanner,
    Output,
    ServiceDetection,
    Custom(String),
}

/// Plugin loading error
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),
    
    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),
    
    #[error("Unsupported plugin type: {0}")]
    UnsupportedType(String),
    
    #[error("Plugin version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },
    
    #[error("Plugin dependency missing: {0}")]
    MissingDependency(String),
}

/// Result type for plugin operations
pub type PluginResult<T> = Result<T, PluginError>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_plugin_config_serialization() {
        let mut config = PluginConfig::default();
        config.settings.insert("timeout".to_string(), serde_json::Value::Number(1000.into()));
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PluginConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.priority, deserialized.priority);
    }
    
    #[test]
    fn test_service_info_creation() {
        let service = ServiceInfo {
            name: "HTTP".to_string(),
            version: Some("1.1".to_string()),
            banner: Some("nginx/1.18.0".to_string()),
            confidence: 0.95,
            additional_info: HashMap::new(),
        };
        
        assert_eq!(service.name, "HTTP");
        assert!(service.confidence > 0.9);
    }
}