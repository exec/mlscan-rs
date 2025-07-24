use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use anyhow::Result;

/// Central configuration for portscan-rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scanning: ScanConfig,
    pub adaptive: AdaptiveConfig,
    pub output: OutputConfig,
    pub storage: StorageConfig,
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub default_timeout: u64,
    pub default_rate_limit: u64,
    pub default_parallelism: usize,
    pub max_retries: u32,
    pub enable_service_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub learning_rate: f64,
    pub min_scans_for_optimization: u32,
    pub max_port_intelligence_entries: usize,
    pub max_host_intelligence_entries: usize,
    pub data_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub default_format: String,
    pub color_enabled: bool,
    pub verbose_output: bool,
    pub show_closed_ports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub data_dir: Option<PathBuf>,
    pub enable_compression: bool,
    pub backup_enabled: bool,
    pub max_file_size_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageBackend {
    Json,
    Sqlite,
    Memory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub enable_connection_pooling: bool,
    pub max_memory_usage_mb: usize,
    pub enable_scan_caching: bool,
    pub cache_ttl_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scanning: ScanConfig {
                default_timeout: 1000,
                default_rate_limit: 50,
                default_parallelism: 50,
                max_retries: 3,
                enable_service_detection: false,
            },
            adaptive: AdaptiveConfig {
                enabled: true,
                learning_rate: 0.1,
                min_scans_for_optimization: 5,
                max_port_intelligence_entries: 10000,
                max_host_intelligence_entries: 5000,
                data_retention_days: 90,
            },
            output: OutputConfig {
                default_format: "human".to_string(),
                color_enabled: true,
                verbose_output: false,
                show_closed_ports: false,
            },
            storage: StorageConfig {
                backend: StorageBackend::Json,
                data_dir: None,
                enable_compression: false,
                backup_enabled: true,
                max_file_size_mb: 100,
            },
            performance: PerformanceConfig {
                enable_connection_pooling: false,
                max_memory_usage_mb: 512,
                enable_scan_caching: false,
                cache_ttl_seconds: 300,
            },
        }
    }
}

impl Config {
    /// Load configuration from the standard config directory
    pub fn load() -> Result<Self> {
        let config_path = Self::get_config_path();
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: Config = serde_json::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }
    
    /// Save configuration to the standard config directory
    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path();
        
        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, content)?;
        Ok(())
    }
    
    /// Get the path to the config file
    pub fn get_config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("portscan");
        path.push("config.json");
        path
    }
    
    /// Get the data directory for storing persistent data
    pub fn get_data_dir(&self) -> PathBuf {
        if let Some(ref custom_dir) = self.storage.data_dir {
            custom_dir.clone()
        } else {
            let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push("portscan");
            path
        }
    }
    
    /// Validate configuration settings
    pub fn validate(&self) -> Result<()> {
        if self.scanning.default_timeout == 0 {
            return Err(anyhow::anyhow!("default_timeout must be greater than 0"));
        }
        
        if self.scanning.default_parallelism == 0 {
            return Err(anyhow::anyhow!("default_parallelism must be greater than 0"));
        }
        
        if self.adaptive.learning_rate <= 0.0 || self.adaptive.learning_rate >= 1.0 {
            return Err(anyhow::anyhow!("learning_rate must be between 0 and 1"));
        }
        
        if !matches!(
            self.output.default_format.as_str(),
            "human" | "json" | "xml" | "csv"
        ) {
            return Err(anyhow::anyhow!(
                "default_format must be one of: human, json, xml, csv"
            ));
        }
        
        Ok(())
    }
    
    /// Get effective timeout based on configuration and adaptive learning
    pub fn get_effective_timeout(&self, adaptive_timeout: Option<u64>) -> u64 {
        if self.adaptive.enabled {
            adaptive_timeout.unwrap_or(self.scanning.default_timeout)
        } else {
            self.scanning.default_timeout
        }
    }
    
    /// Get effective rate limit based on configuration and adaptive learning
    pub fn get_effective_rate_limit(&self, adaptive_rate_limit: Option<u64>) -> u64 {
        if self.adaptive.enabled {
            adaptive_rate_limit.unwrap_or(self.scanning.default_rate_limit)
        } else {
            self.scanning.default_rate_limit
        }
    }
    
    /// Get effective parallelism based on configuration and adaptive learning
    pub fn get_effective_parallelism(&self, adaptive_parallelism: Option<usize>) -> usize {
        if self.adaptive.enabled {
            adaptive_parallelism.unwrap_or(self.scanning.default_parallelism)
        } else {
            self.scanning.default_parallelism
        }
    }
    
    /// Create a minimal config for testing
    #[cfg(test)]
    pub fn test_config() -> Self {
        Self {
            scanning: ScanConfig {
                default_timeout: 100,
                default_rate_limit: 10,
                default_parallelism: 10,
                max_retries: 1,
                enable_service_detection: false,
            },
            adaptive: AdaptiveConfig {
                enabled: false,
                learning_rate: 0.1,
                min_scans_for_optimization: 1,
                max_port_intelligence_entries: 100,
                max_host_intelligence_entries: 50,
                data_retention_days: 7,
            },
            output: OutputConfig {
                default_format: "human".to_string(),
                color_enabled: false,
                verbose_output: false,
                show_closed_ports: false,
            },
            storage: StorageConfig {
                backend: StorageBackend::Memory,
                data_dir: None,
                enable_compression: false,
                backup_enabled: false,
                max_file_size_mb: 10,
            },
            performance: PerformanceConfig {
                enable_connection_pooling: false,
                max_memory_usage_mb: 64,
                enable_scan_caching: false,
                cache_ttl_seconds: 60,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.scanning.default_timeout, deserialized.scanning.default_timeout);
        assert_eq!(config.adaptive.enabled, deserialized.adaptive.enabled);
    }
    
    #[test]
    fn test_effective_values() {
        let config = Config::default();
        
        // Test with adaptive learning enabled
        assert_eq!(config.get_effective_timeout(Some(500)), 500);
        assert_eq!(config.get_effective_timeout(None), config.scanning.default_timeout);
        
        // Test with adaptive learning disabled
        let mut config_disabled = config.clone();
        config_disabled.adaptive.enabled = false;
        assert_eq!(config_disabled.get_effective_timeout(Some(500)), config.scanning.default_timeout);
    }
}