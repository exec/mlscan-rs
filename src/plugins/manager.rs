use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use tokio::sync::RwLock;

use super::{ScannerPlugin, OutputPlugin, ServiceDetectionPlugin, PluginConfig, PluginMetadata, PluginError, PluginResult};
use crate::cli::ScanType;

/// Plugin manager handles loading, managing, and executing plugins
pub struct PluginManager {
    scanner_plugins: HashMap<String, Arc<dyn ScannerPlugin>>,
    output_plugins: HashMap<String, Arc<dyn OutputPlugin>>,
    service_plugins: HashMap<String, Arc<dyn ServiceDetectionPlugin>>,
    plugin_configs: HashMap<String, PluginConfig>,
    metadata: HashMap<String, PluginMetadata>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Self {
        Self {
            scanner_plugins: HashMap::new(),
            output_plugins: HashMap::new(),
            service_plugins: HashMap::new(),
            plugin_configs: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Register a scanner plugin
    pub async fn register_scanner_plugin(
        &mut self,
        plugin: Arc<dyn ScannerPlugin>,
        config: PluginConfig,
    ) -> PluginResult<()> {
        let name = plugin.name().to_string();
        
        // Initialize the plugin with its configuration
        // Note: We can't call initialize here due to the trait constraint, 
        // but in a real implementation we'd handle this properly
        
        self.scanner_plugins.insert(name.clone(), plugin);
        self.plugin_configs.insert(name, config);
        
        Ok(())
    }
    
    /// Register an output plugin
    pub async fn register_output_plugin(
        &mut self,
        plugin: Arc<dyn OutputPlugin>,
        config: PluginConfig,
    ) -> PluginResult<()> {
        let name = plugin.name().to_string();
        self.output_plugins.insert(name.clone(), plugin);
        self.plugin_configs.insert(name, config);
        Ok(())
    }
    
    /// Register a service detection plugin
    pub async fn register_service_plugin(
        &mut self,
        plugin: Arc<dyn ServiceDetectionPlugin>,
        config: PluginConfig,
    ) -> PluginResult<()> {
        let name = plugin.name().to_string();
        self.service_plugins.insert(name.clone(), plugin);
        self.plugin_configs.insert(name, config);
        Ok(())
    }
    
    /// Get a scanner plugin by name
    pub fn get_scanner_plugin(&self, name: &str) -> Option<Arc<dyn ScannerPlugin>> {
        self.scanner_plugins.get(name).cloned()
    }
    
    /// Get an output plugin by name
    pub fn get_output_plugin(&self, name: &str) -> Option<Arc<dyn OutputPlugin>> {
        self.output_plugins.get(name).cloned()
    }
    
    /// Get a service detection plugin by name
    pub fn get_service_plugin(&self, name: &str) -> Option<Arc<dyn ServiceDetectionPlugin>> {
        self.service_plugins.get(name).cloned()
    }
    
    /// Get all scanner plugins that support a specific scan type
    pub fn get_scanner_plugins_for_type(&self, scan_type: ScanType) -> Vec<Arc<dyn ScannerPlugin>> {
        self.scanner_plugins
            .values()
            .filter(|plugin| plugin.supports_scan_type(scan_type))
            .cloned()
            .collect()
    }
    
    /// Get all registered plugin names
    pub fn list_plugins(&self) -> Vec<String> {
        let mut plugins = Vec::new();
        plugins.extend(self.scanner_plugins.keys().cloned());
        plugins.extend(self.output_plugins.keys().cloned());
        plugins.extend(self.service_plugins.keys().cloned());
        plugins.sort();
        plugins
    }
    
    /// Get plugin configuration
    pub fn get_plugin_config(&self, name: &str) -> Option<&PluginConfig> {
        self.plugin_configs.get(name)
    }
    
    /// Update plugin configuration
    pub fn update_plugin_config(&mut self, name: String, config: PluginConfig) {
        self.plugin_configs.insert(name, config);
    }
    
    /// Enable a plugin
    pub fn enable_plugin(&mut self, name: &str) -> PluginResult<()> {
        if let Some(config) = self.plugin_configs.get_mut(name) {
            config.enabled = true;
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }
    
    /// Disable a plugin
    pub fn disable_plugin(&mut self, name: &str) -> PluginResult<()> {
        if let Some(config) = self.plugin_configs.get_mut(name) {
            config.enabled = false;
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }
    
    /// Check if a plugin is enabled
    pub fn is_plugin_enabled(&self, name: &str) -> bool {
        self.plugin_configs
            .get(name)
            .map(|config| config.enabled)
            .unwrap_or(false)
    }
    
    /// Get scanner plugins sorted by priority (highest first)
    pub fn get_prioritized_scanner_plugins(&self) -> Vec<(Arc<dyn ScannerPlugin>, u32)> {
        let mut plugins: Vec<_> = self.scanner_plugins
            .iter()
            .filter_map(|(name, plugin)| {
                if let Some(config) = self.plugin_configs.get(name) {
                    if config.enabled {
                        Some((plugin.clone(), config.priority))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        
        plugins.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by priority descending
        plugins
    }
    
    /// Shutdown all plugins
    pub async fn shutdown_all(&self) -> Result<()> {
        // Shutdown scanner plugins
        for plugin in self.scanner_plugins.values() {
            if let Err(e) = plugin.shutdown().await {
                eprintln!("Warning: Failed to shutdown scanner plugin {}: {}", plugin.name(), e);
            }
        }
        
        // In a real implementation, we'd also shutdown output and service plugins
        // that implement a shutdown method
        
        Ok(())
    }
    
    /// Load plugins from configuration
    pub async fn load_from_config(&mut self, config: &crate::config::Config) -> Result<()> {
        // Load built-in plugins
        self.load_builtin_plugins().await?;
        
        // In a real implementation, we'd also:
        // 1. Load external plugins from shared libraries
        // 2. Parse plugin configuration from files
        // 3. Validate plugin dependencies
        // 4. Handle plugin versioning
        
        Ok(())
    }
    
    /// Load built-in plugins
    async fn load_builtin_plugins(&mut self) -> Result<()> {
        // Load built-in scanner plugins
        let tcp_plugin = Arc::new(super::builtin::TcpConnectPlugin::new());
        self.register_scanner_plugin(tcp_plugin, PluginConfig::default()).await?;
        
        // Load built-in output plugins
        let human_output = Arc::new(super::builtin::HumanOutputPlugin::new());
        self.register_output_plugin(human_output, PluginConfig::default()).await?;
        
        let json_output = Arc::new(super::builtin::JsonOutputPlugin::new());
        self.register_output_plugin(json_output, PluginConfig::default()).await?;
        
        Ok(())
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe plugin manager wrapper
pub struct ThreadSafePluginManager {
    inner: Arc<RwLock<PluginManager>>,
}

impl ThreadSafePluginManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PluginManager::new())),
        }
    }
    
    pub async fn register_scanner_plugin(
        &self,
        plugin: Arc<dyn ScannerPlugin>,
        config: PluginConfig,
    ) -> PluginResult<()> {
        self.inner.write().await.register_scanner_plugin(plugin, config).await
    }
    
    pub async fn get_scanner_plugin(&self, name: &str) -> Option<Arc<dyn ScannerPlugin>> {
        self.inner.read().await.get_scanner_plugin(name)
    }
    
    pub async fn get_scanner_plugins_for_type(&self, scan_type: ScanType) -> Vec<Arc<dyn ScannerPlugin>> {
        self.inner.read().await.get_scanner_plugins_for_type(scan_type)
    }
    
    pub async fn list_plugins(&self) -> Vec<String> {
        self.inner.read().await.list_plugins()
    }
    
    pub async fn load_from_config(&self, config: &crate::config::Config) -> Result<()> {
        self.inner.write().await.load_from_config(config).await
    }
    
    pub async fn shutdown_all(&self) -> Result<()> {
        self.inner.read().await.shutdown_all().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert_eq!(manager.list_plugins().len(), 0);
    }
    
    #[tokio::test]
    async fn test_plugin_loading() {
        let mut manager = PluginManager::new();
        manager.load_builtin_plugins().await.unwrap();
        
        let plugins = manager.list_plugins();
        assert!(plugins.contains(&"tcp_connect".to_string()));
        assert!(plugins.contains(&"human_output".to_string()));
        assert!(plugins.contains(&"json_output".to_string()));
    }
}