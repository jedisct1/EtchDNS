#[cfg(feature = "hooks")]
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(feature = "hooks")]
use std::sync::Mutex;

#[cfg(feature = "hooks")]
use extism::{Error as ExtismError, Manifest, Plugin, Wasm};
#[cfg(feature = "hooks")]
use std::path::Path;

/// Input data for the hook_client_query_received function
#[cfg(feature = "hooks")]
#[derive(Serialize, Deserialize)]
struct QueryInput<'a> {
    query_name: &'a str,
    qtype: u16,
    qclass: u16,
    client_ip: &'a str,
}

/// Hooks structure for customizing DNS query processing
///
/// This structure will be initialized when the program starts and
/// will be accessible by the query manager's submit_query function.
/// It is designed to be thread-safe.
#[derive(Debug, Clone)]
pub struct Hooks {
    /// WebAssembly plugin for hook implementations
    #[cfg(feature = "hooks")]
    wasm_plugin: Option<Arc<Mutex<Plugin>>>,
}

impl Hooks {
    /// Create a new Hooks instance
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "hooks")]
            wasm_plugin: None,
        }
    }

    /// Create a new Hooks instance with a WebAssembly plugin
    ///
    /// # Arguments
    ///
    /// * `wasm_file_path` - Path to the WebAssembly file
    ///
    /// # Returns
    ///
    /// A Result containing the Hooks instance or an error
    #[cfg(feature = "hooks")]
    pub fn with_wasm_file<P: AsRef<Path>>(wasm_file_path: P) -> Result<Self, ExtismError> {
        // Create a Wasm object from the file path
        let wasm = Wasm::file(wasm_file_path);

        // Create a manifest with the Wasm object
        let manifest = Manifest::new([wasm]);

        // Create the plugin from the manifest
        let plugin = Plugin::new(manifest, vec![], false)?;

        // Return the Hooks instance with the plugin
        Ok(Self {
            wasm_plugin: Some(Arc::new(Mutex::new(plugin))),
        })
    }

    /// Create a new Hooks instance with a WebAssembly plugin
    ///
    /// This is a stub implementation when the hooks feature is disabled.
    /// It always returns an error.
    #[cfg(not(feature = "hooks"))]
    pub fn with_wasm_file<P>(_wasm_file_path: P) -> Result<Self, &'static str> {
        Err("WebAssembly hooks support is not enabled. Recompile with the 'hooks' feature.")
    }

    /// Hook called when a client query is received
    ///
    /// # Arguments
    ///
    /// * `query_name` - The domain name being queried
    /// * `qtype` - The query type (e.g., A, AAAA, MX)
    /// * `qclass` - The query class (usually IN for Internet)
    /// * `client_ip` - The client IP address (without port)
    /// * `query_data` - The raw query data
    ///
    /// # Returns
    ///
    /// An integer code:
    /// * 0 - Continue normal processing
    /// * -1 - Return a minimal response with REFUSED rcode
    /// * Other values may be defined in the future
    pub fn hook_client_query_received(
        &self,
        #[cfg(feature = "hooks")] query_name: &str,
        #[cfg(not(feature = "hooks"))] _query_name: &str,
        #[cfg(feature = "hooks")] qtype: u16,
        #[cfg(not(feature = "hooks"))] _qtype: u16,
        #[cfg(feature = "hooks")] qclass: u16,
        #[cfg(not(feature = "hooks"))] _qclass: u16,
        #[cfg(feature = "hooks")] client_ip: &str,
        #[cfg(not(feature = "hooks"))] _client_ip: &str,
        _query_data: &[u8],
    ) -> i32 {
        // If hooks are enabled and we have a WebAssembly plugin, call it
        #[cfg(feature = "hooks")]
        {
            if let Some(plugin_arc) = &self.wasm_plugin {
                // Create input data for the WebAssembly function
                let input = QueryInput {
                    query_name,
                    qtype,
                    qclass,
                    client_ip,
                };
                let input_json = serde_json::to_string(&input).unwrap_or_else(|e| {
                    log::warn!("Failed to serialize query input: {}", e);
                    String::new()
                });

                // Try to lock the plugin
                if let Ok(mut plugin) = plugin_arc.lock() {
                    // Call the WebAssembly function
                    match plugin.call::<&str, &str>("hook_client_query_received", &input_json) {
                        Ok(result_str) => {
                            // Try to parse the result as an i32
                            if let Ok(result_code) = result_str.parse::<i32>() {
                                log::debug!(
                                    "WebAssembly hook_client_query_received for {} returned: {}",
                                    query_name,
                                    result_code
                                );
                                return result_code;
                            } else {
                                log::warn!(
                                    "WebAssembly hook_client_query_received returned invalid result: {}",
                                    result_str
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "Error calling WebAssembly hook_client_query_received: {}",
                                e
                            );
                        }
                    }
                } else {
                    log::warn!("Failed to lock WebAssembly plugin");
                }
            }
        }

        // For now, just return 0 to continue normal processing
        0
    }
}

/// Thread-safe wrapper for Hooks
#[derive(Debug, Clone)]
pub struct SharedHooks {
    inner: Arc<Hooks>,
}

impl SharedHooks {
    /// Create a new SharedHooks instance
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Hooks::new()),
        }
    }

    /// Create a new SharedHooks instance with the given Hooks
    pub fn with_hooks(hooks: Hooks) -> Self {
        Self {
            inner: Arc::new(hooks),
        }
    }

    /// Get a reference to the inner Hooks
    #[allow(dead_code)]
    pub fn inner(&self) -> &Arc<Hooks> {
        &self.inner
    }

    /// Hook called when a client query is received
    ///
    /// # Arguments
    ///
    /// * `query_name` - The domain name being queried
    /// * `qtype` - The query type (e.g., A, AAAA, MX)
    /// * `qclass` - The query class (usually IN for Internet)
    /// * `client_ip` - The client IP address (without port)
    /// * `query_data` - The raw query data
    ///
    /// # Returns
    ///
    /// An integer code:
    /// * 0 - Continue normal processing
    /// * -1 - Return a minimal response with REFUSED rcode
    /// * Other values may be defined in the future
    pub fn hook_client_query_received(
        &self,
        query_name: &str,
        qtype: u16,
        qclass: u16,
        client_ip: &str,
        query_data: &[u8],
    ) -> i32 {
        self.inner
            .hook_client_query_received(query_name, qtype, qclass, client_ip, query_data)
    }
}

impl Default for SharedHooks {
    fn default() -> Self {
        Self::new()
    }
}
