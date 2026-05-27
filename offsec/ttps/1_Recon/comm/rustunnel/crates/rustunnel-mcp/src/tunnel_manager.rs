//! Tracks spawned `rustunnel` CLI subprocesses so they can be killed when a
//! tunnel is closed or when the MCP server exits.

use std::collections::HashMap;
use tokio::process::Child;
use tokio::sync::Mutex;

pub struct TunnelManager {
    processes: Mutex<HashMap<String, Child>>,
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            processes: Mutex::new(HashMap::new()),
        }
    }

    /// Register a child process for the given tunnel ID.
    pub async fn insert(&self, tunnel_id: String, child: Child) {
        self.processes.lock().await.insert(tunnel_id, child);
    }

    /// Kill the process associated with `tunnel_id`, if one exists.
    /// Returns `true` if a process was found and signalled.
    pub async fn kill(&self, tunnel_id: &str) -> bool {
        let mut guard = self.processes.lock().await;
        if let Some(mut child) = guard.remove(tunnel_id) {
            let _ = child.start_kill();
            true
        } else {
            false
        }
    }

    /// Kill all tracked processes. Called on server shutdown.
    pub async fn kill_all(&self) {
        let mut guard = self.processes.lock().await;
        for (_, mut child) in guard.drain() {
            let _ = child.start_kill();
        }
    }
}
