//! Request/response capture for the dashboard.

use std::time::SystemTime;

use tokio::sync::mpsc;
use uuid::Uuid;

/// A single proxied HTTP request/response pair captured for the dashboard.
#[derive(Debug, Clone)]
pub struct CaptureEvent {
    pub conn_id: Uuid,
    pub tunnel_id: Uuid,
    /// Subdomain (HTTP) or port string (TCP) that identified the tunnel.
    pub tunnel_label: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// Raw bytes received from the public client.
    pub request_bytes: u64,
    /// Raw bytes returned to the public client.
    pub response_bytes: u64,
    /// Full round-trip duration in milliseconds.
    pub duration_ms: u64,
    pub captured_at: SystemTime,
}

/// Bounded sender for capture events.  Pass `None` to disable capture.
pub type CaptureTx = mpsc::Sender<CaptureEvent>;
