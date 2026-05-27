//! JSON-RPC 2.0 / MCP protocol types and helpers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── incoming (client → server) ────────────────────────────────────────────────

/// A JSON-RPC 2.0 message received from the MCP client.
///
/// Requests have an `id`; notifications do not.
#[derive(Deserialize, Debug)]
pub struct IncomingMessage {
    #[allow(dead_code)]
    pub jsonrpc: String,
    /// Present on requests, absent on notifications.
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

// ── outgoing (server → client) ────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct OutgoingMessage {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Serialize, Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl OutgoingMessage {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn rpc_error(id: Option<Value>, code: i32, msg: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: msg.into(),
            }),
        }
    }
}

// ── tool result helpers ───────────────────────────────────────────────────────

/// Wrap text in an MCP tool success result.
pub fn tool_ok(text: impl Into<String>) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text.into()}],
        "isError": false
    })
}

/// Wrap text in an MCP tool error result.
pub fn tool_err(text: impl Into<String>) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text.into()}],
        "isError": true
    })
}
