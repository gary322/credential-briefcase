//! Model Context Protocol (MCP) primitives used by this repo.
//!
//! This crate is intentionally scoped to the parts needed for:
//! - `apps/mcp-gateway` (MCP server surface)
//! - `apps/briefcased` (MCP client for remote routing, in later phases)
//!
//! The implementation targets the MCP spec transports and lifecycle behaviors
//! referenced in `sop.txt` (stdio + streamable HTTP).

mod http_client;
mod jsonrpc;
mod server;
mod sse;
mod types;

pub use http_client::{HttpMcpClient, HttpMcpClientOptions};
pub use jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
pub use server::{McpConnection, McpHandler, McpServerConfig};
pub use types::{
    CallToolParams, CallToolResult, ContentBlock, InitializeParams, InitializeResult,
    ListToolsParams, ListToolsResult, McpServerInfo, Tool,
};

/// Latest protocol version supported by this implementation.
pub const PROTOCOL_VERSION_LATEST: &str = "2025-11-25";

/// Older protocol version still commonly used by clients.
pub const PROTOCOL_VERSION_2025_06_18: &str = "2025-06-18";
