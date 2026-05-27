//! MCP (Model Context Protocol) server implementation for pmond.
//!
//! This crate provides the MCP interface for the process monitor, allowing
//! MCP clients to access process and cgroup information through the standard
//! MCP protocol.
//!
//! The MCP implementation uses the public API from the `pmond` crate and
//! exposes it via tools and resources.

pub mod handler;
pub mod server;

pub use handler::PmonMcpHandler;
pub use server::{mcp_service, run_mcp_server};
