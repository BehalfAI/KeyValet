//! Proxy calls (credential injection into HTTP requests, made from inside the root helper) and the
//! local gateway (for SDKs/CLIs that can't speak MCP). Direct port of src/helper/http-proxy.ts,
//! http-config.ts, http-manage.ts, and gateway.ts.

pub mod config;
pub mod gateway;
pub mod manage;
pub mod proxy;
pub mod redact;
