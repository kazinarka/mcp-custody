//! Information-flow core of mcp-custody.
//!
//! This crate holds the parts of the gateway that decide, not the parts that move bytes:
//! policy, tool pins and the per-connection state machine. It must stay free of transport and
//! async runtime dependencies so it can be tested exhaustively and embedded elsewhere.

pub mod gateway;
pub mod jsonrpc;
pub mod pins;
pub mod policy;

pub use gateway::{Decision, Finding, Gateway, Verdict};
pub use pins::Pins;
pub use policy::Policy;
