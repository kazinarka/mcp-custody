//! Information-flow core of mcp-custody.
//!
//! This crate holds the parts of the gateway that decide, not the parts that move bytes:
//! labels, the handle store and policy evaluation. It must stay free of transport and
//! async runtime dependencies so it can be tested exhaustively and embedded elsewhere.
