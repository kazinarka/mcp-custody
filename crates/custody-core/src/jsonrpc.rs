//! The few JSON-RPC and MCP details the gateway needs, read from untyped messages.

use serde_json::{Value, json};

/// First revision whose results must carry `resultType`.
const RESULT_TYPE_SINCE: &str = "2026-07-28";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

pub fn method(msg: &Value) -> Option<&str> {
    msg.get("method")?.as_str()
}

/// Requests and responses carry a non-null id; notifications do not.
pub fn id(msg: &Value) -> Option<&Value> {
    msg.get("id").filter(|v| !v.is_null())
}

/// Map key for an id. Ids are strings or numbers, and `1` and `"1"` are different ids.
pub fn id_key(id: &Value) -> String {
    id.to_string()
}

pub fn params(msg: &Value) -> Option<&Value> {
    msg.get("params")
}

/// Since 2026-07-28 every request states its protocol version in `_meta`.
pub fn request_protocol_version(msg: &Value) -> Option<&str> {
    params(msg)?
        .get("_meta")?
        .get(META_PROTOCOL_VERSION)?
        .as_str()
}

pub fn is_response(msg: &Value) -> bool {
    id(msg).is_some() && (msg.get("result").is_some() || msg.get("error").is_some())
}

/// A tool result with `isError`, which the model reads and can recover from, unlike a
/// JSON-RPC error that most clients surface as a failure of the whole request.
pub fn tool_error(id: &Value, text: &str, protocol_version: Option<&str>) -> Value {
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true,
    });
    // Revisions are dates, so string order is release order.
    if protocol_version.is_some_and(|v| v >= RESULT_TYPE_SINCE) {
        result["resultType"] = json!("complete");
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_type_follows_protocol_version() {
        let old = tool_error(&json!(1), "x", Some("2025-11-25"));
        let new = tool_error(&json!(1), "x", Some("2026-07-28"));
        assert!(old["result"].get("resultType").is_none());
        assert_eq!(new["result"]["resultType"], "complete");
    }

    #[test]
    fn ids_of_different_types_do_not_collide() {
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
    }
}
