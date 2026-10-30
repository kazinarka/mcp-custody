//! Static (L0) policy: which tools may be called and which argument values are acceptable.
//!
//! ```toml
//! default = "deny"            # tools not listed below
//!
//! [tools.get_balance]         # listed with no rules: allowed
//!
//! [tools.update_password]
//! action = "deny"
//!
//! [tools.send_money.args.recipient]
//! one_of = ["GB29NWBK60161331926819"]
//!
//! [tools.get_webpage.args.url]
//! hosts = ["www.informations.com", "*.example.org"]
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PinMode {
    /// Block calls to a tool whose definition changed after it was first seen.
    #[default]
    Enforce,
    /// Record changes in the audit log only.
    Warn,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub default: Action,
    #[serde(default)]
    pub pinning: PinMode,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    #[serde(default)]
    pub action: Action,
    #[serde(default)]
    pub args: BTreeMap<String, ArgRule>,
}

/// Constraints apply to every element when the argument is an array. An absent argument is
/// not checked: there is no value for anyone to steer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRule {
    pub one_of: Option<Vec<Value>>,
    /// Exact hosts, or `*.example.org` for subdomains of example.org.
    pub hosts: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum Denial {
    #[error("tool {tool} is not allowed")]
    Tool { tool: String },
    #[error("{tool}.{arg}: {reason}")]
    Argument {
        tool: String,
        arg: String,
        reason: String,
    },
    #[error("tool {tool} changed after it was pinned")]
    Pinned { tool: String },
    #[error("malformed tools/call: {reason}")]
    Malformed { reason: String },
}

impl Policy {
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn check_call(&self, tool: &str, args: &Map<String, Value>) -> Result<(), Denial> {
        let deny_tool = || Denial::Tool {
            tool: tool.to_owned(),
        };
        let Some(rule) = self.tools.get(tool) else {
            return match self.default {
                Action::Allow => Ok(()),
                Action::Deny => Err(deny_tool()),
            };
        };
        if rule.action == Action::Deny {
            return Err(deny_tool());
        }
        for (arg, constraint) in &rule.args {
            if let Some(value) = args.get(arg) {
                constraint.check(value).map_err(|reason| Denial::Argument {
                    tool: tool.to_owned(),
                    arg: arg.clone(),
                    reason,
                })?;
            }
        }
        Ok(())
    }
}

impl ArgRule {
    fn check(&self, value: &Value) -> Result<(), String> {
        let items = match value {
            Value::Array(items) => items.as_slice(),
            single => std::slice::from_ref(single),
        };
        for item in items {
            if let Some(allowed) = &self.one_of
                && !allowed.contains(item)
            {
                return Err(format!("{item} is not an allowed value"));
            }
            if let Some(hosts) = &self.hosts {
                let host = host_of(item).ok_or_else(|| format!("{item} is not a URL"))?;
                if !hosts.iter().any(|pattern| host_matches(pattern, &host)) {
                    return Err(format!("host {host} is not allowed"));
                }
            }
        }
        Ok(())
    }
}

fn host_of(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim();
    // Agents often drop the scheme ("www.example.com/page").
    let url = Url::parse(text)
        .ok()
        .filter(|u| u.has_host())
        .or_else(|| Url::parse(&format!("https://{text}")).ok())?;
    url.host_str().map(str::to_ascii_lowercase)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.')),
        None => host == pattern,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: &str = r#"
        default = "deny"

        [tools.get_balance]

        [tools.update_password]
        action = "deny"

        [tools.send_money.args.recipient]
        one_of = ["GB29NWBK60161331926819"]

        [tools.get_webpage.args.url]
        hosts = ["www.informations.com", "*.example.org"]
    "#;

    fn check(tool: &str, args: Value) -> Result<(), Denial> {
        let policy = Policy::from_toml(POLICY).unwrap();
        policy.check_call(tool, args.as_object().unwrap())
    }

    #[test]
    fn tools() {
        assert!(check("get_balance", json!({})).is_ok());
        assert!(matches!(
            check("update_password", json!({})),
            Err(Denial::Tool { .. })
        ));
        assert!(matches!(
            check("unlisted", json!({})),
            Err(Denial::Tool { .. })
        ));
    }

    #[test]
    fn default_allow_lets_unlisted_tools_through() {
        let policy = Policy::default();
        assert!(policy.check_call("anything", &Map::new()).is_ok());
    }

    #[test]
    fn one_of_checks_scalars_and_every_array_element() {
        let ok = "GB29NWBK60161331926819";
        assert!(check("send_money", json!({"recipient": ok, "amount": 5})).is_ok());
        assert!(check("send_money", json!({"recipient": [ok, ok]})).is_ok());
        assert!(
            check(
                "send_money",
                json!({"recipient": "US133000000121212121212"})
            )
            .is_err()
        );
        assert!(check("send_money", json!({"recipient": [ok, "US13"]})).is_err());
        assert!(check("send_money", json!({"amount": 5})).is_ok());
    }

    #[test]
    fn hosts_with_and_without_scheme() {
        let url = |u: &str| check("get_webpage", json!({ "url": u }));
        assert!(url("https://www.informations.com/page").is_ok());
        assert!(url("www.informations.com").is_ok());
        assert!(url("WWW.Informations.com/x?y").is_ok());
        assert!(url("a.example.org").is_ok());
        assert!(url("example.org").is_err());
        assert!(url("evilexample.org").is_err());
        assert!(url("www.informations.com.evil.net").is_err());
        assert!(url("https://evil.net/?www.informations.com").is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(Policy::from_toml("defualt = \"deny\"").is_err());
        assert!(Policy::from_toml("[tools.x.args.y]\noneof = [1]").is_err());
    }
}
