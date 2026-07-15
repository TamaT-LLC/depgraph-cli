use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Canonical identity components used by graph producers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableIdInput {
    pub repository_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_locator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_identity: Option<String>,
}

/// Produces `<namespace>:sha256:<lowercase hex>` from a typed identity.
#[must_use]
pub fn stable_id(namespace: &str, input: &StableIdInput) -> String {
    let value = serde_json::to_value(input).expect("StableIdInput is always serializable");
    stable_id_from_value(namespace, &value)
}

/// Produces a stable ID from arbitrary canonicalizable JSON data.
#[must_use]
pub fn stable_id_from_value(namespace: &str, input: &Value) -> String {
    let canonical = canonical_json(input);
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("{namespace}:sha256:{hex}")
}

/// Serializes JSON with recursively sorted object keys, preserved array order,
/// no insignificant whitespace, and UTF-8 string content.
#[must_use]
pub fn canonical_json(input: &Value) -> String {
    serde_json::to_string(&canonical_value(input)).expect("JSON Value is always serializable")
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let mut canonical = Map::with_capacity(object.len());
            for key in keys {
                canonical.insert(key.clone(), canonical_value(&object[key]));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{canonical_json, stable_id_from_value};
    use serde_json::json;

    #[test]
    fn canonical_json_recursively_sorts_object_keys_but_not_arrays() {
        let first = json!({"z": [{"b": 2, "a": 1}, 3], "a": true});
        let second = json!({"a": true, "z": [{"a": 1, "b": 2}, 3]});
        assert_eq!(canonical_json(&first), canonical_json(&second));
        assert_eq!(
            canonical_json(&first),
            r#"{"a":true,"z":[{"a":1,"b":2},3]}"#
        );
    }

    #[test]
    fn stable_id_has_known_sha256() {
        let id = stable_id_from_value("file", &json!({"path": "src/lib.rs"}));
        assert_eq!(
            id,
            "file:sha256:54047b442992a19c4f9c11c7c70f2fe9a8344276b07cdbe6b65c218cffa37ecd"
        );
    }
}
