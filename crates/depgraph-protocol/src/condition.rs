use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A deterministic Boolean expression attached to a dependency edge or site.
///
/// `any([])` is the canonical representation of false. A dedicated `false`
/// operator is deliberately not part of protocol v1.0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    All { conditions: Vec<Condition> },
    Any { conditions: Vec<Condition> },
    Not { condition: Box<Condition> },
    Eq { key: String, value: Value },
    In { key: String, values: Vec<Value> },
    Defined { key: String },
}

impl Default for Condition {
    fn default() -> Self {
        Self::All {
            conditions: Vec::new(),
        }
    }
}

impl Condition {
    /// Returns a canonical form suitable for deterministic comparison and IDs.
    ///
    /// Canonicalization recursively flattens matching operators, removes
    /// identities, sorts and deduplicates commutative operands, simplifies
    /// double negation, and normalizes singleton `in` expressions to `eq`.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        match self {
            Self::Eq { key, value } => Self::Eq {
                key: key.clone(),
                value: value.clone(),
            },
            Self::Defined { key } => Self::Defined { key: key.clone() },
            Self::In { key, values } => {
                let mut values = values.clone();
                values.sort_by_key(json_value);
                values.dedup();
                if let [value] = values.as_slice() {
                    Self::Eq {
                        key: key.clone(),
                        value: value.clone(),
                    }
                } else {
                    Self::In {
                        key: key.clone(),
                        values,
                    }
                }
            }
            Self::Not { condition } => {
                let condition = condition.canonicalized();
                if let Self::Not { condition } = condition {
                    *condition
                } else {
                    Self::Not {
                        condition: Box::new(condition),
                    }
                }
            }
            Self::All { conditions } => canonicalize_all(conditions),
            Self::Any { conditions } => canonicalize_any(conditions),
        }
    }

    /// Consumes this expression and returns its canonical form.
    #[must_use]
    pub fn canonicalize(self) -> Self {
        self.canonicalized()
    }

    /// Renders a stable, human-readable expression after canonicalization.
    #[must_use]
    pub fn render(&self) -> String {
        render_canonical(&self.canonicalized())
    }

    fn sort_key(&self) -> String {
        serde_json::to_string(self).expect("Condition is always JSON serializable")
    }
}

fn canonicalize_all(conditions: &[Condition]) -> Condition {
    let mut flattened = Vec::new();
    for condition in conditions {
        match condition.canonicalized() {
            Condition::All { conditions } if conditions.is_empty() => {}
            Condition::All { conditions } => flattened.extend(conditions),
            other => flattened.push(other),
        }
    }
    flattened.sort_by_key(Condition::sort_key);
    flattened.dedup();
    match flattened.len() {
        0 => Condition::default(),
        1 => flattened.pop().expect("length checked"),
        _ => Condition::All {
            conditions: flattened,
        },
    }
}

fn canonicalize_any(conditions: &[Condition]) -> Condition {
    let mut flattened = Vec::new();
    for condition in conditions {
        match condition.canonicalized() {
            Condition::All { conditions } if conditions.is_empty() => {
                return Condition::default();
            }
            Condition::Any { conditions } => flattened.extend(conditions),
            other => flattened.push(other),
        }
    }
    flattened.sort_by_key(Condition::sort_key);
    flattened.dedup();
    match flattened.len() {
        1 => flattened.pop().expect("length checked"),
        _ => Condition::Any {
            conditions: flattened,
        },
    }
}

fn render_canonical(condition: &Condition) -> String {
    match condition {
        Condition::Eq { key, value } => {
            format!("{} == {}", render_key(key), json_value(value))
        }
        Condition::In { key, values } => format!(
            "{} in [{}]",
            render_key(key),
            values.iter().map(json_value).collect::<Vec<_>>().join(", ")
        ),
        Condition::Defined { key } => format!("defined({})", render_key(key)),
        Condition::Not { condition } => format!("!({})", render_canonical(condition)),
        Condition::All { conditions } if conditions.is_empty() => "true".into(),
        Condition::All { conditions } => format!(
            "({})",
            conditions
                .iter()
                .map(render_canonical)
                .collect::<Vec<_>>()
                .join(" && ")
        ),
        Condition::Any { conditions } if conditions.is_empty() => "false".into(),
        Condition::Any { conditions } => format!(
            "({})",
            conditions
                .iter()
                .map(render_canonical)
                .collect::<Vec<_>>()
                .join(" || ")
        ),
    }
}

fn render_key(key: &str) -> String {
    let mut chars = key.chars();
    let first_is_valid = chars
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_');
    if first_is_valid
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '-')
        })
    {
        key.to_owned()
    } else {
        json_string(key)
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("a string is always JSON serializable")
}

fn json_value(value: &Value) -> String {
    serde_json::to_string(value).expect("a JSON value is always serializable")
}

#[cfg(test)]
mod tests {
    use super::Condition;
    use serde_json::Value;

    fn eq(key: &str, value: &str) -> Condition {
        Condition::Eq {
            key: key.into(),
            value: Value::String(value.into()),
        }
    }

    #[test]
    fn canonicalizes_commutative_expressions() {
        let condition = Condition::All {
            conditions: vec![
                eq("runtime", "server"),
                Condition::default(),
                Condition::All {
                    conditions: vec![eq("mode", "production"), eq("runtime", "server")],
                },
            ],
        };

        assert_eq!(
            condition.canonicalized(),
            Condition::All {
                conditions: vec![eq("mode", "production"), eq("runtime", "server")]
            }
        );
        assert_eq!(
            condition.render(),
            "(mode == \"production\" && runtime == \"server\")"
        );
    }

    #[test]
    fn canonicalizes_in_and_double_negation() {
        let condition = Condition::Not {
            condition: Box::new(Condition::Not {
                condition: Box::new(Condition::In {
                    key: "target".into(),
                    values: vec![Value::String("linux".into()), Value::String("linux".into())],
                }),
            }),
        };

        assert_eq!(condition.canonicalized(), eq("target", "linux"));
    }

    #[test]
    fn true_and_false_use_only_protocol_v1_boolean_operators() {
        assert_eq!(
            serde_json::to_value(Condition::default()).unwrap(),
            serde_json::json!({"op":"all","conditions":[]})
        );
        assert_eq!(Condition::default().render(), "true");
        assert_eq!(
            Condition::Any {
                conditions: Vec::new()
            }
            .render(),
            "false"
        );
        assert!(serde_json::from_value::<Condition>(serde_json::json!({"op":"true"})).is_err());
    }
}
