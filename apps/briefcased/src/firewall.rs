use briefcase_core::{OutputFirewall, OutputFirewallMode};

pub fn apply_output_firewall(
    firewall: &OutputFirewall,
    value: serde_json::Value,
) -> serde_json::Value {
    match firewall.mode {
        OutputFirewallMode::AllowAll => value,
        OutputFirewallMode::AllowPaths => filter_allow_paths(value, &firewall.allowed_paths),
    }
}

fn filter_allow_paths(value: serde_json::Value, allowed: &[String]) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for path in allowed {
        if let Some(v) = get_dot_path(&value, path) {
            insert_dot_path(&mut out, path, v.clone());
        }
    }
    serde_json::Value::Object(out)
}

fn get_dot_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn insert_dot_path(
    out: &mut serde_json::Map<String, serde_json::Value>,
    path: &str,
    value: serde_json::Value,
) {
    let mut parts = path.split('.').peekable();
    let mut cur = out;
    while let Some(part) = parts.next() {
        let is_last = parts.peek().is_none();
        if is_last {
            cur.insert(part.to_string(), value);
            return;
        }

        let replace = match cur.get(part) {
            None => true,
            Some(v) => !v.is_object(),
        };
        if replace {
            cur.insert(
                part.to_string(),
                serde_json::Value::Object(serde_json::Map::new()),
            );
        }

        cur = cur
            .get_mut(part)
            .and_then(|v| v.as_object_mut())
            .expect("inserted object");
    }
}
